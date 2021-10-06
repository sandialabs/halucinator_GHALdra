# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

'''This module implements the plugin. It essentially is a wrapper
It is the interface for the GHALdra inside Ghidra.'''
import itertools
import threading

from ghidra.app.plugin import ProgramPlugin
from ghidra.app.script import GhidraState
from ghidra.program.model.address import AddressSet
from ghidra.program.util import ProgramSelection
from ghidra.util.exception import CancelledException
from ghidra.util.task import ConsoleTaskMonitor

from ghaldra import GHALdra
from ghaldra_gui import GHALdraComponentProvider
from halucinator.qemu_targets import ARMQemuTarget


class GHALdraPlugin(ProgramPlugin):
    '''implements the plugin interfacing'''
    def __init__(self, tool, *args):
        super(GHALdraPlugin, self).__init__(tool, *args)
        self.component = GHALdraComponentProvider(self)
        self.emulator = None
        self.started = False
        self.monitor = ConsoleTaskMonitor()
        self.parent_tool = tool
        self.state = None
        self.threads = list()
        tool.addComponentProvider(self.component, True)

    def get_monitor(self):
        '''getter for ghaldra.py to use to get monitor'''
        return self.monitor

    def get_ghidra_state(self):
        '''returns a new GhidraState given the current Ghidra view'''
        return GhidraState(self.getTool(), self.getTool().getProject(),
            self.getCurrentProgram(), self.getProgramLocation(),
            self.getProgramSelection(), self.getProgramHighlight())

    def sync_view(self, address=None):
        '''interface to sync the emulator state inside Ghidra view'''
        if address is None:
            address = self.state.getCurrentAddress()
        self.state.setCurrentAddress(address)
        self.state.setCurrentSelection(ProgramSelection(AddressSet(address)))

    def get_current_fn(self, state=None):
        '''returns the current function the view is in from Ghidra'''
        if state is None:
            state = self.state
        return "%s" % state.currentProgram.getFunctionManager().getFunctionContaining(
                state.getCurrentAddress())

    def do_start(self):
        '''try to do initilization of the plugin,
        config and servers, then sync view'''
        try:
            self.state = self.get_ghidra_state()
            self.component.setStatus("Initializing @ %s" % self.get_current_fn())
            if self.started:
                self.emulator.restart()
            else:
                self.init_ghaldra()
            self.emulator.init_function_parameters()
            self.emulator.start()
            self.emulator.start_server()
            self.sync_view()
            self.component.setStatus("Started @ %s" % self.get_current_fn())
            self.started = True
        except CancelledException:
            pass

    def init_ghaldra(self, state=None):
        '''Initialized GHALdra by creating the actual class object'''
        if "ARM" in str(self.state.currentProgram.getLanguageID()):
            self.emulator = ARMQemuTarget(self, state)
        else:
            self.emulator = GHALdra(self, state)


    def do_cmd(self):
        '''handler for taking the command line input,
        and actually calling the right command handler'''
        if self.emulator is None:
            self.do_start()

        cmds = self.component.panel_input.getText().strip().split(', ')
        for _, cmd in enumerate(cmds):
            #For commands that actually execute instructions in emulator, start it in a thread
            if cmd == 'c' or cmd[0] == 'n' or (cmd[0] == 's' and len(cmd) > 1 and cmd[1] != 's'):
                if self.emulator.input_wildcards:
                    self.threads.append(threading.Thread(target=self.do_cmd_fuzzing, args=(cmd,)))
                else:
                    self.threads.append(threading.Thread(
                        target=self.emulator.execute_cmd, args=(cmd,)))
                self.threads[-1].setDaemon(True)
                self.threads[-1].start()
            # Otherwise just execute with the main thread
            # (allows for spawning other threads without issue)
            else:
                self.emulator.execute_cmd(cmd)

        self.component.panel_input.selectAll()

    def set_registers(self, registers):
        '''sets the values in the GUI given the registers'''
        self.component.set_registers(registers)

    def do_cmd_fuzzing(self, cmds):
        '''if you are wanting to fuzz commands for testing'''
        input_wildcards = self.emulator.input_wildcards
        domain = [range(0x100) for _ in range(len(input_wildcards))]

        for vals in itertools.product(*domain):
            self.emulator.init_ghaldra()
            self.emulator.start({key:as_byte(value) \
                                for key, value in zip(input_wildcards,vals)})
            self.emulator.execute_cmd(cmds)

    def quit_emulator(self):
        '''stops the servers and removes the plugin from Ghidra.
        It shuts the server down but sometimes the thread still idles,
        when Ghidra is shutdown it is guaranteed'''
        if self.emulator:
            self.emulator.stop_server()
        self.emulator = None
        self.parent_tool.removeComponentProvider(self.component)

def as_byte(value):
    '''helper function for do_cmd_fuzzing'''
    if isinstance(value, basestring):
        if len(value) == 1:
            return "%02x" % ord(value)
        return value
    return "%02x" % value
