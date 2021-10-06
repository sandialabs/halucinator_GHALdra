# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

'''#@description This is not the emulator file script, run emulate_function.py
#This is the file that essentially does most of the work for the emulator'''
import logging
import os
import string
import sys
import threading
from functools import wraps

import ghidra
from __main__ import *
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.app.emulator import EmulatorHelper
from ghidra.pcode.emulate import BreakCallBack
from ghidra.program.flatapi import FlatProgramAPI

import halucinator
from ghaldra_utils import ghaldra_utils
from halucinator.bp_handlers import intercepts
from halucinator.peripheral_models import peripheral_server as periph_server


class PeriphServer(object):
    '''used to handle the server thread stuff'''
    def __init__(self):
        self.server_thread = None

    def start_server(self, qemu):
        '''Starts the peripheral server. If wanted, change rx and tx port.'''
        if self.server_thread is None:
            rx_port=5555
            tx_port=5556
            periph_server.start(rx_port, tx_port, qemu)
            self.server_thread = threading.Thread(target=periph_server.run_server)
            self.server_thread.start()

    def stop_server(self, qemu):
        '''stops the peripheral server'''
        periph_server.stop()
        if self.server_thread:
            self.server_thread.join()
        periph_server.stop()

    def check_if_running(self):
        '''check if the server is running'''
        if self.server_thread:
            return True
        return False

class Context(object):
    '''used for storing state for interrupts'''
    def __init__(self, ghaldra):
        self.regs = {}
        for register in ghaldra.ghaldra_helper.getLanguage().getRegisters():
            if register.isBaseRegister() and not register.isProcessorContext():
                self.regs[str(register)] = str(ghaldra.ghaldra_helper.readRegister(register))

    def save_reg_state(self, ghaldra):
        '''save the register state when context switch or interrupt'''
        for register in ghaldra.ghaldra_helper.getLanguage().getRegisters():
            if register.isBaseRegister() and not register.isProcessorContext():
                self.regs[str(register)] = str(ghaldra.ghaldra_helper.readRegister(register))

    def restore_reg_state(self, ghaldra):
        '''restore the register state from context switch or interrupt'''
        for register in self.regs.items():
            ghaldra.set_reg(register[0], register[1])

class GHALdraState:
    '''to keep track of the emulator state'''
    WAITING_FOR_PARAM, READY, EXECUTING, DONE = range(4)

def history(func):
    @wraps(func)
    def wrapper(*args):
        '''wraps the different commands to keep a history log of commands'''
        args[0].logger.debug(args[1])
        args[0].history.append(' '.join(args[1]))
        func(*args)
    return wrapper

class BreakCallBackWrapper(BreakCallBack):
    ''' This is a wrapper to do the callback on intercepted functions'''
    def __init__(self, address_callback, pcode_callback):
        self.address_callback = address_callback
        self.pcode_callback = pcode_callback
    def addressCallback(self, address):
        '''set address callback for the breakcallback'''
        self.address_callback(address)
        return True
    def pcodeCallback(self, address):
        '''set pcode callback for the breakcallback'''
        self.pcode_callback(address)
        return True

class GHALdra(object):
    '''main class for the emulator. Is the class to interact with user and emulator'''
    _LINE_LEN = 80
    #Things we don't want reset upon multiple starts within the plugin
    server = PeriphServer()
    initialized = False
    debug = False
    timeout = None
    hq_trace_addr_set = ghidra.program.model.address.AddressSet()
    def __init__(self, plugin, state=None):
        '''initialize, ask the user for a config file, if they say no, ask for everything'''
        self.addr_set = ghidra.program.model.address.AddressSet()
        self.break_execution = False
        self.breakpoints = None
        self.byte_substitution = {}
        self.cur_interrupt = None
        self.cur_function = None
        self.decompiled = None
        self.decomp_interface = None
        self.emulator_state = None
        self.entrypoint = None
        self.exe_instr = []
        self.exit_point = None
        self.flatapi = FlatProgramAPI(currentProgram)
        self.func_manager = self.flatapi.currentProgram.getFunctionManager()
        self.function = None
        self.ghaldra_helper = None
        self.high_function = None
        self.history = []
        self.hooked_func_addrs = set()
        self.input_wildcards = []
        self.intercepts = None
        self.interrupts = {}
        self.last_addresses = []
        self.monitor = plugin.get_monitor()
        self.num_instr_to_save = 100
        self.output_directory = "./"
        self.parameter_map = {}
        self.plugin = plugin
        self.program = self.flatapi.currentProgram
        self.stack_pointer = None
        self.stop_from_intercept = False
        self.start_address = None
        self.symbol_map = None
        self.written_addr_set = ghidra.program.model.address.AddressSet()

        self.init_config()
        self.logger.info("Finished Initializing Config")
        self.logger.info("Initializing GHALdra and Helpers...")
        self.init_ghaldra()
        self.logger.info("Initializing Comand Handlers...")
        self.init_cmd_handlers()
        self.logger.info("Hooking External Functions...")
        self.hook_external_functions()
        self.logger.info("Setting up Intercepts...")
        self.setup_intercepts()
        self.logger.info("Setting up Breakpoints...")
        self.set_breakpoints()

    def init_config(self):
        '''setup based on configuration file'''
        have_config = askYesNo("Config File",
            "Do you have a config file? If not have to enter manually...")
        if have_config:
            options = str(askFile("Config File", "Enter path to Config File"))
            config = ghaldra_utils.read_yaml(options)
            if config is None:
                print("Config error, check formatting!")
            if 'intercepts' in config:
                self.intercepts = config['intercepts']
            if 'breakpoints' in config:
                self.breakpoints = config['breakpoints']
            if 'exit_point' in config:
                self.exit_point = self.get_address(config['exit_point'])
            if 'entry_point' in config:
                self.start_address =  self.get_address(config['entry_point'])
            else:
                raw_address = askLong("Entry Point",
                    "Enter the entry point of where to start emulation")
                self.start_address =  self.get_address(raw_address)
            if 'logfilename' in config:
                logfilename = os.path.expandvars(config['logfilename'])
            else:
                logfilename = "ghaldra.log"
            if 'num_instrToSave' in config:
                self.num_instr_to_save = config['num_instr_to_save']
            if 'output_directory' in config:
                self.output_directory = os.path.expandvars(config['output_directory'])
            else:
                self.output_directory = askString("Output Directory",
                    "Enter path for output tmp files")
            if 'debug' in config:
                self.debug = config['debug']
            else:
                self.debug = askYesNo("Debug Printing",
                    "Do you want to print the debug output?")
        else:
            logfilename = askString("Log Filename", "Enter path where to save log")
            self.num_instr_to_save = askInt("# Instructions",
                "Enter the number of instructions to save for quick debugging")
            self.output_directory = askString("Output Directory",
                "Enter path for output tmp files")
            self.debug = askYesNo("Debug Printing",
                "Do you want to print the debug output?")
            raw_address = askLong("Entry Point",
                "Enter the entry point of where to start emulation")
            self.start_address =  self.get_address(raw_address)
            if not self.start_address:
                self.start_address = state.getCurrentAddress()

            #create output_directory if it doesn't exist
            try:
                os.makedirs(self.output_directory)
            except OSError as err:
                if err.errno is not errno.EEXIST:
                    raise

        #initialize the logger with logfilename
        if not self.plugin.started:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.INFO)
            stdout = logging.StreamHandler(sys.stdout)
            stdout.setLevel(logging.INFO) #DEBUG OR INFO
            if self.debug:
                stdout.setLevel(logging.DEBUG)
            self.logger.addHandler(stdout)
            log_file = logging.FileHandler(logfilename)
            log_file.setLevel(logging.DEBUG)
            self.logger.addHandler(log_file)

    def init_ghaldra(self):
        ''' Setup the emulator helper, symbol maps and fn related stuff '''
        self.function = self.func_manager.getFunctionContaining(self.start_address)
        if self.function is None:
            func_name = askString("You are not in a function, enter address or function name",
                "address or symbol name")
            for func in self.plugin.state.currentProgram.getFunctionManager().getFunctions(True):
                if func_name == func.getName():
                    self.plugin.state.setCurrentAddress(func.getEntryPoint())
                    self.plugin.do_start()
                    return
            for func in self.plugin.state.currentProgram.getFunctionManager().getFunctions(True):
                if int(func_name, 16) == func.getEntryPoint().getOffset():
                    self.plugin.state.setCurrentAddress(func.getEntryPoint())
                    self.plugin.do_start()
                    return

        self.entrypoint = self.program.getListing().getInstructionAt(self.function.getEntryPoint())
        self.plugin.sync_view(self.entrypoint.getAddress())
        self.logger.info("Program: %s",  self.program)
        self.logger.info("Function: %s",  self.function)
        if self.exit_point is None:
            self.exit_point = ghaldra_utils.get_func_last_instr_addr(self.function)

        decomp_options = DecompileOptions()
        self.decomp_interface = DecompInterface()
        self.decomp_interface.setOptions(decomp_options)
        self.decomp_interface.openProgram(self.program)
        result = self.decomp_interface.decompileFunction(self.function, 10, self.monitor)

        if result:
            self.high_function = result.getHighFunction()
            self.decompiled = str(result.getCCodeMarkup())
            self.symbol_map = self.high_function.getLocalSymbolMap()
        else:
            self.logger.error("We can't get the highFunction. Probably won't work out")
            self.high_function = None
            self.decompiled = None
            self.symbol_map = None
        self.ghaldra_helper = EmulatorHelper(self.program)
        self.stack_pointer = ( \
            ((1 << (self.ghaldra_helper.getStackPointerRegister().getBitLength() - 1)) - 1) \
            ^ ((1 << (self.ghaldra_helper.getStackPointerRegister().getBitLength()//2))-1))
        self.ghaldra_helper.writeRegister(self.ghaldra_helper.getStackPointerRegister(),
                                        self.stack_pointer)
        self.ghaldra_helper.setBreakpoint(self.get_stack_address(0))
        self.ghaldra_helper.enableMemoryWriteTracking(True)
        self.ghaldra_helper.setBreakpoint(self.exit_point)

    def get_external_funcs(self):
        '''get what ghidra thinks are all the external functions'''
        external_functions = {}
        for symbol in self.program.getSymbolTable().getExternalSymbols():
            if symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION:
                func = symbol.getObject()
                thunk_addrs = func.getFunctionThunkAddresses()
                if len(thunk_addrs) == 1:
                    addr = thunk_addrs[0]
                    external_functions[addr] = func
        return external_functions

    def hook_external_functions(self):
        '''skip all external functions with a skip before any other registering
        then if user wants to use their implementation, use that'''
        external_functions = self.get_external_funcs()
        for item in external_functions.items():
            addr = item[0]
            func = item[1]
            address_int = int(addr.toString(),16)
            skip_int = {'addr': address_int, 'function': func.toString(),
                        'class': 'halucinator.bp_handlers.SkipFunc'}
            self.hook_func(addr, func, skip_int)

    def set_breakpoints(self):
        '''set breakpoints specified in config file'''
        if self.breakpoints:
            for point in self.breakpoints:
                address = self.get_address(point)
                self.logger.info("Setting breakpoint at address %s",  address)
                self.ghaldra_helper.setBreakpoint(address)

    def setup_intercepts(self):
        '''set intercepts specified in config file'''
        if self.intercepts:
            for intercept in self.intercepts:
                if intercept.has_key('addr'): #intercept on address as priority
                    address = self.get_address(intercept['addr'])
                    function = self.func_manager.getFunctionContaining(address)
                elif intercept.has_key('symbol'): #if no address then see if symbol exists
                    func_options = getGlobalFunctions(intercept['symbol'])
                    if len(func_options) != 1:
                        self.logger.warning("Could not hook %s, could not find function.",
                            (intercept['symbol']))
                        self.logger.warning("Try breakpoint instead or make function in ghidra!")
                    else:
                        function = func_options[0]
                else:
                    self.logger.warning("Couldn't hook %s, fix 'addr' or 'symbol' in config",
                        intercept)

                if 'addr_hook' in intercept:
                    if address:
                        self.hook_address(address, intercept)
                        self.logger.info("Hooking as address, not function")
                elif function:
                    self.logger.info("Hooking as function")
                    address = function.getEntryPoint()
                    intercept['addr'] = int(address.toString(), 16)
                    self.hook_func(address, function, intercept)
                else:
                    self.logger.warning("Could not hook %s, trying hook address instead",
                                        intercept)
                    if address:
                        self.hook_address(address, intercept)

    def hook_address(self, address, intercept):
        '''hooks and address for the emulator with a callback'''
        try:
            if address in self.hooked_func_addrs:
                self.ghaldra_helper.emulator.getBreakTable().unregisterAddressCallback(address)
            break_point = intercepts.register_bp_handler(self, intercept)
            callback = BreakCallBackWrapper(intercepts.addr_interceptor(self.program, self, \
                                            break_point, self.monitor), lambda x: True)
            self.ghaldra_helper.emulator.getBreakTable().registerAddressCallback(address, callback)
            self.hooked_func_addrs.add(address)
            self.logger.info('Hooked address `%s` with `%s`', str(address),
                            intercepts.func_interceptor.__name__)
        except Exception as err:
            self.logger.info("Errors %s occured. Arguments %s",
                err.message, err.args)
            self.logger.info("Could not hook address `%s` with `%s`", str(address),
                            intercepts.func_interceptor.__name__)

    def hook_func(self, address, function, intercept):
        '''hooks a function if possible, if not logs message and continues'''
        try:
            if address in self.hooked_func_addrs:
                self.logger.warning("Address is already hooked! Unhooking and rehooking")
                self.ghaldra_helper.emulator.getBreakTable().unregisterAddressCallback(address)
            break_point = intercepts.register_bp_handler(self, intercept)
            callback = BreakCallBackWrapper(intercepts.func_interceptor(self.program, self, \
                                            function, break_point, self.monitor), lambda x: True)
            self.ghaldra_helper.emulator.getBreakTable().registerAddressCallback(address, callback)
            self.hooked_func_addrs.add(address)
            self.logger.info('Hooked function `%s` at %s with `%s`', function.getName(),
                            str(address), intercepts.func_interceptor.__name__)
        except Exception as err:
            self.logger.warning("Errors %s occured. Arguments %s",
                err.message, err.args)
            self.logger.warning("COULD NOT HOOK FUNCTION!")
            if address is not None:
                self.ghaldra_helper.emulator.getBreakTable().unregisterAddressCallback(address)
                self.hooked_func_addrs.discard(address)
                if function:
                    self.logger.warning("Could not hook Function: %s Address: %s",
                                        function.getName(), address)

    def init_function_parameters(self, bytes_value_buffer=""):
        ''' Setup fn input parameters. Required to emulate.
                uses Ghidra parameter types and number of params '''

        fn_parameters_all_bytes_value = ""
        if self.symbol_map:
            for parameter in [self.symbol_map.getParam(i) \
                            for i in range(self.symbol_map.getNumParams())]:
                psize = self.parameter_storage_size(parameter)
                if len(bytes_value_buffer) < psize*2:
                    format_str = "Setting Parameters for " + str(parameter.name) \
                                + " (size: " + str(psize) + ")"
                    bytes_value_buffer = askString(
                        format_str,
                        'byte values')
                bytes_value = bytes_value_buffer[:psize*2]
                bytes_value = (bytes_value + "00"*psize)[:psize*2]
                assert len(bytes_value) == psize*2

                for i in range(0,len(bytes_value), 2):
                    if bytes_value[i] in string.hexdigits \
                            and bytes_value[i+1] in string.hexdigits:
                        continue
                    self.input_wildcards.append(bytes_value[i:i+2])

                self.parameter_map[parameter.name] = bytes_value
                fn_parameters_all_bytes_value += bytes_value

                bytes_value_buffer = bytes_value_buffer[psize*2:]

        if self.input_wildcards:
            self.logger.info("Found %d wildcards: %s", len(self.input_wildcards),
                            self.input_wildcards)
            self.logger.info("The next batch of cmds will be executed in fuzzing mode")

        for word in self.input_wildcards:
            self.byte_substitution[word] = "00"

        self.emulator_state = GHALdraState.READY

    def get_reg(self, reg_name):
        '''return the value from a register'''
        #Used in bp handlers
        return self.ghaldra_helper.readRegister(reg_name)

    def set_reg(self, reg_name, value):
        '''set the register value given the register and value'''
        #Used in bp handlers
        if isinstance(value, str):
            if value.startswith('0x'):
                value = long(value[2], 16)
            else:
                value = long(value[2])

        self.ghaldra_helper.writeRegister(reg_name, value)

    def get_addr_for_symbol(self, symbol):
        '''get the address from the given symbol'''
        #Used in bp handlers
        candidates = getGlobalFunctions(symbol)
        if len(candidates) != 1:
            self.logger.warning("More than one option for get_addr_for symbol!")
        return candidates[0].getEntryPoint()

    def get_symbol_name(self, address):
        '''get the function symbol name that contains address'''
        #Used in bp handlers
        address =  self.get_address(address)
        func = getFunctionContaining(address)
        if func:
            return func.getName()
        self.logger.warning("Could not get symbol name for %s",  address)
        return None

    def get_arg(self, position):
        '''get the arg at a position for a function'''
        #Used in bp handlers
        parameter = None
        try:
            address = self.ghaldra_helper.getExecutionAddress()
            #we should check to see if there is a function at this address
            #if not we should decompile here and then do this code
            if self.cur_function is None:
                self.cur_function = self.func_manager.getFunctionContaining(address)
            parameter = self.cur_function.getParameter(position)
            if parameter and parameter.isValid():
                psize = parameter.getLength()
                if parameter.isRegisterVariable():
                    arg = self.ghaldra_helper.readRegister(parameter.getRegister())
                elif parameter.isStackVariable():
                    #readStackValue(offset relative to sp, data size in bytes, signed if True)
                    arg = self.ghaldra_helper.readStackValue(
                        parameter.getStackOffset(), psize, True)
                elif parameter.isMemoryVariable():
                    arg = self.ghaldra_helper.readMemory(parameter.getMinAddress(), psize)
                #If not one of the above, this print should throw exception for the error below
                self.logger.debug("Position %s Arg is: %s", position, arg)
                return arg
        except Exception as err:
            self.logger.warning("Errors %s occured. Arguments %s",
                err.message, err.args)
            self.logger.warning("Error with get_arg, position %s, location: %s", \
                position, self.ghaldra_helper.getExecutionAddress())
        return None

    def parameter_storage_size(self, parameter):
        '''Helper functions for callback'''
        try: #For HighLocal
            return sum(map(lambda x: x.getSize(), parameter.getStorage().getVarnodes()))
        except Exception as err:
            self.logger.debug("Errors %s occured. Arguments %s",
                err.message, err.args)
            return parameter.getSize() #supposed to return size of the variable

    def get_address(self, offset):
        '''get an address from an offset or address'''
        try:
            address = ghaldra_utils.get_address(offset, program=self.program)
            return address
        except Exception as err:
            self.logger.info("Errors %s occured. Arguments %s",
                err.message, err.args)
            return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def get_stack_address(self, offset):
        '''get the address from value on the stack'''
        address = self.get_address(
            self.ghaldra_helper.readRegister(
                self.ghaldra_helper.getStackPointerRegister()) + offset)
        or_address = self.get_address(self.stack_pointer + offset)
        self.logger.debug('Stack address at %s or %s', address, or_address)
        return or_address

    def write_stack_value(self, offset, size, value):
        '''write a value on the emulator stack'''
        #used in bp handlers
        bytes_value = ghaldra_utils.long_to_bytes(value, size)
        if not self.ghaldra_helper.getLanguage().isBigEndian():
            bytes_value = bytes_value[::-1]
        self.ghaldra_helper.writeMemory(self.get_stack_address(offset), bytes_value)

    def apply_byte_substitution(self, bytes_value):
        '''used when doing fuzzing'''
        for key, value in self.byte_substitution.items():
            bytes_value = bytes_value.replace(key, value)
        return bytes_value.decode('hex')

    def restart(self, byte_substitution=None):
        self.ghaldra_helper.getEmulator().dispose()
        self.ghaldra_helper.dispose()
        self.__init__(self.plugin)

    def start(self, byte_substitution=None):
        ''' Write the fn inputs in memory (eventually applying the byte substitution) and
        \t   start the emulation, breaking at fn entry point'''
        assert self.emulator_state == GHALdraState.READY
        if byte_substitution is not None:
            self.byte_substitution = byte_substitution

        self.logger.info('Started with byte_sub: %r', self.byte_substitution)

        if self.symbol_map: #Only have if we can get highFunction
            for parameter in [self.symbol_map.getParam(i) \
                    for i in range(self.symbol_map.getNumParams())]:
                bytes_value = self.parameter_map[parameter.name]
                bytes_value = self.apply_byte_substitution(bytes_value)
                storage = parameter.getStorage()
                offset = 0
                for varnode in storage.getVarnodes():
                    chunk = bytes_value[offset:offset+varnode.getSize()]
                    if varnode.getAddress().isStackAddress():
                        self.ghaldra_helper.writeMemory(
                            self.get_stack_address(varnode.getAddress().getOffset()), chunk)
                    else:
                        self.ghaldra_helper.writeMemory(varnode.getAddress(), chunk)
                    offset += varnode.getSize()

        self.ghaldra_helper.setBreakpoint(self.function.getEntryPoint())
        self.ghaldra_helper.run(self.function.getEntryPoint(), self.entrypoint, self.monitor)

        self.emulator_state = GHALdraState.EXECUTING

    def execute_cmd(self, cmd):
        '''parses the command and calls the right handler'''
        cmd = cmd.strip().split()
        if cmd[0] not in self.cmd_handlers:
            self.logger.error("Unknown command %s (%r)", cmd[0], cmd)
            self.cmd_help(cmd)
        else:
            # call the actual handler
            self.cmd_handlers[cmd[0]](cmd)
            if cmd[0] != 'e':
                self.update_ui()
        self.logger.info('Stopping execution for %s at %08x with error %s',
                        self.ghaldra_helper.getEmulateExecutionState(),
                        self.ghaldra_helper.readRegister(self.ghaldra_helper.getPCRegister()),
                        self.ghaldra_helper.getLastError())

    def print_state(self):
        '''print the state of the emulator'''
        for symbol in self.program.getSymbolTable().getAllSymbols(True):
            symbol_object = symbol.getObject()
            try:
                data_type = symbol_object.getDataType()
                name = symbol.getName()
                if name in self.decompiled and symbol.getAddress() and data_type.getLength() > 0:
                    self.logger.debug('Found symbol name=%s type=%s location=%s',
                        name, data_type, symbol.getAddress())
                    bytes_value = self.ghaldra_helper.readMemory(symbol.getAddress(),
                                                                data_type.getLength())
                    string_value = bytes_value.tostring()
                    print_value = repr(string_value) if is_printable(string_value) \
                                                    else string_value.encode('hex')
                    self.logger.info('Variable %s has value `%s`', name, print_value)
            except AttributeError as err:
                self.logger.debug(str(err))
            except Exception as err:
                self.logger.error(str(err))

        write_set = self.ghaldra_helper.getTrackedMemoryWriteSet()
        for parameter in self.high_function.getLocalSymbolMap().getSymbols():
            if parameter.name not in self.decompiled:
                continue
            storage = parameter.getStorage()
            bytes_value = bytearray(0)
            for varnode in storage.getVarnodes():
                if varnode.getAddress().isStackAddress():
                    bytes_value.extend(self.ghaldra_helper.readMemory(
                        self.get_stack_address(varnode.getAddress().getOffset()),
                        varnode.getSize()))
                elif write_set.contains(varnode.getAddress()):
                    bytes_value.extend(self.ghaldra_helper.readMemory(
                        varnode.getAddress(), varnode.getSize()))
            string_value = str(bytes_value)
            print_value = repr(string_value) if is_printable(string_value) \
                                            else string_value.encode('hex')
            self.logger.info('Variable `%s` @ `%s` has value `%s`',
                            parameter.name, storage, print_value)

        for register in self.ghaldra_helper.getLanguage().getRegisters():
            if register.isBaseRegister() and not register.isProcessorContext():
                self.logger.debug(str(register))
                self.logger.debug(str(self.ghaldra_helper.readRegister(register)))

        self.logger.debug(str(self.ghaldra_helper))
        self.logger.debug(str(self.ghaldra_helper.getLanguage()))
        self.logger.debug(str(self.ghaldra_helper.getLanguage().getRegisters()))

        self.logger.info(str(['{} = {}'.format(
            register, self.ghaldra_helper.readRegister(register)) \
                for register in self.ghaldra_helper.getLanguage().getRegisters() \
                    if register.isBaseRegister() and not register.isProcessorContext()]))

        self.logger.info('Stopping execution at %08x',
            self.ghaldra_helper.readRegister(self.ghaldra_helper.getPCRegister()))
        self.logger.debug('Logged writes at %s',
            self.ghaldra_helper.getTrackedMemoryWriteSet())

    def read_memory(self, address, wordsize, num_words=1, raw=False):
        '''reads memory (to be compatible with HALucinator, wrap and send to our readMemory)
                :param address:   Address to read from
                :param wordsize:  the size of a read word (1, 2, 4 or 8)
                :param num_words: the amount of read words
                :param raw:       Whether the read memory should be returned unprocessed
                :return:          The read memory
        '''
        self.logger.debug("address: %s, wordsize: %s, num_words: %s, raw: %s",
                            address, wordsize, num_words, raw)
        size = wordsize*num_words
        address = self.get_address(address)
        if address.isConstantAddress():
            bytes_value = getBytes(address, size)
            string_value = str(bytes_value)
        else:
            bytes_value = bytearray(0)
            bytes_value.extend(self.ghaldra_helper.readMemory(address, size))
            string_value = str(bytes_value)
        self.logger.info('Reading from %s (size: %s): %s\n\thex=%s', address,
                        size, repr(string_value), string_value.encode("hex"))
        return string_value

    def read_pointer(self, address):
        '''read pointer from emulator'''
        self.logger.debug('reading %d from address %s',
            self.program.getLanguage().getProgramCounter().getBitLength()//8, str(address))
        packed = bytearray(0)
        packed.extend(self.ghaldra_helper.readMemory(
            address, self.program.getLanguage().getProgramCounter().getBitLength()//8))
        self.logger.debug('reading `%s` from address', repr(str(packed)))
        if not self.program.getLanguage().isBigEndian():
            packed = str(packed[::-1])
        self.logger.debug('got pointer at `%s`', repr(str(packed)))
        return int(packed.encode('hex'), 16)

    def read_string(self, addr, max_len=256):
        '''Test. Is in arm qemu model'''
        ret_string = self.read_memory(addr, 1, max_len, raw=True)
        ret_string = ret_string.decode('latin-1')
        return ret_string.split('\x00')[0]

    def write_memory(self, address, wordsize, val, num_words=1, raw=False):
        '''Write memory.
            :param address:   the address to write to
            :param wordsize:  size of a written word (1, 2, 4 or 8)
            :param val:       the value to write
            :type val:        int if num_words == 1 and raw == False,
                                                list of int if num_words > 1 and raw == False,
                                                str or byte if raw == True
            :param num_words: the amount of words to write
            :param raw:       whether to write in raw mode
            :return: True on success, False otherwise
        '''
        self.logger.debug("address: %s, wordsize: %s, val: %s, num_words: %s, raw: %s",
                            address, wordsize, val, num_words, raw)
        self.logger.info("val: %s",  val)
        bytes_value = val.encode("hex")
        self.logger.info("hexval: %s",  bytes_value)
        #write memory to emulator
        bytes_value = self.apply_byte_substitution(bytes_value)
        self.logger.info("bytes_valueType %s", type(bytes_value))
        address = self.get_address(address)
        self.written_addr_set.add(address)
        self.ghaldra_helper.writeMemory(address, bytes_value)
        self.logger.info("Current Address: %s", self.ghaldra_helper.getExecutionAddress())

    def update_ui(self):
        '''updates the UI in Ghidra, coloring visited instructions yellow and current instr green'''
        self.highlight_addr_set(self.addr_set)
        self.plugin.sync_view(self.ghaldra_helper.getExecutionAddress())
        regs = {}
        for register in self.ghaldra_helper.getLanguage().getRegisters():
            if register.isBaseRegister() and not register.isProcessorContext():
                reg = str(register)
                if "ARM" in str(self.program.getLanguageID()):
                    if len(reg) == 2 and reg[0] == 'r':
                        reg = 'r0' + reg[1]
                regs[reg] = str(self.ghaldra_helper.readRegister(register))

        registers = ""
        line_len = self._LINE_LEN
        for reg in sorted(regs.items()):
            entry = str(reg[0]) + ':'
            if len(entry) <= 6:
                entry += '\t'
            entry += str.format('0x{:08x}', int(reg[1]))
            line_len -= len(entry)
            if line_len <= 0:
                entry += "\n"
                line_len = self._LINE_LEN
            else:
                entry += ",\t"
            registers += entry
        self.plugin.set_registers(registers)

    def run(self, monitor, num_instr=None):
        '''runs the emulator until a breakpoint or timeout'''
        timeout = None
        update_num_instr = 1000
        if num_instr:
            timeout = num_instr
        elif self.timeout and self.timeout != 0:
            timeout = self.timeout

        self.ghaldra_helper.emulator.setHalt(False)
        index = 0
        update_index = 0
        cur_loc = None
        while not self.ghaldra_helper.emulator.getHalt() \
                    and not monitor.isCancelled():
            if timeout and index >= timeout:
                break
            if update_index >= update_num_instr:
                self.update_ui()
                update_index = 0
            if self.break_execution:
                break
            if self.stop_from_intercept:
                break
            if self.cur_interrupt:
                self.interrupts[self.cur_interrupt] = Context(self)
                self.logger.info("Interrupt %s triggered!",  self.cur_interrupt)
                break
            index += 1
            update_index += 1
            cur_loc = self.ghaldra_helper.getExecutionAddress()
            self.addr_set.add(cur_loc)
            self.logger.debug("PC %s",  cur_loc)
            self.cur_function = self.func_manager.getFunctionContaining(cur_loc)
            if len(self.last_addresses) == 0 or self.last_addresses[0] != cur_loc:
                self.last_addresses = [cur_loc] + self.last_addresses[:1]
            success = self.ghaldra_helper.step(monitor)
            if success:
                self.exe_instr.insert(0, cur_loc)
                del self.exe_instr[self.num_instr_to_save:]
        self.break_execution = False
        self.stop_from_intercept = False
        if cur_loc == self.exit_point:
            self.emulator_state = GHALdraState.DONE
            self.ghaldra_helper.emulator.setHalt(True)
            self.logger.info("Finished emulating %s function",  self.function)
        else:
            self.logger.info("Executed %s instructions before pausing",  index)

    def start_server(self):
        '''Starts the peripheral server. If wanted, change rx and tx port.'''
        self.server.start_server(self,)

    def stop_server(self):
        '''stops the peripheral server'''
        self.server.stop_server(self)

    def init_cmd_handlers(self):
        '''initializes the cmd handlers'''
        self.cmd_handlers = {
            'b': self.cmd_breakpoint_add,
            'break': self.cmd_break_exe,
            'c': self.cmd_continue,
            'd': self.cmd_breakpoint_remove,
            'e': self.cmd_eval,
            'h': self.cmd_help,
            'printpath': self.cmd_print_exe_path,
            'l': self.cmd_log_history,
            'n': self.cmd_next,
            'p': self.cmd_print_state,
            'q': self.cmd_quit,
            'read': self.cmd_read_mem,
            's': self.cmd_step,
            'timeout': self.cmd_timeout,
            'wm': self.cmd_write_mem,
            'wr': self.cmd_write_register,
            'hook': self.cmd_hook,
            'list_hooks': self.cmd_list_hook,
        }

    @history
    def cmd_breakpoint_add(self, cmd):
        '''`b 0xXXXXXXXX` - add breakpoint (`hex_address`)'''
        address = self.get_address(int(cmd[1], 16))
        self.ghaldra_helper.setBreakpoint(address)
        self.logger.info("Breakpoint set at %s", address)

    @history
    def cmd_break_exe(self, cmd):
        '''break at the current instruction. Can use to jump out of infinite loop'''
        self.break_execution = True

    @history
    def cmd_continue(self, cmd):
        '''continue - execute up to sys.maxint or timeout number of instructions in program'''
        self.run(self.monitor, self.timeout)

    @history
    def cmd_breakpoint_remove(self, cmd):
        '''`d 0xXXXXXXXX` - remove breakpoint (`hex_address`)'''
        address = self.get_address(int(cmd[1], 16))
        self.ghaldra_helper.clearBreakpoint(address)

    @history
    def cmd_eval(self, cmd):
        '''executes your command. e.g. `e print("Hello World")`'''
        exec(' '.join(cmd[1:]))

    @history
    def cmd_help(self, cmd):
        '''help - prints all the available commands'''
        self.logger.info("Commands:")
        for key, value in self.cmd_handlers.items():
            self.logger.info("\t%s: %s", key, value.__doc__)

    @history
    def cmd_print_exe_path(self, cmd):
        '''print the last X instructions executed
        \t   (x is specified as num_instrToSave in config file)'''
        self.logger.info("Last %d instructions executed",  self.num_instr_to_save)
        for addr in self.exe_instr:
            self.logger.info("%s",  addr)

    @history
    def cmd_log_history(self, cmd):
        '''prints a serialized version of this debugging session'''
        self.logger.debug(self.history)
        self.logger.info("`%s`",  (', '.join(self.history)))

    @history
    def cmd_next(self, cmd):
        '''`n [x]` - This will step over x instructions. It will count any function call
        \t   as a single instruction, executing the whole function)'''
        num_instr = 1
        if len(cmd) > 1:
            num_instr = int(cmd[1])
        for _ in range(0, num_instr):
            address = self.flatapi.getInstructionAfter(
                self.ghaldra_helper.getExecutionAddress()).getAddress()
            self.ghaldra_helper.setBreakpoint(address)
            self.run(self.monitor)
            self.ghaldra_helper.clearBreakpoint(address)

    @history
    def cmd_print_state(self, cmd):
        '''print state'''
        self.print_state()

    @history
    def cmd_quit(self, cmd):
        '''quit - prints the state and quits/closes the plugin'''
        self.update_ui()
        self.stop_server()
        self.plugin.quit_emulator()

    @history
    def cmd_read_mem(self, cmd):
        '''read memory addr (either `hex_from:hex_to` or `hex_from size`)'''
        if len(cmd) == 3:
            from_ = cmd[1]
            size = int(cmd[2], 16 if "0x" in cmd[2].lower() else 10)
        else:
            from_, to_ = map(lambda x: int(x,16), cmd[1].split(":"))
            size = to_ - from_
            from_ = hex(from_)
        self.read_memory(from_.replace("0x",""), 1, size)

    @history
    def cmd_step(self, cmd):
        '''`s [x]` - This will execute [x] instructions, even if it steps into a function.
        \t   if x is not specified it defaults to 1'''
        num_instr = 1
        if len(cmd) > 1:
            num_instr = int(cmd[1])
        self.run(self.monitor, num_instr)

    @history
    def cmd_timeout(self, cmd):
        '''`timeout x` Set number of instructions to timeout on to x.
        \t   e.g. `timeout 10` followed by c will execute 10 instructions'''
        self.timeout = int(cmd[1])

    @history
    def cmd_write_mem(self, cmd):
        '''write memory addr (`hex_addr hex_bytes
        \t    e.g. `wm 0x1234 hello` or `wm 0x01234 a1045b`)`)'''
        self.write_memory(cmd[1], 1, cmd[2], 1)

    @history
    def cmd_write_register(self, cmd):
        '''write a register (`reg_name value` e.g. `wr r2 2960982560` or `wr pc 0x01234`)'''
        if cmd[2].startswith('0x'):
            self.ghaldra_helper.writeRegister(str(cmd[1]), long(cmd[2], 16))
        else:
            self.ghaldra_helper.writeRegister(str(cmd[1]), long(cmd[2]))

    def read_register(self, reg_name):
        '''read a register'''
        register = self.ghaldra_helper.readRegister(reg_name)
        self.logger.info(hex(int(register)))
        return register

    @history
    def cmd_hook(self, cmd):
        '''hook address module.function - replace a function with a python implementation
        \t    e.g. hook 0x080355d8 bp_handlers.SkipFunc'''
        address = self.get_address(int(cmd[1], 16))
        function = self.func_manager.getFunctionContaining(address)
        intercept = {}
        intercept['addr'] = int(function.getEntryPoint().toString(), 16)
        intercept['function'] = function.getName()
        intercept['class'] = cmd[2]
        self.hook_func(address, function, intercept)

    @history
    def cmd_list_hook(self, cmd):
        '''List generic available hooks'''
        for handler in halucinator.bp_handlers.exports:
            for implm in handler.exports:
                for function in implm.exports:
                    self.logger.debug('Found function `%s`', function.__name__)
                    self.logger.info('%s.%s - %s',
                                    implm.__name__,
                                    function.__name__,
                                    function.__doc__)

    ##########################################################################
    #######: look what to do for these from HALucinator and implement ########
    ##########################################################################
    def irq_set_qmp(self, irq_num):
        '''irq_set_qmp. Needs interrupt table set to work'''
        self.logger.info("irq_set_qmp: %s", irq_num)

    def irq_clear_qmp(self, irq_num):
        '''irq_clear_qmp. Needs interrupt table set to work'''
        self.logger.info("irq_clear_qmp: %s", irq_num)

    def irq_set_bp(self, irq_num):
        '''irq_set_bp. Needs interrupt table set to work'''
        self.logger.info("irq_set_bp: %s", irq_num)

    def irq_clear_bp(self, irq_num):
        '''irq_clear_bp. Needs interrupt table set to work'''
        self.logger.info("irq_clear_bp: %s", irq_num)

    def set_vector_table_base(self, base):
        '''set_vector_table_base. Needs interrupt table set to work'''
        self.logger.info("set_vector_table_base: %s", base)

    def trigger_interrupt(self, num):
        '''trigger_interrupt. Needs interrupt table set to work'''
        self.logger.info("trigger_interrupt")
        #Trigger interrupt with the number
        self.cur_interrupt = num
        self.interrupts[self.cur_interrupt] = Context(self)
        self.logger.info("Interrupt %s triggered!",  self.cur_interrupt)

    def call(self, func_name, args=None):
        '''this should lookup the func_name from Ghidra,
        and do the function call with the given args'''
        self.logger.info("calling function %s with args: %s", func_name, args)
    ##########################################################################
    #######: look what to do for these from HALucinator and implement ########
    ##########################################################################

    ### FUNCTIONS USED FOR DEBUGGING,
    ### useful when using the `e` command for dynamic printing###
    ### Not exposing as a normal command until more testing is accomplished ###
    def load_hq_trace(self):
        ''' Ask for qemu_asm.log and stats.yaml file and load the instructions '''
        filename = askString("QEMU Log File",
            "Enter QEMU asm.log file (e.g. tmp/example/qemu_asm.log)")
        num_instr = 0
        with open(filename, "r") as addr_file:
            for _, line in enumerate(addr_file):
                if line.startswith('0x'):
                    int_addr = int(line.split()[0][2:-1], 16)
                    addr =  self.get_address(int_addr)
                    if addr:
                        self.hq_trace_addr_set.add(addr)
                        num_instr += 1
        self.logger.info("Loaded %d addresses from file", num_instr)

    def reset_highlight(self):
        '''reset the highlight to our executed instructions'''
        self.highlight_addr_set(self.addr_set)

    def highlight_addr_set(self, addr_set):
        '''highlight an address set'''
        prog_selection = ghidra.program.util.ProgramSelection(addr_set)
        service = self.plugin.getTool().getService(ghidra.app.services.GoToService)
        if service:
            navigatable = service.getDefaultNavigatable()
            if navigatable:
                navigatable.setHighlight(prog_selection)

    def highlight_diff(self):
        '''highlight the diff of hqtrace and our current addr_set'''
        curr_selection = self.plugin.get_ghidra_state().getCurrentHighlight()
        diff_addr_set = curr_selection.subtract(self.addr_set)
        self.highlight_addr_set(diff_addr_set)

    def highlight_same(self):
        '''highlight the intersection of hqtrace and our current addr_set'''
        curr_selection = self.plugin.get_ghidra_state().getCurrentHighlight()
        same_addr_set = curr_selection.intersect(self.addr_set)
        self.highlight_addr_set(same_addr_set)

    def get_reg_keys(self):
        '''shortcut to print the register keys from the 'e' command'''
        registers = []
        for reg in self.ghaldra_helper.getLanguage().getRegisters():
            registers.append(str(reg))
        return registers

    def print_regs(self):
        '''print the register values'''
        regs = {}
        for register in self.ghaldra_helper.getLanguage().getRegisters():
            if register.isBaseRegister() and not register.isProcessorContext():
                regs[str(register)] = str(self.ghaldra_helper.readRegister(register))
        self.logger.info("Registers: %s", regs)
        self.logger.info('Logged writes at %s',
            self.ghaldra_helper.getTrackedMemoryWriteSet())

    def print_pc(self):
        '''shortcut to print the pc from the 'e' command'''
        self.logger.info(hex(int(
            self.ghaldra_helper.readRegister(self.ghaldra_helper.getPCRegister()))))

    def print_mem_at_address(self, address, size=1):
        '''print_mem_at_address, useful for dynamic debugging'''
        address = self.get_address(address)
        self.logger.info("Address We are reading from: %s, with size: %s", address, size)
        to_print_bytes = getBytes(address, size)
        self.logger.info("Bytes: %s",  to_print_bytes)
        bytes_value = bytearray(0)
        bytes_value.extend(self.ghaldra_helper.readMemory(address, size))
        string_value = str(bytes_value)
        self.logger.info("bytes_value: %s",  bytes_value)
        self.logger.info("string_value: %s",  string_value)

_printable = set(string.printable)
def is_printable(input_string):
    '''helper function used for printing the memory and state of emulator'''
    return sum(map(lambda x: 1 if x in _printable else 0, input_string)) > len(input_string) * 3//4
