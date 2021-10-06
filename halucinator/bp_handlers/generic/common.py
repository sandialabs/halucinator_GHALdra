# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

from __main__ import *
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

name = 'common'

class ReturnZero(BPHandler):
    '''
        Break point handler that just returns zero

        Halucinator configuration usage:
        - class: halucinator.bp_handlers.ReturnZero
          function: <func_name> (Can be anything)
          registration_args: {silent:false}
          addr: <addr>
    '''
    def __init__(self, filename=None):
        self.silent = {}
        self.func_names = {}

    def register_handler(self, qemu, addr, func_name, silent=False):
        qemu.logger.debug("Registering: %s at addr: %s with ReturnZero" %(func_name, hex(addr)))
        self.silent[addr] = silent
        self.func_names[addr] = func_name
        return ReturnZero.return_zero

    @bp_handler
    def return_zero(self, qemu, addr, *args):
        '''
            Intercept Execution and return 0
        '''
        if not self.silent[addr]:
            qemu.logger.info("ReturnZero: %s " %(self.func_names[addr]))
        return True, 0


class ReturnConstant(BPHandler):
    '''
        Break point handler that returns a constant

        Halucinator configuration usage:
        - class: halucinator.bp_handlers.ReturnConstant
          function: <func_name> (Can be anything)
          registration_args: { ret_value:(value), silent:false}
          addr: <addr>
    '''
    def __init__(self, filename=None):
        self.ret_values = {}
        self.silent = {}
        self.func_names = {}

    def register_handler(self, qemu, addr, func_name, ret_value=None, silent=False):
        qemu.logger.debug("Registering: %s at addr: %s with ReturnConstant %s" %(func_name, hex(addr), ret_value))
        self.ret_values[addr] = ret_value
        self.silent[addr] = ret_value
        self.func_names[addr] = func_name
        return ReturnConstant.return_constant

    @bp_handler
    def return_constant(self, qemu, addr, *args):
        '''
            Intercept Execution and return 0
        '''
        if not self.silent[addr]:
            qemu.logger.debug("ReturnConstant: %s : %#x" %(self.func_names[addr], self.ret_values[addr]))
        return True, self.ret_values[addr]


class SkipFunc(BPHandler):
    '''
        Break point handler that immediately returns from the function
        Halucinator configuration usage:
        - class: halucinator.bp_handlers.SkipFunc
          function: <func_name> (Can be anything)
          registration_args: {silent:false}
          addr: <addr>
    '''
    def __init__(self, filename=None):
        self.silent = {}
        self.func_names = {}

    def register_handler(self, qemu, addr, func_name, silent=False):
        qemu.logger.debug("Registering: %s at addr: %s" %(func_name, hex(addr)))
        self.silent[addr] = silent
        self.func_names[addr] = func_name
        return SkipFunc.skip

    @bp_handler
    def skip(self, qemu, addr, *args):
        '''
            Just return
        '''
        qemu.logger.info("SkipFunc: %s " %(self.func_names[addr]))
        return True, None

class SetRegisters(BPHandler):
    '''
        Break point handler that changes a register

        Halucinator configuration usage:
        - class: halucinator.bp_handlers.SetRegisters
          function: <func_name> (Can be anything)
          registration_args: { registers: {'<reg_name>':<value>}}
          addr: <addr>
          addr_hook: True
    '''
    def __init__(self, filename=None):
        self.changes = {}

    def register_handler(self, qemu, addr, func_name, registers={}):
        qemu.logger.debug("Registering: %s at addr: %s with SetRegisters %s" %(func_name, hex(addr), registers))
        self.changes[addr] = registers
        return SetRegisters.set_registers

    @bp_handler
    def set_registers(self, qemu, addr, *args):
        '''
            Intercept Execution and return 0
        '''
        for change in self.changes[addr].items():
            reg = change[0]
            value = change[1]
            qemu.ghaldra_helper.writeRegister(reg, value)
            qemu.logger.debug("ChangeRegister: %s : %#x" %(reg, value))
        return False, 0

exports = [
    ReturnZero,
    ReturnConstant,
    SkipFunc,
    SetRegisters,
]
