# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

import logging
import re
import sys

from __main__ import *
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler

name = 'libc6'
from ghaldra_utils import ghaldra_utils

h_stdout = logging.StreamHandler(sys.stdout)
h_stdout.setLevel(logging.INFO)

class Libc6(BPHandler):
  '''
        Handles puts currently

        Halucinator configuration usage:
        - class: halucinator.bp_handlers.Libc6
          function: <func_name>
          addr: <addr>
    '''
  def __init__(self, filename=None):
    self.silent = {}
    self.func_names = {}

  def register_handler(self, ghaldra, addr, func_name, silent=False):
    ghaldra.logger.info("Registering: %s at addr: %s with Libc6" %(func_name, hex(addr)))
    self.silent[addr] = silent
    self.func_names[addr] = func_name
    return BPHandler.register_handler(self, ghaldra, addr, func_name)
  
  def read_string(self, ghaldra, addr):
    str_list = []
    not_null = True
    while not_null:
      str_list.append(chr(ghaldra.read_memory(addr,1,1)))
      not_null =  str_list[-1] != '\x00'
      addr += 1
    return ''.join(str_list)

  @bp_handler(['puts'])
  def puts(self, ghaldra, addr):
    ghaldra.logger.debug('puts 0x%08x' % addr)
    function = getFunctionContaining(ghaldra_utils.get_address(addr))
    args = ghaldra_utils.get_decompiled_args_from_ghidra(ghaldra, function)
    p = args[0]
    s = []
    i = 0
    while p[i] != '\x00' and i < 1000:
        s.append(p[i])
        i += 1
    _format = '{}'.format(repr(''.join(s)))
    ghaldra.logger.info('puts : %s'% _format)
    return True, 1 

  @bp_handler(['printf'])
  def printf(self, ghaldra, addr):
    ghaldra.logger.debug('printf 0x%08x' % addr)
    function = getFunctionContaining(ghaldra_utils.get_address(addr))
    args = ghaldra_utils.get_decompiled_args_from_ghidra(ghaldra, function)
    p = args[0]
    s = []
    i = 0
    while p[i] != '\x00' and i < 1000:
        s.append(p[i])
        i += 1
    _format_str = '{}'.format(repr(''.join(s)))
    
    formats = []
    strsplit = re.split('(\W)', _format_str)
    for i, element in enumerate(strsplit):
      if element == "%" and len(strsplit) > i + 1:
        formats.append(strsplit[i+1].replace('lhLzjt', '')) #removes length fields
    printf_args = []
    for i, form in enumerate(formats):
      arg_int = i + 1
      if i < 8:
        reg = 'x'+str((arg_int))
        value = ghaldra.ghaldra_helper.readRegister(reg)
        if "i" in form or "d" in form: #int
          value = int(value)
        elif "f" in form or "F" in form: # double in normal form
          value = float(value)
        elif "x" in form or "X" in form: # hexidecimal
          value = int(value)
        elif "s" in form: #null terminated string
          value = str(value)
        elif "c" in form: #character
          value = str(value)
        elif "e" in form or "E" in form: # double in standard form
          value = float(value)
        elif "g" in form or "G" in form: # double in normal or exponential form
          value = float(value)
        elif "o" in form: #unsigned int in octal
          value = int(value)
        elif "a" in form or "A" in form: # double in dex notation
          value = float(value)
        # elif "p" in form: #void pointer
        # # elif "n" in form: # print nothing but writes the number of characters written so far into integer pointer parameter
        printf_args.append(value)
    
    print_string = ghaldra_utils.format_string(_format_str, *printf_args)
    ghaldra.logger.debug('printf _format: %s'% _format_str)
    ghaldra.logger.debug('%s'% print_string)
    print('%s' % print_string)
    return True, len(print_string)

exports = [
  Libc6,
]
