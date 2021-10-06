# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

import struct
import sys

import ghidra
import yaml
from __main__ import *
from ghidra.app.decompiler import DecompInterface

# the following snippet of code was copied from  
# https://github.com/dlitz/pycrypto/blob/7acba5f3a6ff10f1424c309d0d34d2b713233019/lib/Crypto/Util/py3compat.py
# https://github.com/dlitz/pycrypto/blob/7acba5f3a6ff10f1424c309d0d34d2b713233019/lib/Crypto/Util/number.py#L387
# see https://github.com/dlitz/pycrypto/blob/7acba5f3a6ff10f1424c309d0d34d2b713233019/COPYRIGHT for the original owner license terms

if sys.version_info[0] == 2:
    from types import \
            UnicodeType as \
            _UnicodeType  # In Python 2.1, 'unicode' is a function, not a type.

    def b(s):
        return s
    def bchr(s):
        return chr(s)
    def bstr(s):
        return str(s)
    def bord(s):
        return ord(s)
    def tobytes(s):
        if isinstance(s, _UnicodeType):
            return s.encode("latin-1")
        else:
            return ''.join(s)
    def tostr(bs):
        return unicode(bs, 'latin-1')
    # In Pyton 2.x, StringIO is a stand-alone module
    from StringIO import StringIO as BytesIO
else:
    def b(s):
        return s.encode("latin-1") # utf-8 would cause some side-effects we don't want
    def bchr(s):
        return bytes([s])
    def bstr(s):
        if isinstance(s,str):
            return bytes(s,"latin-1")
        else:
            return bytes(s)
    def bord(s):
        return s
    def tobytes(s):
        if isinstance(s,bytes):
            return s
        else:
            if isinstance(s,str):
                return s.encode("latin-1")
            else:
                return bytes(s)
    def tostr(bs):
        return bs.decode("latin-1")
    # In Pyton 3.x, StringIO is a sub-module of io
    from io import BytesIO

def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.
    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    bfrmt = '0' + str((blocksize)) + 'b'
    return bytearray(format(n, bfrmt))

def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.
    This is (essentially) the inverse of long_to_bytes().
    """
    return int(bytes.encode('hex'),16)

##############################################END OF COPIED CODE############################

def format_string(format_str, *args):
    return format_str % args

def read_yaml(filename):
    with open(filename, 'r') as stream:
        try:
            db = yaml.safe_load(stream)
            return db
        except yaml.YAMLError as exc:
            print(exc)
            # sys.exit()

def get_address(address=None, program=None):
    """ 
    Take an integer/string address and turn it into a ghidra address
    If not address provided, get the current address
    """
    if address is None:
        if program is not None:
            if program != getState().getCurrentProgram():
                raise Exception(
                    "Using current address, but have specified not current program")
        return getState().getCurrentAddress()
    if isinstance(address, ghidra.program.model.address.GenericAddress):
        # already done, no need to fix
        return address
    if program is None:
        program = getState().getCurrentProgram()
    if not isinstance(address, str) and not isinstance(address, unicode):
        address = hex(address)
        if address.endswith("L"):
            address = address[:-1]
    return program.getAddressFactory().getAddress(address)

def get_func_last_instr_addr(function, addressFactory=None):
    if function is None:
        return None
    if addressFactory is None:
        addressFactory =  currentProgram.getAddressFactory()  
    endAddr = get_address(int(function.getEntryPoint().toString(), 16) + 
                          function.getBody().getNumAddresses() - 2, currentProgram) 
    endInstr = getInstructionContaining(endAddr)    
    if endInstr:
        endAddr = endInstr.getAddress()                                 
    return endAddr

signed_format = {
    2: 'h',
    4: 'i',
    8: 'q'
}
unsigned_format = {
    2: 'h',
    4: 'i',
    8: 'q'
}
unsigned_types = set([
'uint', 'ulong', 'ushort'
])

signed_types = set([
    'int', 'long', 'short'
])

integer_types = unsigned_types.union(signed_types)

class NativePointer():
    def __init__(self, address, parameter, ghaldra):
        self.ghaldra = ghaldra
        self.parameter = parameter
        self.pointed_type = parameter.getDataType().getDataType()
        self.address = ghaldra.get_address(ghaldra.read_pointer(address))
        ghaldra.logger.debug('NativePointer at address %s' % str(self.address))

    def __setitem__(self, key, item):
        self.ghaldra.ghaldra_helper.writeMemory(self.address.add(key * self.pointed_type.getLength()), item)
    
    def __getitem__(self, key):
        self.ghaldra.logger.debug('reading %d bytes from %s at %d' % (self.pointed_type.getLength(), self.address, key))
        self.ghaldra.logger.debug('reading %d bytes from %s at %d' % (self.pointed_type.getLength(), self.address.add(key * self.pointed_type.getLength()), key))
        ret = bytearray(0)
        ret.extend(self.ghaldra.ghaldra_helper.readMemory(self.address.add(key * self.pointed_type.getLength()), self.pointed_type.getLength()))
        self.ghaldra.logger.debug('reading `%s` at %d' % (repr(ret), key))
        return str(ret)
    
    def __repr__(self):
        return '<NativePointer(address=`%s`, pointed_type=`%s`)>' % (self.address, self.pointed_type)

def get_param_bytes(parameter, ghaldra):
    ghaldra.logger.debug("Found parameter `%s` with size `%d` with type `%s`" % 
                        (parameter.getName(), parameter.getSize(), str(parameter.getDataType())))
    storage = parameter.getStorage()
    content =  bytearray(0)
    for varnode in storage.getVarnodes():
        if varnode.getAddress().isStackAddress():
            content.extend(ghaldra.ghaldra_helper.readMemory(
                            ghaldra.get_stack_address(varnode.getAddress().getOffset()), 
                            varnode.getSize()))
        else:
            content.extend(ghaldra.ghaldra_helper.readMemory(varnode.getAddress(), varnode.getSize()))
    ghaldra.logger.debug("got a nice content `%s`" % (repr(content)))
    return content

def is_pointer(data_type):
    return 'getDataType' in dir(data_type) 

def is_c_string(data_type):
    return is_pointer(data_type) and 'char' in data_type.getDataType().toString()

def get_varnode_address(varnode, ghaldra):
    if varnode.getAddress().isStackAddress():
        return ghaldra.get_stack_address(varnode.getAddress().getOffset())
    else:
        return varnode.getAddress()

def get_param(parameter, ghaldra, monitor):
    data_type = parameter.getDataType()
    if is_pointer(data_type):
        varnode = parameter.getRepresentative()
        address = get_varnode_address(varnode, ghaldra)
        ghaldra.logger.debug('parameter is at %s' % str(address))
        return NativePointer(address, parameter, ghaldra)
    content = get_param_bytes(parameter, ghaldra)
    type_name = parameter.getDataType().getName()
    if type_name in integer_types and len(content) in signed_format:
        ghaldra.logger.debug('parameter is with type %s the content is %d bytes' % (type_name, len(content)))
        struct_format = ('>' if ghaldra.program.getLanguage().isBigEndian() else '<') + ((signed_format if type_name in signed_types else unsigned_format)[len(content)])
        return struct.unpack(struct_format, str(content))[0]
    return content

function_arguments_cache = {}
def get_decompiled_args_from_ghidra(ghaldra, function):
    monitor = ghaldra.monitor
    try:
        ######################################################################
        function_offset = function.getEntryPoint().getOffset()
        while function_offset not in function_arguments_cache and not monitor.isCancelled():
            decompinterface = DecompInterface()
            decompinterface.openProgram(ghaldra.program)
            result = decompinterface.decompileFunction(function, 0, monitor)
            high_function = result.getHighFunction()
            if not result.isCancelled() and not result.isTimedOut() and high_function:
                function_arguments_cache[function_offset] = high_function
        high_function = function_arguments_cache[function_offset]
        symbol_map = high_function.getLocalSymbolMap()
        args = []
        for parameter in [symbol_map.getParam(i) for i in range(symbol_map.getNumParams())]:
            ghaldra.logger.debug("Found parameter `%s` with size `%d` with type `%s`",
                    parameter.getName(),
                    parameter.getSize(),
                    str(parameter.getDataType()))
            param = get_param(parameter, ghaldra, monitor)
            args.append(param)
        return args
    except:
        ghaldra.logger.debug("*"*40)
        ghaldra.logger.debug("get_decompiled_args_from_ghidra Failed, returning None!")
        return None

