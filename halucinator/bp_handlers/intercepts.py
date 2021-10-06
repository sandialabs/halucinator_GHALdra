# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

'''intercept master for GHALdra'''
import importlib
from functools import wraps

from ghaldra_utils import ghaldra_utils

initalized_classes = {}
bp2handler_lut = {}

def get_bp_handler(intercept_desc):
    '''
        gets the bp_handler class from the config file class name.
        Instantiates it if has not been instantiated before if it
        has it just returns the instantiated instance
    '''
    split_str = intercept_desc['class'].split('.')

    module_str = ".".join(split_str[:-1])
    class_str = split_str[-1]
    module = importlib.import_module(module_str)

    cls_obj = getattr(module, class_str)
    if cls_obj in initalized_classes:
        bp_class = initalized_classes[cls_obj]
    else:
        if 'class_args' in intercept_desc and intercept_desc['class_args'] is not None:
            print('Class:', cls_obj)
            print('Class Args:', intercept_desc['class_args'])
            bp_class = cls_obj(**intercept_desc['class_args'])
        else:
            bp_class = cls_obj()
        initalized_classes[cls_obj] = bp_class
    return bp_class


def register_bp_handler(ghaldra, intercept_desc):
    '''
    '''
    bp_cls = get_bp_handler(intercept_desc)
    if 'registration_args' in intercept_desc and \
                        intercept_desc['registration_args'] is not None:
        ghaldra.logger.info("Registering BP Handler: %s.%s : %s, registration_args: %s" % (
                intercept_desc['class'], intercept_desc['function'], hex(intercept_desc['addr']),
                str(intercept_desc['registration_args'])))
        handler = bp_cls.register_handler(ghaldra,
                                        intercept_desc['addr'],
                                        intercept_desc['function'],
                                        **intercept_desc['registration_args'])
    else:
        ghaldra.logger.info("Registering BP Handler: %s.%s : %s" % (
            intercept_desc['class'], intercept_desc['function'], hex(intercept_desc['addr'])))
        handler = bp_cls.register_handler(ghaldra,
                                        intercept_desc['addr'],
                                        intercept_desc['function'])
    break_point = intercept_desc['addr']
    bp2handler_lut[break_point] = (bp_cls, handler)
    ghaldra.logger.debug("BP is %s" % hex(break_point))
    return break_point

def args_wrapper(func):
    @wraps(func)
    def wrapped(program, ghaldra, function, break_point, monitor, *args):
        @wraps(func)
        def stub(address):
            try:
                ######################################################################
                function_offset = function.getEntryPoint().getOffset()
                while function_offset not in function_arguments_cache and \
                        not monitor.isCancelled():
                    decompinterface = DecompInterface()
                    decompinterface.openProgram(program)
                    result = decompinterface.decompileFunction(function, 0, monitor)
                    high_function = result.getHighFunction()
                    if not result.isCancelled() and not result.isTimedOut() and high_function:
                        function_arguments_cache[function_offset] = high_function
                high_function = function_arguments_cache[function_offset]
                symbol_map = high_function.getLocalSymbolMap()
                args = []
                for parameter in [symbol_map.getParam(i) \
                        for i in range(symbol_map.getNumParams())]:
                    ghaldra.logger.debug("Found parameter `%s` with size `%d` with type `%s`",
                        (parameter.getName(),
                        parameter.getSize(),
                        str(parameter.getDataType())))
                    param = getParam(parameter, ghaldra, monitor)
                    args.append(param)
                ######################################################################
                intercept, retval = func(program, ghaldra, function, break_point, monitor, *args)
                ghaldra.logger.debug('Finish execution of hook %s with return value %s',
                    (func.__name__, repr(retval)))
                if intercept:
                    try:
                        if retval is not None and isinstance(retval, (int,long)):
                            offset = 0
                            retvarnodes = function.getReturn().getVariableStorage().getVarnodes()
                            if retvarnodes:
                                for varnode in retvarnodes:
                                    if varnode.getAddress().isRegisterAddress():
                                        reg = currentProgram.getRegister(varnode.getAddress())
                                        ghaldra.ghaldra_helper.writeRegister(reg, retval)
                                    else:
                                        pointer_size = \
                                            currentProgram.getLanguage().getProgramCounter().getBitLength() \
                                            //8
                                        bretval = ghaldra_utils.long_to_bytes(retval, pointer_size)
                                        if not ghaldra.program.getLanguage().isBigEndian():
                                            bretval = bretval[::-1]
                                        ghaldra.ghaldra_helper.writeMemory(
                                                varnode.getAddress(),
                                                bretval[offset:offset+varnode.getSize()])
                                    offset += varnode.getSize()
                        else:
                            print("retval is not of type int or long")
                    except:
                        print("Error saving return value")
                    ghaldra.logger.info('Finish execution of hook %s we were at %s before',
                        (func.__name__, str(ghaldra.last_addresses)))
                    ghaldra.logger.info('Return value: %s' % retval)
                    current = ghaldra.ghaldra_helper.getExecutionAddress()
                    for address in ghaldra.last_addresses:
                        ghaldra.logger.debug("CurrentAddress: %s\tLastAddresses: %s",
                            current, address)
                        ghaldra.logger.debug('Checking if %s is different from %s',
                            address, current)
                        if str(address) != str(current):
                            next_address = ghaldra.flatapi.getInstructionAfter(address).getAddress()
                            ghaldra.logger.debug('I propose to go to %s now', str(next_address))
                            ghaldra.ghaldra_helper.getEmulator().setExecuteAddress(
                                next_address.getOffset())
                            ghaldra.logger.debug('Can you believe that we are at %s now?',
                                str(ghaldra.ghaldra_helper.getExecutionAddress()))
                            break
                    return True
            except:
                print("*"*40)
                ghaldra.logger.info("Emulation Error!")
                current = ghaldra.ghaldra_helper.getExecutionAddress()
                for addr in ghaldra.last_addresses:
                    ghaldra.logger.debug("CurrentAddress: %s\tLastAddresses: %s", current, addr)
                    ghaldra.logger.debug('Checking if %s is different from %s', addr, current)
                    if str(addr) != str(current):
                        ghaldra.logger.debug('address offset: 0x%08x', addr.getOffset() + 4)
                        next_address = ghaldra_utils.get_address((addr.getOffset()+ 4))
                        ghaldra.logger.info('I propose to go to %s now', str(next_address))
                        ghaldra.ghaldra_helper.getEmulator().setExecuteAddress(
                            next_address.getOffset())
                        ghaldra.logger.debug('Can you believe that we are at %s now?',
                            str(ghaldra.ghaldra_helper.getExecutionAddress()))
                        break
                return True
        ghaldra.logger.debug('Creating function callback for `%s`', func.__name__)
        return stub
    return wrapped

def default_wrapper(func):
    @wraps(func)
    def wrapped(program, ghaldra, break_point, monitor, *args):
        @wraps(func)
        def stub(address):
            intercept, retval = func(program, ghaldra, break_point, monitor, *args)
            ghaldra.logger.info('Finish execution of hook %s we were at %s before',
                func.__name__, str(ghaldra.last_addresses))
            current = ghaldra.ghaldra_helper.getExecutionAddress()
            if intercept:
                for addr in ghaldra.last_addresses:
                    ghaldra.logger.debug("CurrentAddress: %s\tLastAddresses: %s",
                        current,addr)
                    ghaldra.logger.debug('Checking if %s is different from %s',
                        addr, current)
                    if str(addr) != str(current):
                        next_address = ghaldra.flatapi.getInstructionAfter(addr).getAddress()
                        ghaldra.logger.debug('I propose to go to %s now', str(next_address))
                        ghaldra.ghaldra_helper.getEmulator().setExecuteAddress(
                            next_address.getOffset())
                        ghaldra.logger.debug('Can you believe that we are at %s now?',
                            str(ghaldra.ghaldra_helper.getExecutionAddress()))
                        break
            else:
                next_address = ghaldra.flatapi.getInstructionAfter(current).getAddress()
                ghaldra.ghaldra_helper.getEmulator().setExecuteAddress(next_address.getOffset())
            return intercept, retval
        return stub
    return wrapped


function_arguments_cache = {}
# @args_wrapper - this will work on most elfs, not raw binaries. Ghidra isn't good enough at highfuncs yet
@default_wrapper
def func_interceptor(program, ghaldra, function, break_point, monitor, *args):
    '''
        This is one of only 2 hooked functions. It will lookup and call the correct handler
        from the address. This function is wrapped by a decorator that will try to automatically
        get the arguments, as well as automatically save the return values according to
        ghidra decompilation.
    '''
    cls, method = bp2handler_lut[break_point]
    program_counter = int(function.getEntryPoint().toString(), 16)
    intercept, retval = method(cls, ghaldra, program_counter, *args)
    if intercept and retval is not None:
        try:
            if retval is not None and isinstance(retval, (int,long)):
                offset = 0
                retvarnodes = function.getReturn().getVariableStorage().getVarnodes()
                if retvarnodes:
                    for varnode in retvarnodes:
                        if varnode.getAddress().isRegisterAddress():
                            reg = program.getRegister(varnode.getAddress())
                            ghaldra.ghaldra_helper.writeRegister(reg, retval)
                        else:
                            pointer_size = \
                                program.getLanguage().getProgramCounter().getBitLength() \
                                //8
                            bretval = ghaldra_utils.long_to_bytes(retval, pointer_size)
                            if not ghaldra.program.getLanguage().isBigEndian():
                                bretval = bretval[::-1]
                            ghaldra.ghaldra_helper.writeMemory(
                                    varnode.getAddress(),
                                    bretval[offset:offset+varnode.getSize()])
                        offset += varnode.getSize()
            else:
                print("retval is not of type int or long")
        except:
            print("Error saving return value")
            if "ARM" in str(program.getLanguageID()):
                ghaldra.ghaldra_helper.writeRegister("r0", retval)
    return intercept, retval

@default_wrapper
def addr_interceptor(program, ghaldra, break_point, monitor, *args):
    '''
        This is one of only 2 hooked functions. It will lookup and call the correct handler
        from the address.
    '''
    cls, method = bp2handler_lut[break_point]
    intercept, retval = method(cls, ghaldra, break_point, *args)
    return intercept, retval
