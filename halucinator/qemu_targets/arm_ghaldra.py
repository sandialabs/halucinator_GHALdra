# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

from ghaldra import GHALdra
from halucinator.bp_handlers import intercepts
from halucinator.bp_handlers.bp_handler import BPHandler


class AllocedMemory():
    def __init__(self, target, base_addr, size):
        self.target = target
        self.base_addr = base_addr
        self.size = size
        self.in_use = True

    def zero(self):
        zeros = "\x00"* self.size
        self.target.write_memory(self.base_addr, 1, zeros, raw=True)

    def alloc_portion(self, size):
        if size < self.size:
            new_alloc = AllocedMemory(self.target, self.base_addr, size)
            self.base_addr += size
            self.size -= size
            return new_alloc, self
        elif size == self.size:
            self.in_use = True
            return self, None
        else:
            raise ValueError("Trying to alloc %i bytes from chuck of size %i" %(size, self.size))

    def merge(self, block):
        '''
            Merges blocks with this one
        '''
        self.size += block.size
        self.base_addr = self.base_addr if self.base_addr <= block.base_addr else block.base_addr

class ARMQemuTarget(GHALdra):
    '''
        Implements a QEMU target that has function args for use with
        halucinator.  Enables read/writing and returning from
        functions in a calling convention aware manner
    '''
    def __init__(self, *args, **kwargs):
        super(ARMQemuTarget, self).__init__(*args, **kwargs)
        self.irq_base_addr = None
        self.logger.warning("arm ghaldra init")

    def get_arg(self, idx):
        '''
            Gets the value for a function argument (zero indexed)

            :param idx  The argument index to return
            :returns    Argument value
        '''
        self.logger.warning("arm ghaldra get_arg")
        if idx >= 0 and idx < 4:
            return self.read_register("r%i" % idx)
        elif idx >= 4:
            sp = self.read_register("sp")
            stack_addr = sp + (idx-4) * 4
            return self.read_memory(stack_addr, 4, 1)
        else:
            raise ValueError("Invalid arg index")

    def set_args(self, args):
        '''
            Sets the value for a function argument (zero indexed)

            :param args:  Iterable of args to set
        '''
        self.logger.warning("arm ghaldra set_args")
        for idx, value in enumerate(args[0:4]):
            if idx < 4:
                self.write_register(("r%i" % idx), value)
            else:
                break

        sp = self.read_register("sp")
        for idx, value in enumerate(args[:3:-1]):
            sp -= 4
            self.write_memory(sp, 4, value)

        self.write_register('sp', sp)
        return sp
