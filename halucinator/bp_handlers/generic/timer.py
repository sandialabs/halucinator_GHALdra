# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

import time
from binascii import hexlify
from os import path

from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler


class Timer(BPHandler):
    '''
        Returns an increasing value based of host system time 

        - class: halucinator.bp_handlers.Timer
          function: <func_name> (Can be anything)
          registration_args: { scale:(value)} (Optional)
          addr: <addr>
    '''

    def __init__(self):
        self.start_time = {}
        self.scale = {}

    def register_handler(self, qemu, addr, func_name, scale=1):
        '''

        '''
        self.start_time[addr] = time.time()
        self.scale[addr] = scale

        return Timer.get_value

    @bp_handler
    def get_value(self, qemu, addr):
        '''
            Gets the current timer value
        '''
        time_ms = int(
            (time.time() - self.start_time[addr]) * 1000 / float(self.scale[addr]))
        qemu.logger.info("Time: %i" % time_ms)

        return True, time_ms

exports = [
    Timer,
]
