# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

from collections import deque

from halucinator.peripheral_models import peripheral_server
from halucinator.peripheral_models.interrupts import \
    Interrupts as InterruptsModel


class UTTYInterface:

    def __init__(self, interface_id, enabled=True,
                  irq_num=None,):
        self.interface_id = interface_id
        self.rx_queue = deque()
        self.tx_queue = deque()
        self.irq_num = irq_num
        self.enabled = enabled

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def flush(self):
        self.rx_queue.clear()

    def disable_irq(self):
        self.irq_enabled = False

    def enable_irq_bp(self):
        InterruptsModel.clear_active_bp(self.irq_num)

    def _fire_interrupt_bp(self):
        if self.rx_queue and self.irq_num:
            InterruptsModel.set_active_bp(self.irq_num)

    def _fire_interrupt_qmp(self):
        if self.rx_queue and self.irq_num:
            print("Sending Interupt for %s: %#x" %(self.interface_id, self.irq_num))
            InterruptsModel.set_active_qmp(self.irq_num)


    def buffer_rx_chars_qmp(self, chars):
        '''

        '''
        if self.enabled:
            print("Adding chars to: %s" % self.interface_id)
            for char in chars:
                self.rx_queue.append(char)

            self._fire_interrupt_qmp()
        else:
            return


    def get_rx_char(self, get_time=False):
        char = None

        if self.rx_queue:
            char = self.rx_queue.popleft()

        if get_time:
            return char
        else:
            return char

    def get_rx_buff_size(self, ):
        if self.rx_queue:
            return len(self.rx_queue)

    def buffer_tx_char_qmp(self, char):
        '''

        '''
        if self.enabled:
            self.tx_queue.append(char)
            print("Adding char to: %s" % self.interface_id)
            self._fire_interrupt_qmp()
        else:
            return
    def get_tx_char(self, get_time=False):
        char = None

        if self.tx_queue:
            char = self.tx_queue.popleft()

        if get_time:
            return char
        else:
            return char

    def get_tx_buff_size(self, ):
        if self.tx_queue:
            return len(self.tx_queue)


@peripheral_server.peripheral_model
class UTTYModel(object):

    interfaces = dict()

    @classmethod
    def add_interface(cls, interface_id, enabled=True,irq_num=None,):
        '''

        '''
        interface = UTTYInterface(interface_id, enabled=True,irq_num=irq_num)
        cls.interfaces[interface_id] = interface

    @classmethod
    def enable(cls, interface_id):
        cls.interfaces[interface_id].enable()

    @classmethod
    def flush(cls, interface_id):
        cls.interfaces[interface_id].flush()

    @classmethod
    def disable(cls, interface_id):
        cls.interfaces[interface_id].disable()

    @classmethod
    @peripheral_server.tx_msg
    def tx_buf(cls, interface_id, buf):
        '''
            Creates the message that Peripheral.tx_msga will send on this
            event
        '''
        msg = {'interface_id': interface_id, 'buffer': buf}
        return msg

    @classmethod
    @peripheral_server.reg_rx_handler
    def rx_char_or_buf(cls, msg):
        '''
            Processes reception of this type of message from
            PeripheralServer.rx_msg
        '''
        interface_id = msg['interface_id']
        interface = cls.interfaces[interface_id]
        if isinstance(msg['char'], int):
            print("Adding char to: %s" % interface_id)
            char = msg['char']
            interface.buffer_rx_chars_qmp([char])
        else:
            char_buff = msg['char']
            interface.buffer_rx_chars_qmp(char_buff)
            pass

    @classmethod
    def get_rx_char(cls, interface_id, get_time=False):
        print("Getting RX char from: %s" % str(interface_id))
        interface = cls.interfaces[interface_id]
        return interface.get_rx_char(get_time)
    @classmethod
    def get_rx_buff_size(cls,interface_id):
        print("Getting RX bugg size from: %s" % str(interface_id))
        interface = cls.interfaces[interface_id]
        return interface.get_rx_buff_size()
