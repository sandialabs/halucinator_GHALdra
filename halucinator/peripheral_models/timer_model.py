# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

from threading import Event, Thread

from halucinator.peripheral_models import peripheral_server
from halucinator.peripheral_models.interrupts import \
    Interrupts as InterruptsModel


@peripheral_server.peripheral_model
class TimerModel(object):

    active_timers = {}
    @classmethod
    def start_timer(cls, name, isr_num, rate):
        if name not in cls.active_timers:
            stop_event = Event()
            t = TimerIRQ(stop_event, name, isr_num, rate)
            cls.active_timers[name] = (stop_event, t)
            t.start()

    @classmethod
    def stop_timer(cls, name):
        if name in cls.active_timers:
            (stop_event, _) = cls.active_timers[name]
            stop_event.set()

    @classmethod
    def clear_timer(cls, irq_name):
        InterruptsModel.clear_active_qmp(irq_name)

    @classmethod
    def shutdown(cls):
        for _, (stop_event, _) in list(cls.active_timers.items()):
            stop_event.set()


class TimerIRQ(Thread):
    def __init__(self, event, irq_name, irq_num, rate):
        Thread.__init__(self)
        self.stopped = event
        self.name = irq_name
        self.irq_num = irq_num
        self.rate = rate

    def run(self):
        while not self.stopped.wait(self.rate):
            InterruptsModel.set_active_qmp(self.irq_num)
