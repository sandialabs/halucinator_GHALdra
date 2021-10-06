# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

import logging

from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler
from halucinator.bp_handlers.intercepts import rx_map, tx_map
from halucinator.peripheral_models.timer_model import TimerModel

log = logging.getLogger(__name__)

class STM32_TIM(BPHandler):

    def __init__(self, model=TimerModel):
        self.model = model
        self.org_lr = None
        self.current_channel = 0
        self.addr2isr_lut = {
            # '0x40000200': 0x32
            0x40000400: 45
        }
        self.irq_rates = {}
        self.name = 'STM32_TIM'

    @bp_handler(['HAL_TIM_Base_Init'])
    def tim_init(self, qemu, bp_addr):
        tim_obj = qemu.get_reg("r0")
        tim_base = qemu.read_memory(tim_obj, 4, 1)

        log.info("STM32_TIM init, base: %#08x" % (tim_base))
        return False, None

    @bp_handler(['HAL_TIM_Base_DeInit'])
    def deinit(self, qemu, bp_addr):
        tim_obj = qemu.get_reg("r0")
        tim_base = qemu.read_memory(tim_obj, 4, 1)

        log.info("STM32_TIM deinit, base: %#08x" % (hex(tim_base)))
        return True, 0

    @bp_handler(['HAL_TIM_ConfigClockSource'])
    def config(self, qemu, bp_addr):
        tim_obj = qemu.get_reg("r0")
        tim_base = qemu.read_memory(tim_obj, 4, 1)

        log.info("STM32_TIM config, base: %#08x" % (hex(tim_base)))
        return True, 0

    @bp_handler(['HAL_TIMEx_MasterConfigSynchronization'])
    def sync(self, qemu, bp_addr):
        tim_obj = qemu.get_reg("r0")
        tim_base = qemu.read_memory(tim_obj, 4, 1)
        log.info("STM32_TIM sync, base: %#08x" % (hex(tim_base)))
        return True, 0

    @bp_handler(['HAL_TIM_Base_Start_IT'])
    def start(self, qemu, bp_addr):
        tim_obj = qemu.get_reg("r0")
        tim_base = qemu.read_memory(tim_obj, 4, 1)

        log.info("STM32_TIM start, base: %#08x" % tim_base)
        self.model.start_timer(hex(tim_base), self.addr2isr_lut[tim_base], 2)
        return True, None  # Just let it run

    @bp_handler(['HAL_TIM_IRQHandler'])
    def isr_handler(self, qemu, bp_addr):
        tim_obj = qemu.get_reg("r0")
        tim_base = qemu.read_memory(tim_obj, 4, 1)
        log.info("TICK: Timer %#08x" % tim_base)
        return False, None

    @bp_handler(['HAL_TIM_Base_Stop_IT'])
    def stop(self, qemu, bp_addr):
        tim_obj = qemu.get_reg("r0")
        tim_base = qemu.read_memory(tim_obj, 4, 1)
        self.model.stop_timer(hex(tim_base))
        return True, 0

    @bp_handler(['HAL_Delay'])
    def sleep(self, qemu, bp_handler):
        amt = qemu.get_reg("r0") / 1000.0
        log.debug("sleeping for %f" % amt)
        return True, 0

    @bp_handler(['HAL_SYSTICK_Config'])
    def systick_config(self, qemu, bp_addr):
        rate = 5
        systick_irq = 15
        log.info("Setting SysTick rate to %#08x" % rate)
        self.model.start_timer('SysTick', systick_irq, rate)
        return True, 0
