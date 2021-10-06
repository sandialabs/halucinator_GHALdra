# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

import logging
from os import path

from halucinator import hal_log
from halucinator.bp_handlers.bp_handler import BPHandler, bp_handler
from halucinator.peripheral_models.uart import UARTPublisher

log = logging.getLogger(__name__)

hal_log = hal_log.getHalLogger()

class STM32F4UART(BPHandler):

    def __init__(self, impl=UARTPublisher):
        self.model = impl

    @bp_handler(['HAL_UART_Init'])
    def hal_ok(self, qemu, bp_addr):
        qemu.logger.info("Init Called")
        return True, 0

    @bp_handler(['HAL_UART_GetState'])
    def get_state(self, qemu, bp_addr):
        qemu.logger.info("Get State")
        return True, 0x20  # 0x20 READY

    @bp_handler(['HAL_UART_Transmit', 'HAL_UART_Transmit_IT', 'HAL_UART_Transmit_DMA'])
    def handle_tx(self, qemu, bp_addr):
        '''
            Reads the frame out of the emulated device, returns it and an 
            id for the interface(id used if there are multiple ethernet devices)
        '''
        huart = qemu.get_reg("r0")
        hw_addr = int(qemu.read_memory(huart, 4, 1).encode("hex"), 16)
        buf_addr = qemu.get_reg("r1")
        buf_len = qemu.get_reg("r2")
        data = qemu.read_memory(buf_addr, 1, buf_len, raw=False)
        qemu.logger.info("UART ID: %s, UART TX:%s" % (hex(hw_addr), data))
        self.model.write(hw_addr, data)
        qemu.logger.info("Finished UART TX!")
        return True, 0

    # HAL_StatusTypeDef HAL_UART_Receive_IT(UART_HandleTypeDef *huart, uint8_t *pData, uint16_t Size);
    # HAL_StatusTypeDef HAL_UART_Transmit_DMA(UART_HandleTypeDef *huart, uint8_t *pData, uint16_t Size);
    # HAL_StatusTypeDef HAL_UART_Receive_DMA(UART_HandleTypeDef *huart, uint8_t *pData, uint16_t Size);
    @bp_handler(['HAL_UART_Receive', 'HAL_UART_Receive_IT', 'HAL_UART_Receive_DMA'])
    def handle_rx(self, qemu, bp_handler):
        huart = qemu.get_reg("r0")
        hw_addr = qemu.read_memory(huart, 4, 1)
        pData = qemu.get_reg("r1")
        size = qemu.get_reg("r2")
        qemu.logger.info("Waiting for data: %i" % size)
        data = self.model.read(hw_addr, size, block=True)
        qemu.logger.info("UART RX: %s" % data)
        qemu.write_memory(pData, 1, data, size, raw=False)
        return True, 0
