# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

import os
import sys
import time
from functools import wraps
from multiprocessing import Process
from os import path

from halucinator.peripheral_models.peripheral_server import (decode_zmq_msg,
                                                             encode_zmq_msg)

sys.path.append(os.environ["GHIDRA_HOME"] + "/Ghidra/patch/jeromq-0.5.3-SNAPSHOT.jar")
import org.zeromq as zmq
import zmq.ZMQ as ZMQ

__run_server = True


def rx_from_emulator(emu_rx_port):
    '''
        Receives 0mq messages from emu_rx_port
        args:
            emu_rx_port:  The port number on which to listen for messages from
                          the emulated software
    '''
    global __run_server
    context = zmq.ZContext()
    mq_socket = context.createSocket(ZMQ.ZMQ_SUB)
    mq_socket.connect("tcp://localhost:%s" % emu_rx_port)
    mq_socket.subscribe('')


    print("Setup GPIO Listener")
    while (__run_server):
        msg = mq_socket.recv_string()
        print("Got from emulator:", msg)
        topic, data = decode_zmq_msg(msg)
        print("Pin: ", data['id'], "Value", data['value'])


def update_gpio(emu_tx_port):
    global __run_server
    global __host_socket
    topic = "Peripheral.GPIO.ext_pin_change"
    context = zmq.ZContext()
    to_emu_socket = context.createSocket(ZMQ.ZMQ_PUB)
    to_emu_socket.bind("tcp://*:%s" % emu_tx_port)

    try:
        while (1):
            time.sleep(2)
    except KeyboardInterrupt:
        __run_server = False


def start(interface, emu_rx_port=5556, emu_tx_port=5555):
    global __run_server
    emu_rx_process = Process(target=rx_from_emulator,
                             args=(emu_rx_port,)).start()

    update_gpio(emu_tx_port)
    emu_rx_process.join()


if __name__ == '__main__':
    from argparse import ArgumentParser
    p = ArgumentParser()
    p.add_argument('-r', '--rx_port', default=5556,
                   help='Port number to receive zmq messages for IO on')
    p.add_argument('-t', '--tx_port', default=5555,
                   help='Port number to send IO messages via zmq')
    args = p.parse_args()
    start(args.rx_port, args.tx_port)
