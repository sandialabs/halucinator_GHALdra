# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

import logging
import os
import sys
from functools import wraps

import yaml

sys.path.append(os.environ["GHIDRA_HOME"] + "/Ghidra/patch/jeromq-0.5.3-SNAPSHOT.jar")
import org.zeromq as zmq
import zmq.ZMQ as ZMQ

log = logging.getLogger(__name__)


__rx_handlers__ = {}
__ctx__ = zmq.ZContext()
__stop_server = False
__rx_socket__ = None
__tx_socket__ = None

__process = None
__qemu = None

output_directory = None
base_dir = None


def peripheral_model(cls):
    '''
        Decorator which registers classes as peripheral models
    '''
    methods = [getattr(cls, x) for x in dir(
        cls) if hasattr(getattr(cls, x), 'is_rx_handler')]

    for m in methods:
        key = 'Peripheral.%s.%s' % (cls.__name__, m.__name__)
        log.info("Adding method: %s" % key)
        __rx_handlers__[key] = (cls, m)
        if __rx_socket__ != None:
            log.info("Subscribing to: %s" % key)
            __rx_socket__.subscribe(bytes(key))

    return cls


def tx_msg(funct):
    '''
        This is a decorator that sends output of the wrapped function as
        a tagged msg.  The tag is the class_name.func_name
    '''
    @wraps(funct)
    def tx_msg_decorator(model_cls, *args):
        '''
            Sends a message using the class.funct as topic
            data is a yaml encoded of the calling model_cls.funct
        '''
        global __tx_socket__
        data = funct(model_cls, *args)
        topic = "Peripheral.%s.%s" % (model_cls.__name__, funct.__name__)
        msg = encode_zmq_msg(topic, data)
        log.info("Sending: %s" % msg)
        __tx_socket__.send(msg)
    return tx_msg_decorator


def reg_rx_handler(funct):
    '''
        This is a decorator that registers a function to handle a specific
        type of message
    '''
    funct.is_rx_handler = True
    return funct


def encode_zmq_msg(topic, msg):
    data_yaml = yaml.safe_dump(msg)
    return "%s %s" % (topic, data_yaml)


def decode_zmq_msg(msg):
    topic, encoded_msg = str(msg).split(' ', 1)
    decoded_msg = yaml.safe_load(encoded_msg)
    return (topic, decoded_msg)


def start(rx_port=5555, tx_port=5556, qemu=None):
    global __ctx__
    global __rx_socket__
    global __tx_socket__
    global __rx_context__
    global __tx_context__
    global __rx_handlers__
    global __process
    global __qemu
    global output_directory

    output_directory = qemu.output_directory # changed from qemu.avatar.output_directory to this
    __qemu = qemu
    log.info('Starting Peripheral Server, In port %i, outport %i' %
             (rx_port, tx_port))
    # Setup subscriber
    __rx_socket__ = __ctx__.createSocket(ZMQ.ZMQ_SUB)

    __rx_socket__.connect("tcp://localhost:%i" % rx_port)

    for topic in list(__rx_handlers__.keys()):
        log.info("Subscribing to: %s" % topic)
        __rx_socket__.subscribe(topic)

    # Setup Publisher
    __tx_socket__ = __ctx__.createSocket(ZMQ.ZMQ_PUB)
    __tx_socket__.bind("tcp://*:%i" % tx_port)


def trigger_interrupt(num):
    global __qemu
    log.info("Sending Interrupt: %s" % num)
    __qemu.trigger_interrupt(num)


def irq_set_qmp(irq_num=1):
    global __qemu
    __qemu.irq_set_qmp(irq_num)


def irq_clear_qmp(irq_num=1):
    global __qemu
    __qemu.irq_clear_qmp(irq_num)


def irq_set_bp(irq_num=1):
    global __qemu
    __qemu.irq_set_bp(irq_num)


def irq_clear_bp(irq_num):
    global __qemu
    __qemu.irq_clear_bp(irq_num)


def run_server():
    global __rx_handlers__
    global __rx_socket__
    global __stop_server
    global __qemu
    global __ctx__

    __stop_server = False
    __rx_socket__.subscribe(b'')

    sockets = dict()
    poller = __ctx__.createPoller(100)
    rx_idx = poller.register(__rx_socket__, poller.POLLIN)
    sockets[__rx_socket__] = rx_idx

    while(not __stop_server):
        socks = poller.poll(500)
        if poller.pollin(sockets[__rx_socket__]):
            string = __rx_socket__.recvStr()
            topic, msg = decode_zmq_msg(string)
            log.info("Got message: Topic %s  Msg: %s" % (str(topic), str(msg)))
            print("Got message: Topic %s  Msg: %s" % (str(topic), str(msg)))
            if topic.startswith("Peripheral"):
                if topic in __rx_handlers__:
                    method_cls, method = __rx_handlers__[topic]
                    method(msg)
                else:
                    log.error(
                        "Unhandled peripheral message type received: %s" % topic)

            elif topic.startswith("Interrupt.Trigger"):
                log.info("Triggering Interrupt %s" % msg['num'])
                irq_set_qmp(msg['num'])
            elif topic.startswith("Interrupt.Base"):
                log.info("Setting Vector Base Addr %s" % msg['num'])
                __qemu.set_vector_table_base(msg['base'])
            else:
                log.error("Unhandled topic received: %s" % topic)
    log.info("Peripheral Server Shutdown Normally")


def stop():
    global __process
    global __stop_server
    __stop_server = True
    if __rx_socket__:
        __rx_socket__.close()
    if __tx_socket__:
        __tx_socket__.close()
