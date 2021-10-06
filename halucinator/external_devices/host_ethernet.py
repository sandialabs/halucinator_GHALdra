# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
# certain rights in this software.

import binascii
import os
import socket
import sys
import time
from multiprocessing import Process  # TODO: Switch to Threads
from os import path

import scapy.all as scapy
from halucinator.peripheral_models.peripheral_server import (decode_zmq_msg,
                                                             encode_zmq_msg)

sys.path.append(os.environ["GHIDRA_HOME"] + "/Ghidra/patch/jeromq-0.5.3-SNAPSHOT.jar")
import org.zeromq as zmq
import zmq.ZMQ as ZMQ

__run_server = True
__host_socket = None


def rx_from_emulator(emu_rx_port, interface):
    '''
        Receives 0mq messages from emu_rx_port
        args:
            emu_rx_port:  The port number on which to listen for messages from
                          the emulated software
    '''
    global __run_server
    topic = "Peripheral.EthernetModel.tx_frame"
    context = zmq.ZContext()
    mq_socket = context.createSocket(ZMQ.ZMQ_SUB)
    mq_socket.connect("tcp://localhost:%s" % emu_rx_port)
    mq_socket.subscribe(topic)

    while (__run_server):
        msg = mq_socket.recvStr()
        topic, data = decode_zmq_msg(msg)
        frame = data['frame']
        p = scapy.Raw(frame)
        scapy.sendp(p, iface=interface)
        print("Sending Frame (%i) on eth: %s" %
              (len(frame), binascii.hexlify(frame)))


def rx_from_host(emu_tx_port, msg_id):
    global __run_server
    global __host_socket
    topic = "Peripheral.EthernetModel.rx_frame"
    context = zmq.ZContext()
    to_emu_socket = context.createSocket(ZMQ.ZMQ_PUB)
    to_emu_socket.bind("tcp://*:%s" % emu_tx_port)

    while (__run_server):
        pass
        # Listen for frame from host
        frame = __host_socket.recv(2048)
        data = {'interface_id': msg_id, 'frame': frame}
        msg = encode_zmq_msg(topic, data)
        to_emu_socket.send_string(msg)
        print("Sent message to emulator ", binascii.hexlify(frame))


def start(interface, emu_rx_port=5556, emu_tx_port=5555, msg_id=1073905664):
    global __run_server
    global __host_socket
    # Open socket to send raw frames on ethernet adapter
    os.system('ip link set %s promisc on' % interface)  # Set to permisucous

    ETH_P_ALL = 3
    __host_socket = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    __host_socket.bind((interface, 0))

    print("Starting Servers")
    emu_rx_process = Process(target=rx_from_emulator,
                             args=(emu_rx_port, interface)).start()
    emu_tx_process = Process(
        target=rx_from_host, args=(emu_tx_port, msg_id)).start()
    try:
        while (1):
            time.sleep(0.1)
    except KeyboardInterrupt:
        __run_server = False
    emu_rx_process.join()
    emu_tx_process.join()


if __name__ == '__main__':
    from argparse import ArgumentParser
    p = ArgumentParser()
    p.add_argument('-r', '--rx_port', default=5556,
                   help='Port number to receive zmq messages for IO on')
    p.add_argument('-t', '--tx_port', default=5555,
                   help='Port number to send IO messages via zmq')
    p.add_argument('-i', '--interface', required=True,
                   help='Ethernet Interace to listen to')
    p.add_argument('--id', default=1073905664,
                   help='Ethernet Interace to listen to')
    args = p.parse_args()
    start(args.interface, args.rx_port, args.tx_port, args.id)
