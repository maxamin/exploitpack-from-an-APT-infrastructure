#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  demo_spy1.py
## Description:
##            :
## Created_On :  Fri Feb 22 2019
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import os
import re
import struct
import socket
import logging
import time
import ptrace.debugger
import signal
import subprocess

if '.' not in sys.path:
    sys.path.append('.')

import libs.virtualization.virtualbox.libvboxmanage as vboxmanage

# Globals
stop_script=0
syscall_names = { 44: 'sendto', 45: 'recvfrom' }


def sigint_handler(signum, frame):
    '''
    Just allows to interrupt spying...
    '''
    global stop_script
    stop_script=1


def main():

    signal.signal(signal.SIGINT, sigint_handler)

    if len(sys.argv) < 2:
        logging.error('Usage: %s TARGET_PID' % sys.argv[0])
        sys.exit(1)

    try:
        pid = int(sys.argv[1])
    except:
        logging.error('Wrong PID: %s' % sys.argv[1])
        sys.exit(1)

    logging.debug("Attach the running process %s" % pid)
    debugger = ptrace.debugger.PtraceDebugger()
    process = debugger.addProcess(pid, False)

    while not stop_script:
        try:
            process.syscall()
            time.sleep(0.001)

            regs = process.getregs()
            syscall_num = regs.orig_rax

            if syscall_num == 45 or syscall_num == 44:
                fd = regs.rdi
                buff = regs.rsi
                bufflen = regs.rdx

                logging.debug("%s(%d, 0x%x, %d)" % (syscall_names[syscall_num], fd, buff, bufflen))

                if syscall_num == 44:
                    x = process.readBytes(buff, bufflen)
                    logging.debug('SEND: %s' % x.encode('hex'))
                    packet = vboxmanage.ipc_unserialize(x)
                    logging.info(packet)

            process.syscall()
            time.sleep(0.001)

            regs = process.getregs()
            ret = regs.rax

            if syscall_num == 45 or syscall_num == 44:

                logging.debug("    = %d" % (ret))

                if syscall_num == 45:
                    x = process.readBytes(buff, ret)
                    logging.debug('RECV: %s' % x.encode('hex'))
                    packet = vboxmanage.ipc_unserialize(x)
                    logging.info(packet)


        except Exception as e:
            pass


    process.detach()
    debugger.quit()

 
if __name__ == "__main__":

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    main()
