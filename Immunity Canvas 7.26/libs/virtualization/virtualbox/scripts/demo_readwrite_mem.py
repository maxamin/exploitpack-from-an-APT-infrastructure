#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  demo_readwrite_mem.py
## Description:
##            :
## Created_On :  Mon Mar 11 2019
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

if '.' not in sys.path:
    sys.path.append('.')

import libs.virtualization.virtualbox.libvboxmanage as vboxmanage
from libs.virtualization.virtualbox.ipc import IVIRTUALBOX_IID_v5, IVIRTUALBOX_IID_v6
from libs.virtualization.virtualbox.ipc import ICONSOLE_IID, IMACHINE_IID_v5
from libs.virtualization.virtualbox.ipc import IINTERNAL_SESSION_CONTROL_IID, IINTERNAL_MACHINE_CONTROL_IID
from libs.virtualization.virtualbox.ipc import ipcPayload
from libs.virtualization.virtualbox.rpc import Session_AssignRemoteMachine_Ret
from libs.virtualization.virtualbox.rpc import IMachineDebugger_loadPlugIn_Args, IMachineDebugger_loadPlugIn_Ret
from libs.virtualization.virtualbox.rpc import IMachineDebugger_detectOS_Ret

XUBUNTU_TARGET  = "b92f861b-3d20-40f1-a80e-94dbf3d2e4f1"
XUBUNTU2_TARGET = "aa76a594-9b45-4f7d-83a0-3cc7afd1857d"
KUBUNTU_TARGET  = "07e33c53-e07c-4a4a-a1cb-e0c09da719e5"
WIN7_TARGET     = "ea805761-d923-467b-8765-984612220923"

def vbox_read_mem(target_iid, addr, addr_len):

    logging.info("-------- VBoxManage debugvm %s ??? (no cmd) ---------" % target_iid)

    ipcc = vboxmanage.IPC_class()
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -1

    ipcc.send_clienthello()
    ipcc.define_target()
    ipcc.resolve_clientname(name='VBoxSVC-5.2.18_Ubuntu')

    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=IVIRTUALBOX_IID_v5)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -2

    ipcc.dconnect_invoke(instance=pIVirtualBox, method_index=5)

    ret, ptr1 = ipcc.dconnect_setup_queryinterface(iid=IVIRTUALBOX_IID_v5, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3


    ret = ipcc.dconnect_release(instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_release() failed [err=0x%x]' % (ret & 0xffffffff))
        return -4

    ret, pTargetMachine = ipcc.dconnect_ivirtualbox_findmachine(pIVirtualBox, machine_iid=target_iid)
    if ret:
        logging.error('dconnect_release() failed [err=0x%x]' % (ret & 0xffffffff))
        return -5


    pTargetMachine &= (~1)
    ret, pISession, dco_seqnum = ipcc.dconnect_imachine_lockmachine(pTargetMachine, instance=pTargetMachine|1)
    if ret:
        logging.error('dconnect_imachine_lockmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -6

    status, ans = ipcc.dconnect_setup_reply(0x7f72cc000f80, 0, dconnect_request_id=(dco_seqnum+1), ret_class=Session_AssignRemoteMachine_Ret)
    if status:
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None

    dco_seq_num = ans.get_dconnect_header().get_header().get_request_index()
    payload = ans.get_payload()
    pIMachine = payload.get_imachine_ptr(with_flag=False)
    pIConsole = payload.get_iconsole_ptr(with_flag=False)

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=IINTERNAL_MACHINE_CONTROL_IID, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -9

    # Packet 32
    status, ans = ipcc.dconnect_invoke(instance=pIMachine, method_index=3)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -10

    # Packet 35
    status, ans = ipcc.dconnect_invoke_reply(0, dco_req_index=dco_seq_num)
    if status:
        logging.error('dconnect_invoke_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -11

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=ICONSOLE_IID, instance=pIConsole)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -12

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=IMACHINE_IID_v5, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -13

    # GetDebugger()
    status, ans = ipcc.dconnect_invoke(instance=pIConsole, method_index=9)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14

    payload = ans.get_payload()
    pIMachineDebugger = (struct.unpack('<Q', str(payload))[0] & (~1))
    logging.debug("pIMachineDebugger = %x" % pIMachineDebugger)

    # readPhysicalMemory()
    arg = ipcPayload(struct.pack('<QL', addr, addr_len))
    status, ans = ipcc.dconnect_invoke(instance=pIMachineDebugger, method_index=56, arg_class=arg)
    time.sleep(0.005)
    print status, ans #80004001

    # writePhysicalMemory()
    arg = ipcPayload(struct.pack('<QL', addr, 0))
    status, ans = ipcc.dconnect_invoke(instance=pIMachineDebugger, method_index=57, arg_class=arg)
    time.sleep(0.005)
    print ans #80004001

    # readVirtualMemory()
    arg = ipcPayload(struct.pack('<LQL', 0, addr, addr_len))
    status, ans = ipcc.dconnect_invoke(instance=pIMachineDebugger, method_index=58, arg_class=arg)
    time.sleep(0.005)
    print ans #80004001

    # writePhysicalMemory()
    arg = ipcPayload(struct.pack('<LQL', 0, addr, 0))
    status, ans = ipcc.dconnect_invoke(instance=pIMachineDebugger, method_index=59, arg_class=arg)
    time.sleep(0.005)
    print ans #80004001

    # pIMachineDebugger
    ret = ipcc.dconnect_release(instance=pIMachineDebugger)
    if ret:
        logging.error('dconnect_release() failed [err=0x%x]' % (ret & 0xffffffff))
        return -15

    ret = ipcc.dconnect_release(instance=pIMachine)
    if ret:
        logging.error('dconnect_release() failed [err=0x%x]' % (ret & 0xffffffff))
        return -16

    ret = ipcc.dconnect_release(instance=pIConsole)
    if ret:
        logging.error('dconnect_release() failed [err=0x%x]' % (ret & 0xffffffff))
        return -17

    return 0

###
# Entry point - testing/debugging only
###

if __name__ == "__main__":

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if len(sys.argv) < 2:
        logging.error('Usage: %s TARGET_IID' % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) > 2:
        if sys.argv[2] in ['verbose','debug']:
            logger.setLevel(logging.DEBUG)

    target_iid = sys.argv[1]
    vbox_read_mem(target_iid, 0xffffffff8f0001a0, 16)
