#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_svcctl.py
## Description:
##            :
## Created_On :  Tue Dec 30 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

# The API is not 100% written but is currently working quite well.

import sys
if '.' not in sys.path:
    sys.path.append('.')

import libs.newsmb.svcctl as svcctl

HOST1 = '10.0.0.1'
USER1 = u'Administrator'
PWD1 = 'foobar123!'
DOMAIN1 = 'immu5.lab'

HOST2 = '192.168.22.1'
USER2 = u'Administrator'
PWD2 = 'barbar123!'
DOMAIN2 = 'IMMU3.COM'

HOST3 = '192.168.33.1'
USER3 = u'Administrator'
PWD3 = 'barbar123!'
DOMAIN3 = 'IMMU4.COM'

TEST_VECTORS = [
            {'host':HOST1, 'user':USER1, 'passwd':PWD1, 'domain':DOMAIN1},
            #{'host':HOST2, 'user':USER2, 'passwd':PWD2, 'domain':DOMAIN2}
            #{'host':HOST3, 'user':USER3, 'passwd':PWD3, 'domain':DOMAIN3}
          ]

def Test1(svc):
    try:
        svc.open_manager()
        handle = svc.open_service('Cdfs')
        if handle:
            svc.close_service(handle)
        svc.close_manager()
    except Exception as e:
        print e

# We do not handle correctly fault answers
def Test2(svc):
    try:
        svc.close_service(handle='\x44'*20)
    except Exception as e:
        print e

def Test3(svc):
    try:
        svc.open_manager()
        services = svc.get_services(service_type=svcctl.SVCCTL_SERVICE_FILE_SYSTEM_DRIVER)
        svc.close_manager()

        print "*** FS Drivers ***"
        for srv in services:
            print "%s (%s) Type=%s" % (srv['ServiceName'], srv['DisplayName'], svcctl.SVCCTL_ServiceType2Str(srv['Type']))
    except Exception as e:
        print e

def Test3_bis(svc):
    try:
        svc.open_manager()
        services = svc.get_services()
        svc.close_manager()

        print "*** All Services ***"
        for srv in services:
            print "%s (%s) Type=%s State=%s" % ( srv['ServiceName'],
                                                 srv['DisplayName'],
                                                 svcctl.SVCCTL_ServiceType2Str(srv['Type']),
                                                 svcctl.SVCCTL_ServiceState2Str(srv['CurrentState']))
    except Exception as e:
        print e

def Test4(svc):
    try:
        handle = svc.open_manager()
        service_handle = svc.create_service(handle, 'IMMUSVC', '%SystemRoot%\\PSEXESVC.EXE')
        svc.delete_service(service_name='IMMUSVC')
        svc.close_manager()
    except Exception as e:
        print e

def Test5(svc, srv_name='Cdfs'):
    try:
        handle = svc.open_manager()
        handle = svc.open_service(srv_name)
        x = svc.query_service(handle)
        print "%s: Type = %s, State = %s" % (srv_name,
                                             svcctl.SVCCTL_ServiceType2Str(x['Type']),
                                             svcctl.SVCCTL_ServiceState2Str(x['CurrentState']))
        svc.close_service(handle)
        svc.close_manager()
    except Exception as e:
        print e

def Test6(svc, srv_name='Cdfs'):
    try:
        handle = svc.open_manager()
        handle = svc.open_service(srv_name)
        svc.start_service(handle)
        svc.close_service(handle)
        svc.close_manager()
    except Exception as e:
        print e

def Test7(svc, srv_name='Cdfs'):
    try:
        handle = svc.open_manager()
        handle = svc.open_service(srv_name)
        svc.stop_service(handle)
        svc.close_service(handle)
        svc.close_manager()
    except Exception as e:
        print e


if __name__ == "__main__":

    for vec in TEST_VECTORS:

        print "*********************** %s ***********************" % vec['domain']
        svc = svcctl.SVCCTLClient(vec['host'])
        svc.set_credentials(vec['user'], vec['passwd'], vec['domain'])
        svc.bind()
        Test1(svc)
        Test2(svc) # Must generate an exception!
        Test3(svc)
        Test3_bis(svc)
        Test4(svc)
        Test5(svc)
        Test6(svc, srv_name='IPSec') # start
        Test7(svc, srv_name='WebClient') # stop
