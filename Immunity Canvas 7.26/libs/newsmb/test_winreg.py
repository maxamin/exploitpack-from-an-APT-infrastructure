#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_winreg.py
## Description:
##            :
## Created_On :  Tue Oct 20 CEST 2015
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

# The API is not 100% written but is currently working quite well.

import sys
import logging

if '.' not in sys.path:
    sys.path.append('.')

import libs.newsmb.winreg as wreg

HOST1 = '192.168.0.1'
USER1 = u'Administrator'
PWD1 = 'barbar123!'
DOMAIN1 = 'IMMU2.COM'

HOST2 = '192.168.22.1'
USER2 = u'Administrator'
PWD2 = 'barbar123!'
DOMAIN2 = 'IMMU3.COM'

HOST3 = '192.168.33.1'
USER3 = u'Administrator'
PWD3 = 'barbar123!'
DOMAIN3 = 'IMMU4.COM'

HOST4 = HOST1
USER4 = u'jojo1'
PWD4 = 'foobar123!'
DOMAIN4 = DOMAIN1

# No credentials test.
HOST5 = HOST1
USER5 = u''
PWD5 = u''
DOMAIN5 = DOMAIN1

HOST6 = '192.168.55.1'
USER6 = u'Administrator'
PWD6 = 'barbar123!'
DOMAIN6 = 'IMMU5.COM'

HOST7 = '192.168.0.12'
USER7 = u'Administrator'
PWD7 = 'barbar123!'
DOMAIN7 = 'IMMU2.COM'

HOST8 = '10.0.0.1'
DOMAIN8 = 'immu5.lab'
USER8 = u'jojo1'
PWD8 = 'foobar1234!'

TEST_VECTORS = [
            #{'host':HOST1, 'user':USER1, 'passwd':PWD1, 'domain':DOMAIN1},
            #{'host':HOST2, 'user':USER2, 'passwd':PWD2, 'domain':DOMAIN2},
            #{'host':HOST3, 'user':USER3, 'passwd':PWD3, 'domain':DOMAIN3},
            #{'host':HOST4, 'user':USER4, 'passwd':PWD4, 'domain':DOMAIN4},
            #{'host':HOST5, 'user':USER5, 'passwd':PWD5, 'domain':DOMAIN5},
            #{'host':HOST6, 'user':USER6, 'passwd':PWD6, 'domain':DOMAIN6},
            #{'host':HOST7, 'user':USER7, 'passwd':PWD7, 'domain':DOMAIN7},
            {'host':HOST8, 'user':USER8, 'passwd':PWD8, 'domain':DOMAIN8},
          ]

def test1_get_version(winreg):

    try:
        hkey = winreg.open_local_machine()
        version = winreg.get_version(handle=hkey)
        print "OS FINGERPRINT: %s" % version
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST1", e
        return False

def test2_dump_local_machine(winreg, param='Software'):

    try:
        hkey = winreg.open_local_machine()

        def dump(current_key, keyname, level):
            if level > 1:
                return
            key = winreg.open_subkey(current_key, keyname=keyname)
            res = winreg.query_information(handle=key)

            for i in xrange(res['nbr_keys']):
                print "  "*level + "[DIR] %s" % winreg.enum_key(key, i)['name']
                dump(current_key, "%s\%s" % (keyname, winreg.enum_key(key, i)['name']), level+1)

            for i in xrange(res['nbr_values']):
                try:
                    res2 = winreg.enum_value(key,
                                         i,
                                         valnamelen=res['max_value_namelen'],
                                         valbufsize=res['max_value_len'])
                    print "  "*level + "      %s (%s)" % (res2['name'], res2['type'])
                except Exception as e:
                    if e.status == wreg.ERROR_NO_MORE_ITEMS:
                        break
            winreg.close_key(key)

        print "DUMPING...."
        dump(hkey, param,0)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST2", e
        return False

def test3_open_current_user_and_enum(winreg, param='Console'):

    try:
        access  = wreg.READ_CONTROL
        access |= wreg.KEY_QUERY_VALUE
        access |= wreg.KEY_NOTIFY
        access |= wreg.KEY_ENUMERATE_SUB_KEYS
        hkey = winreg.open_current_user(access=access)
        key = winreg.open_subkey(hkey, keyname=param, access=access)
        res = winreg.query_information(handle=key)

        for i in xrange(res['nbr_keys']):
            print winreg.enum_key(key, i)['name']

        for i in xrange(res['nbr_values']):
            try:
                print winreg.enum_value(key, i, valnamelen=res['max_value_namelen'], valbufsize=res['max_value_len'])
            except Exception as e:
                if e.status == wreg.ERROR_NO_MORE_ITEMS:
                    break

        winreg.close_key(key)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST3", e
        return False

def test4_open_classes_root_and_enum(winreg, param='xslfile'):

    try:
        hkey = winreg.open_classes_root()
        key = winreg.open_subkey(hkey, keyname=param)
        res = winreg.query_information(handle=key)
        for i in xrange(res['nbr_keys']):
            print "[DIR] " + winreg.enum_key(key, i)['name']
        for i in xrange(res['nbr_values']):
            try:
                    res2 = winreg.enum_value(key,
                                         i,
                                         valnamelen=res['max_value_namelen'],
                                         valbufsize=res['max_value_len'])
                    print "      %s (%s)" % (res2['name'], res2['type'])
            except Exception as e:
                if e.status == wreg.ERROR_NO_MORE_ITEMS:
                    break
        winreg.close_key(key)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST4", e
        return False

def test5_open_users_and_enum(winreg, param='.DEFAULT'):

    try:
        hkey = winreg.open_users()
        key = winreg.open_subkey(hkey, keyname=param)
        res = winreg.query_information(handle=key)
        for i in xrange(res['nbr_keys']):
            print "[DIR] " + winreg.enum_key(key, i)['name']
        for i in xrange(res['nbr_values']):
            try:
                    res2 = winreg.enum_value(key,
                                         i,
                                         valnamelen=res['max_value_namelen'],
                                         valbufsize=res['max_value_len'])
                    print "      %s (%s)" % (res2['name'], res2['type'])
            except Exception as e:
                if e.status == wreg.ERROR_NO_MORE_ITEMS:
                    break
        winreg.close_key(key)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST5", e
        return False

def test6_create_and_delete_key(winreg, param='TEST_123456'):

    try:
        access  = wreg.READ_CONTROL
        access |= wreg.KEY_QUERY_VALUE
        access |= wreg.KEY_NOTIFY
        access |= wreg.KEY_ENUMERATE_SUB_KEYS
        access |= wreg.KEY_SET_VALUE
        hkey = winreg.open_current_user(access=access)
        key = winreg.create_key(hkey, keyname=param)
        winreg.delete_key(hkey, keyname=param)
        winreg.close_key(key)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST6", e
        return False

def test7_save_key_as_file(winreg, param1='.DEFAULT', param2='TEST_123456_3.reg'):

    try:
        hkey = winreg.open_users()
        key = winreg.open_subkey(hkey, keyname=param1)
        winreg.save_key_as_file(key, filename=param2)
        winreg.close_key(key)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST7", e
        return False

def test8_create_and_delete_value(winreg, param='TEST_123456'):

    try:
        access  = wreg.READ_CONTROL
        access |= wreg.KEY_QUERY_VALUE
        access |= wreg.KEY_NOTIFY
        access |= wreg.KEY_ENUMERATE_SUB_KEYS
        access |= wreg.KEY_SET_VALUE
        hkey = winreg.open_current_user(access=access)
        key = winreg.create_key(hkey, keyname=param)
        winreg.set_value(key, v_name='cuicui', v_type=wreg.REG_DWORD, v_value='ab\x01\x02')
        winreg.delete_value(key, v_name='cuicui')
        winreg.delete_key(hkey, keyname=param)
        winreg.close_key(key)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST8", e
        return False

def test9_open_performance_data(winreg, param='\\'):

    try:
        access  = wreg.READ_CONTROL
        access |= wreg.KEY_QUERY_VALUE
        access |= wreg.KEY_NOTIFY
        access |= wreg.KEY_ENUMERATE_SUB_KEYS
        hkey = winreg.open_performance_data(access=access)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST9", e
        return False

def test10_open_current_config(winreg, param='\\'):

    try:
        access  = wreg.READ_CONTROL
        access |= wreg.KEY_QUERY_VALUE
        access |= wreg.KEY_NOTIFY
        access |= wreg.KEY_ENUMERATE_SUB_KEYS
        hkey = winreg.open_current_config(access=access)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST10", e
        return False

def test11_get_key_security(winreg, param='.DEFAULT'):

    try:
        access  = wreg.READ_CONTROL
        access |= wreg.KEY_QUERY_VALUE
        access |= wreg.KEY_NOTIFY
        access |= wreg.KEY_ENUMERATE_SUB_KEYS
        access |= wreg.ACCESS_SYSTEM_SECURITY
        hkey = winreg.open_users(access=access)
        key = winreg.open_subkey(hkey, keyname=param, access=access)
        res = winreg.get_key_security(handle=key)
        if res['Owner']:
            print 'Owner: %s [%s]' % (res['Owner'], wreg.get_sid_name(res['Owner']))
        if res['Group']:
            print 'Group: %s [%s]' % (res['Group'], wreg.get_sid_name(res['Group']))
        if res['Dacl']:
            print 'Dacl:'
            for dacl in res['Dacl']:
                res2 = dacl.get_results()
                print "\tMask %x : Sid %s [%s]" % (res2['mask'], res2['sid'], wreg.get_sid_name(res2['sid']))
        if res['Sacl']:
            print 'Sacl:'
            for sacl in res['Sacl']:
                res2 = sacl.get_results()
                print "\tMask %x : Sid %s [%s]" % (res2['mask'], res2['sid'], wreg.get_sid_name(res2['sid']))
        winreg.close_key(key)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST11", e
        return False

def test12_dir_and_get_key_security(winreg, param='Software'):

    access  = wreg.READ_CONTROL
    access |= wreg.KEY_QUERY_VALUE
    access |= wreg.KEY_NOTIFY
    access |= wreg.KEY_ENUMERATE_SUB_KEYS
    access |= wreg.ACCESS_SYSTEM_SECURITY

    try:
        hkey = winreg.open_local_machine(access=access)

        def dump(current_key, keyname, level):
            if level > 1:
                return
            key = winreg.open_subkey(current_key, keyname=keyname, access=access)
            res = winreg.get_key_security(handle=key)
            print res
            res = winreg.query_information(handle=key)

            for i in xrange(res['nbr_keys']):
                dump(current_key, "%s\%s" % (keyname, winreg.enum_key(key, i)['name']), level+1)

            winreg.close_key(key)

        print "DUMPING...."
        dump(hkey, param,0)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST12", e
        return False

def test13_open_performance_text(winreg, param='\\'):

    try:
        access  = wreg.READ_CONTROL
        access |= wreg.KEY_QUERY_VALUE
        access |= wreg.KEY_NOTIFY
        access |= wreg.KEY_ENUMERATE_SUB_KEYS
        hkey = winreg.open_performance_text(access=access)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST13", e
        return False

def test14_open_performance_nls_text(winreg, param='\\'):

    try:
        access  = wreg.READ_CONTROL
        access |= wreg.KEY_QUERY_VALUE
        access |= wreg.KEY_NOTIFY
        access |= wreg.KEY_ENUMERATE_SUB_KEYS
        hkey = winreg.open_performance_nls_text(access=access)
        winreg.close_key(hkey)
        return True
    except Exception as e:
        print "TEST14", e
        return False

if __name__ == "__main__":

    if len(sys.argv) > 1 and sys.argv[1] == '-v':
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

    for vec in TEST_VECTORS:

        print "*********************** %s ***********************" % vec['domain']
        winreg = wreg.WINREGClient(vec['host'])
        winreg.set_credentials(vec['user'], vec['passwd'], vec['domain'])
        if not winreg.bind():
            print "[-] bind() failed."
            sys.exit(1)

        print "========> TEST1"
        test1_get_version(winreg)
        print "========> TEST2"
        test2_dump_local_machine(winreg)
        print "========> TEST3"
        test3_open_current_user_and_enum(winreg)
        print "========> TEST4"
        test4_open_classes_root_and_enum(winreg)
        print "========> TEST5"
        test5_open_users_and_enum(winreg)
        print "========> TEST6"
        test6_create_and_delete_key(winreg)
        print "========> TEST7"
        test7_save_key_as_file(winreg)
        print "========> TEST8"
        test8_create_and_delete_value(winreg)
        #print "========> TEST9"
        #test9_open_performance_data(winreg)
        #print "========> TEST10"
        #test10_open_current_config(winreg)
        #print "========> TEST11"
        #test11_get_key_security(winreg)
        #print "========> TEST12"
        #test12_dir_and_get_key_security(winreg)
        print "========> TEST13"
        test13_open_performance_text(winreg)
        print "========> TEST14"
        test14_open_performance_nls_text(winreg)
