#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  test_libwinreg.py
## Description:
##            :
## Created_On :  Wed Jan 2 2019
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import os
import sys
import logging

if '.' not in sys.path:
    sys.path.append('.')

import libs.libwinreg.libwinreg as libwinreg

# Globals
WINREG_LIBDIR = './libs/libwinreg'


def DumpRegistry(fname, max_bins=20):

    try:
        f = open(fname)
        data = f.read()
        f.close()
    except Exception as e:
        logging.error("open() failed: %s" % str(e))
        return

    base_block = libwinreg.BaseBlock(data=data)
    bins_length = base_block.get_hivebins_datasize()
    len_base_block = base_block.calcsize()

    remaining_bytes = bins_length
    offset = len_base_block

    i = 0
    hbs = []
    while 1:
        hb = libwinreg.HiveBin(data=data[offset:])
        hbs.append(hb)

        offset += hb.get_size()
        remaining_bytes -= hb.get_size()
        i += 1

        if remaining_bytes == 0:
            break

        if i >= max_bins:
            break

    return hbs

def test1():

    test_dir = os.path.join(WINREG_LIBDIR, 'tests')
    test_files = os.listdir(test_dir)

    for i in xrange(len(test_files)):
        f = test_files[i]
        logging.info("Test #1.%d - DumpRegistry(%s)" % (i+1,f))
        try:
            hbs = DumpRegistry(os.path.join(WINREG_LIBDIR, 'tests', f), max_bins=20)
            for hb in hbs:
                logging.debug(str(hb))
        except Exception as e:
            logging.error('Parsing failed with error: %s' % str(e))
            sys.exit(1)


def test2():

    test_dir = os.path.join(WINREG_LIBDIR, 'tests')
    test_files = [ f for f in os.listdir(test_dir) if 'sam_' in f ]

    for i in xrange(len(test_files)):

        fname = test_files[i]
        logging.info("Test #2.%d - SAM(%s)" % (i+1,fname))
        wrp = libwinreg.WinRegParser(os.path.join(test_dir, fname))

        rcell = wrp.get_rootcell()
        logging.debug('Root cell name: %s' % rcell.get_data().get_keyname())
        rcell2 = wrp.get_keynode_by_name('\\')
        rcell2_name = rcell2.get_data().get_keyname()
        if rcell2_name != 'ROOT' and rcell2_name != 'SAM' and rcell2_name.find('CreateHive') == -1:
            logging.error("Subtest #1 failed! Found: %s" % rcell2_name)

        cell_sam = wrp.get_keynode_by_name('\\SAM')
        cell_sam_name = cell_sam.get_data().get_keyname()
        if cell_sam_name != 'SAM':
            logging.error("Subtest #2 failed!")

        cell_sam = wrp.get_keynode_by_name('SAM')
        cell_sam_name2 = cell_sam.get_data().get_keyname()
        if cell_sam_name2 != 'SAM':
            logging.error("Subtest #3 failed!")

        try:
            skeys = wrp.get_subkeys(cell_sam.get_data())
            for k in skeys:
                logging.debug(k.get_data().get_keyname())
        except Exception as e:
            logging.error("Subtest #4 failed with a parsing error: %s" % str(e))
            sys.exit(1)

        try:
            cell_sam_domains_account = wrp.get_keynode_by_name('SAM\\Domains\\Account')
            logging.debug(cell_sam_domains_account.get_data().get_keyname())
            skeys = wrp.get_subkeys(cell_sam_domains_account.get_data())
            for k in skeys:
                logging.debug(k.get_data().get_keyname())
        except Exception as e:
            logging.error("Subtest #5 failed with a parsing error: %s" % str(e))
            sys.exit(1)

        try:
            cell_sam_domains_account = wrp.get_keynode_by_name('SAM\\Domains\\Account\\Users\\000001F4')
            cell_val = wrp.get_keyvalue_by_name(cell_sam_domains_account.get_data(), 'V')
            data = wrp.get_rawdata_from_keyvalue(cell_val.get_data())
            logging.debug("Data [len=%d]: %s" % (len(data), data.encode('hex')))
        except Exception as e:
            logging.error("Subtest #6 failed with a parsing error: %s" % str(e))
            sys.exit(1)


tests = [ test1, test2 ]


if __name__ == "__main__":

    Log = logging.getLogger()
    Log.setLevel(logging.INFO)

    if len(sys.argv) >= 2 and sys.argv[1] == 'verbose':
        Log.setLevel(logging.DEBUG)

    for i in xrange(len(tests)):
        tests[i]()

