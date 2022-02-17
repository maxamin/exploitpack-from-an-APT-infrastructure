#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
shelllistener.py


Runs over a standard unix shell connection, perhaps
one spawned by an exploit.

Why? You may ask? Well, two reasons.
1. I can upload and download files more easily this way. Even if a remote
machine does not have uuencode and uudecode.
2. I can programatically address the shell. I.E. I can have exploits
or other modules run commands for me and get the results.

"""

from shellserver import shellserver

import os
import re
from exploitutils import *
import time
import threading
from internal import *
from canvaserror import *

import struct

def od2bin(oddata):
    """
    takes od -t -x data and makes it a binary
    """
    lines = oddata.split('\n')
    data  = ''
    for line in lines:
        words = re.findall('\s[0-9a-f]{4}', line)
        if len(words) > 0:
            data += ''.join(map(lambda w: w.strip().decode('hex')[::-1], words))

    return data

class shellfrom:
    """
    encapsulation class of all shells here
    """
    def __init__(self,fd):
        self.fd = fd

    def get_socket(self):
        return self.fd

class shellfromsocket(shellfrom):
    def __init__(self,s):
        """s is a socket, or MOSDEFSock, not a fd"""
        shellfrom.__init__(s)
        self.s=s
        return

    def get_socket(self):
        return self.s

    def get_fileno(self):
        return self.s.fileno()

    def write(self,data):
        return self.s.sendall(data)

    def read_until(self,prompt):
        """May hang forever"""
        print "read_until %s called"%prompt
        #to support socks that have read_until natively (like MOSDEF socks)
        try:
            ret=self.s.read_until(match,timeout)
            return ret
        except:
            #no read_until supported on that socket type
            pass

        buf=""
        tmp="A"
        timeout=self.s.get_timeout()
        self.s.set_timeout(None)
        while tmp!="":
            try:
                tmp=self.s.recv(1)
            except:
                break #some sort of read error causes us to return nothing
            buf+=tmp
            if buf.find(prompt)!=-1:
                self.s.set_timeout(timeout) #restore timeout
                return buf
        #we did not find our string, and the socket closed!
        return ""

    def read_some(self):
        """Read at least one byte of data"""
        buf=""
        tmp="A"
        #print "In read_some"
        while tmp!="":
            try:
                tmp=self.s.recv(100)
            except:
                if buf!="":
                    break #some sort of read error or timeout, and buf is not empty
            buf+=tmp
        return buf

class shellfromtelnet:
    """
    Support class for shells that are spawned from telnetd
    """

    _CMD_RM_FORCE="rm -f '%s'"
    _OCTET_PRINT_COMMAND = "printf \"%s\" >> %s"
    _OCTET_PRINT_FORMAT ="\\%.3o"

    def __init__(self,tn):
        self.tn=tn
        return

    def get_socket(self):
        return self.tn.get_socket()

    def get_fileno(self):
        return self.tn.fileno()

    def write(self,data):
        return self.tn.write(str(data))

    def read_until(self,prompt):
        return self.tn.read_until(prompt)

    def read_some(self):
        return self.tn.read_some()

class shellfromtty(shellfrom):
    """
    Support class for shells that are spawned from a tty

    Typical path:
    LinuxMOSDEF->TTY->master fd
                    ->slave fd with shell
    """

    _CMD_RM_FORCE="rm -f '%s'"
    _OCTET_PRINT_COMMAND = "printf \"%s\" >> %s"
    _OCTET_PRINT_FORMAT ="\\%.3o"

    def __init__(self,parent,fd):
        shellfrom.__init__(self,fd)
        self.fd=fd
        self.parent=parent
        self.shell=self.parent.shell
        return

    def write(self,data):
        return self.shell.write(self.fd,data)

    def read_until(self,prompt):
        return self.shell.read_until(self.fd,prompt)

    def read_some(self):
        return self.shell.read_some(self.fd)

class shelllistener(shellserver):
    def __init__(self,shell,logfunction=None,simpleShell=0, use_idrac_prompt=False):
        self.started=0
        self.node=None
        self.max_octects = 45

        #should never do this in the main thread!
        #unless we are, of course, in the only thread from the commandline
        threadchecknonMain()

        devlog("shelllistener", "[!] in main shell listener init!")

        sock=shell.get_socket()

        shellserver.__init__(self,sock,
                             type="Active",logfunction=logfunction)
        self.shell=shell

        self.prompt = get_random_letters(5)
        self.localPrompt = "(CANVAS)"

        self.simpleShell = simpleShell
        #arrange to always have the same prompt
        if not simpleShell:
            self.sendraw("/bin/sh -i\n")
            self.setProgress(20)
            time.sleep(1)
            self.sendraw("stty -echo 2 >/dev/null\n")
            self.log("Setting prompt.")
            #TODO: Some sort of bug here...breaks sadmind.
            time.sleep(1)
            self.setProgress(40)
            self.sendraw("PS1=\"%s\" \n"%self.prompt)
            self.log("Creating shelllistener, stage 1")
            time.sleep(1)
            self.setProgress(50)
            shell.read_until(self.prompt)
            time.sleep(1)
            self.sendraw("export PS1\n")
            self.setProgress(60)
            self.log("Creating shelllistener, stage 2")
            time.sleep(1)
            shell.read_until(self.prompt)
            self.setProgress(80)
            self.log("Creating shelllistener, done!")
            self.sock=shell.get_socket()
            self.setProgress(100)
            #print "Self.sock= %s"%str(self.sock)
        # for limited environments (like linksys embedded routers)

        else:
            devlog("shelllistener", "[!] in simple shell listener init...")

            # this prompt can't have a $ in it because minix reduced shell echo does not
            # handle "" strings, and will still escape the $, ie: echo "simpleShell$ "
            # returns "simpleShell "

            self.prompt = "simpleShell"
            self.sendraw("\necho \"" + self.prompt + "\"\n");
            shell.read_until(self.prompt)
            self.log("Creating shelllistener, done!")
            self.sock=shell.get_socket()
            self.setProgress(100)

            devlog("shellistener","[!] returning from simple shell listener init!")

        return

    def startup(self):
        if self.started:
            return
        self.started=1

    def pwd(self):
        out, rv = self.shellcommand("pwd")
        if rv != 0:
            raise NodeCommandError("Shell command returned nonzero value %d: %s"  % (rv, out))
        else:
            return out

    def getcwd(self):
        return self.pwd()

    def oneShellCommand(self, command, LFkludge =False):
        """Run a single shell command"""
        # KLUDGE: LFkludge try to escape the '\n' mess ... coz else that returns "\nOUTPUT\n"
        data=""
        off0, off1 = 0, 0
        # we set self.prompt to "simpleShell" for self.simpleShell
        if self.simpleShell:
            self.sendraw(command+";echo \""+self.prompt+"\"\n")
        else:
            if len(command) > 50:
                pcmd = "%s..." % command[:50]
            else:
                pcmd = command
            self.log("sending command: %s (prompt: %s)"%(pcmd, self.prompt))
            self.sendraw(command+"\n")
        result="A"
        #while result!="":
        while True:
            try:
                result=self.shell.read_some()
            except timeoutsocket.Timeout:
                result=""
            data+=result
            #print "Data=%s"%data
            if data.count(self.prompt)>data.count("PS1="+self.prompt):
                #print "Found prompt in data, breaking out of loop"
                break
        if LFkludge:
            if data[0] == '\n':
                off0 = 1
            if data[-1] == '\n':
                off1 = 1

        return data[off0:-(len(self.prompt)+1+off1)]

    def shellcommand(self, command, LFkludge=False):
        """Wrap oneShellCommand with a thing that'll also get and return the exit code of the shell"""
        if not self.simpleShell:
            data = self.oneShellCommand(command, LFkludge)
            exitcode = self.oneShellCommand("echo $?")
        else:
            data = self.oneShellCommand(command  + "; echo $?", LFkludge)
            exitcode = data.split("\n")[-1].strip()

        try:
            exitcode = int(exitcode)
        except ValueError:
            exitcode = 0

        return (data, exitcode)

    def sendraw(self,data):
        self.shell.write(data)
        return 1

    def runcommand(self, command, LFkludge=False):
        """
        Running a command is easy with a shell
        """
        out, rv = self.shellcommand(command, LFkludge)
        # Standard runcommand api is to ignore errors. For now. :(

        if rv != 0:
            self.log("Warning, shell command '%s' returned nonzero value %d" % (command, rv))

        return out

    def dospawn(self,command):
        # account for nohup.out need writeable cwd
        out, rv = self.shellcommand("cd /tmp && nohup '%s'" % command)
        if rv != 0:
            raise NodeCommandError("Shell command returned nonzero value %d: %s"  % (rv, out))
        else:
            return out

    def dounlink(self,filename):
        out, rv = self.shellcommand(self.shell._CMD_RM_FORCE % filename)
        if rv != 0:
            raise NodeCommandError("Shell command returned nonzero value %d: %s"  % (rv, out))
        else:
            return out

    def cd(self,directory):
        out, rv = self.shellcommand("cd '%s' " % directory)
        if rv != 0:
            raise NodeCommandError("Shell command returned nonzero value %d: %s"  % (rv, out))
        else:
            return out

    def dodir(self,directory):
        out, rv = self.shellcommand("ls -lat '%s' " % directory)
        if rv != 0:
            raise NodeCommandError("Shell command returned nonzero value %d: %s"  % (rv, out))
        else:
            return out

    def upload(self,source,dest=".", destfilename=None):
        """
        uploads a file to the target using printf

        """
        #if dest is nothing, then we don't want
        #to try to write to the root of the filesystem
        if dest=="": dest="."

        if destfilename==None:
            destfile = dest + "/"+source.split(os.path.sep)[-1]
        else:

            if "/"!=destfilename[0]:
                #if destfilename = hi and dest == /tmp then use /tmp/hi
                destfile = dest + "/"+destfilename
            else:
                #if destfilename = /tmp/hi then use /tmp/hi
                destfile = destfilename

        try:
            fin=open(source,"rb")
            data=fin.read()
            fin.close()
        except IOError, i:
            raise NodeCommandError("Error opening local file: %s" % str(i))

        #delete it if it exists
        command=self.shell._CMD_RM_FORCE%destfile
        out, rv = self.shellcommand(command)
#        if rv != 0:
#            raise NodeCommandError("Error removing destination file: %s, command %s" % (out, command))

        i=0
        while i < len(data):
            tmpdata=data[i:i+self.max_octects]
            octeddata=""
            for c in tmpdata:
                octeddata+=self.shell._OCTET_PRINT_FORMAT % (ord(c))
            command=self.shell._OCTET_PRINT_COMMAND % (octeddata,destfile)
            #command=self._OCTET_PRINT_COMMAND + " \"%s\" >> %s"%(octeddata,destfile)
            out, rv = self.shellcommand(command)
            if rv != 0:
                raise NodeCommandError("Error writing data to file %s: %s" % (destfile, out))
            #i+=45
            i+=self.max_octects

        return "File uploaded"

    def download(self,source,destdir="."):
        """
        Downloads a file
        """
        oddata, rv = self.shellcommand("od -v -x %s" % source)
        # the echo $? will cause a prompt/file: not found return status
        # so do the sanity check on the actual oddata and not the ret
        try:
            data = od2bin(oddata)
            if not len(data):
                raise NodeCommandError('Unable to retrieve od data!')
            if os.path.isdir(destdir):
                name = os.path.join(destdir,os.path.basename(source))
            else:
                name = destdir
            f = open(name,"wb")
            f.write(data)
            f.close()
        except IOError, i:
            raise NodeCommandError("Unable to write %s: %s" % (name, str(i)))
        return "Downloaded %d bytes into %s" % (len(data), name)

    def get_shell(self):
        """
        spawn telnet client with remote end hooked to it
        TODO
        """


class androidShellListener(shelllistener):
    def __init__(self,shell,logfunction=None):

        self.simpleShell = 0
        self.started=0
        self.node=None

        #Slower but more reliable
        self.max_octects = 20

        devlog("shelllistener", "[!] in main shell listener init!")

        sock=shell.get_socket()

        shellserver.__init__(self,sock,
                             type="Active",logfunction=logfunction)
        self.shell=shell

        self.prompt = get_random_letters(5)
        self.localPrompt = "(CANVAS)"

        #arrange to always have the same prompt

        self.sendraw("/system/bin/sh -i\n")
        time.sleep(1)
        self.setProgress(20)

        self.log("Setting prompt.")
        self.sendraw("PS1=\"%s\" \n"%self.prompt)
        time.sleep(1)
        self.setProgress(30)

        shell.read_until(self.prompt)
        self.sendraw("export PS1\n")
        time.sleep(1)
        self.setProgress(40)


        shell.read_until(self.prompt)
        self.log("Setting paths.")
        self.sendraw("PATH=\"/sbin:/system/bin:/system/xbin\"\n")
        time.sleep(1)

        shell.read_until(self.prompt)
        self.sendraw("export PATH\n")
        time.sleep(1)

        self.log("Creating shelllistener, stage 1")
        self.setProgress(50)
        time.sleep(1)

        self.log("Creating shelllistener, stage 2")
        shell.read_until(self.prompt)
        self.setProgress(80)

        self.log("Creating shelllistener, done!")
        self.sock=shell.get_socket()
        self.setProgress(100)

        return

    def dodir(self,directory):
        out, rv = self.shellcommand("ls -l '%s' " % directory)
        if rv != 0:
            raise NodeCommandError("Shell command returned nonzero value %d: %s"  % (rv, out))
        else:
            return out

    def upload(self,source,dest=".", destfilename=None):
        """
        uploads a file to the target using printf

        """
        #if dest is nothing, then we don't want
        #to try to write to the root of the filesystem
        if dest=="": dest="."

        if destfilename==None:
            destfile = dest + "/"+source.split(os.path.sep)[-1]
        else:

            if "/"!=destfilename[0]:
                #if destfilename = hi and dest == /tmp then use /tmp/hi
                destfile = dest + "/"+destfilename
            else:
                #if destfilename = /tmp/hi then use /tmp/hi
                destfile = destfilename

        try:
            fin=open(source,"rb")
            data=fin.read()
            fin.close()
        except IOError, i:
            raise NodeCommandError("Error opening local file: %s" % str(i))

        #delete it if it exists
        command=self._CMD_RM_FORCE%destfile
        out, rv = self.shellcommand(command)
#        if rv != 0:
#            raise NodeCommandError("Error removing destination file: %s, command %s" % (out, command))

        self.sendraw("cat > /tmp/dest_file <<someuniquetag\n")
        time.sleep(1)
        self.sendraw( "%s%s " % (data, "\nsomeuniquetag\n"))
        time.sleep(1)

        return "File uploaded"
