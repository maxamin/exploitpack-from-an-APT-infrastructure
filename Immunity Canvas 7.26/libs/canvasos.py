#!/usr/bin/env python

"""
canvasos.py - contains a class that allows us to abstract the idea of an
operating system
"""

import sys
if "." not in sys.path: sys.path.append(".")

from internal import *
import copy
import re

#there's 2 kinds of portuguese - annoying, no?
win32languages=["English","Arabic", "Hebrew", "Japanese"]
win32languages+=["Korean", "German", "French", "Spanish", "Russian","Swedish"]
win32languages+=["Italian", "Portuguese" , "Brazilian", "Polish"]
win32languages+=["Dutch", "Norwegian", "Hungarian", "Danish","Finnish"]
win32languages+=["Simplified Chinese" , "Traditional Chinese" , "Greek",  "Turkish" , "Czech"]

probably_english=["English","Arabic","Hebrew"]
#there often is a case on XP for example where there's no web server
#and you can't determine if it's English just from the printers

class canvasos:
    DB_SERVER="Database Server"
    SHELL_SERVER="Shell Server" #TermServer/Citrix/SSH/telnet
    MAIL_SERVER="Mail Server" #exchange/etc
    WEB_SERVER="Web Server" #WWW/HTTPS

    valid_roles=[DB_SERVER,SHELL_SERVER,MAIL_SERVER,WEB_SERVER]
    def __init__(self, base=""):
        self.base=base #Windows
        self.servicepack=[] #["SP4"] <--this is a list of possibilities. It starts empty.
        self.version="" #2000, XP, 2003, Vista, etc. For solaris this is "10" for example.
        self.build="" #8129 or "Dapper" for example would be 6.06
        self.language="" #used if only one is there...
        self.languageList=[] #["English","Simplified Chinese"]
        self.speed=None #gigahertz
        self.arch="" #x86
        self.SMP=False
        self.vm=None #string value if inside a VM we know about
        self.chroot=None #string value if a known chroot, True if unknown but true.
        self.kernel_version=None #unknown, or 2.6 or 2.4.1 or whatever
        self.cygwin=False #true if running on windows under cygwin environment
        self.family="" #Professional for XP Pro, for example. or "Home" for XP Home Edition
        self.notes=None #for storing other data
        #role is for storing things that define what this
        #machine is used for. Things like "DNS Server" "SSH Server" "Mail Server", "DB server" etc.
        #not all machines that have SMTP are "mail servers". This way you select in the
        #Gui all the "DB servers" and run a "DB Audit Script" against them.
        #this member is filled in by various exploit modules.
        self.role=[]

        #we used to assume all Windows boxes were x86, but now we don't.

        return

    def __str__(self):
        """
        We pretend to be a string if people want us to be
        """
        ret=""
        for c in [self.base, self.version, self.servicepack, self.language, self.arch, self.notes]:
            if c:
                ret+=str(c)+" "
        return ret


    def addRole(self, role):
        if role not in self.valid_roles:
            devlog("errors", "%s is not a valid role!"%role)
        self.role+=[role]
        return

    def isProbablyEnglish(self):
        """
        We check for this common situation since some exploits
        will want to just assume English.
        """
        if self.base=="Windows" and self.languageList==probably_english:
            return True
        return False


    def isSameAs(self, other):
        """Considering only attributes which are set, are we the same as other?"""
        props = ["base", "servicepack", "version", "build", "language", "arch", "kernel_version", "family"]
        rv = True
        default = canvasos()

        for p in props:
            if getattr(self,p) != getattr(other,p) and getattr(self,p) != getattr(default,p) and getattr(other,p) != getattr(default,p):
                rv = False
                break

        return rv

    def basename(self):
        return self.base

    def find(self,astr):
        return str(self).find(astr)

    def count(self, astr):
        return str(self).count(astr)

    def load_uname(self, unamestr):
        """
        Returns self.base (essentially true if we had
        any level of success)
        Loads our variables from a passed in uname string
        TODO: Add all other unixes
        """

        # x86es = ["i386", "i486", "i686", "i586", "i86pc", "amd64", "x86_64"]
        x86es = {'i386'     : 'x86',
                 'i486'     : 'x86',
                 'i686'     : 'x86',
                 'i586'     : 'x86',
                 'i86pc'    : 'x86',
                 'amd64'    : 'x64',
                 'x86_64'   : 'x64',
                }

        if isinstance(unamestr, dict):
            # Output from uname(2) syscall
            if unamestr.has_key("sysname"):
                self.base = unamestr["sysname"]

                if unamestr["machine"] in x86es:
                    self.arch = x86es[unamestr["machine"]]
                else:
                    self.arch = unamestr["machine"]
                self.kernel_version = unamestr["release"]

            elif unamestr.has_key("Major Version"):
                #Output from kernel32.dll|GetVersionExA
                self.base = "Windows"
                self.arch = "x86"
                vermap = {"5.2":"2003", "5.1":"XP", "5.0":"2000", "6.0":"Vista" }
                for k, v in vermap.iteritems():
                    maj,min = k.split(".")
                    maj = int(maj)
                    min = int(min)
                    if unamestr["Major Version"] == maj and unamestr["Minor Version"] == min:
                        self.version = v
                        break
                self.servicepack = unamestr["SP string"]

            return self.base

        if unamestr.count("Windows NT Version 4."):
            # Ver output on NT is different to rest of windowses
            self.base = "Windows"
            self.arch = "x86"
            self.version = unamestr[unamestr.index("4."):]

        if unamestr.count("[Version"):
            #ver output on windows
            self.base = "Windows"
            vermap = {"Windows 2000": "2000",
                      "Windows XP": "XP",
                      "Windows [Version 6": "Vista",
                      "Windows [Version 10": "10"
            }
            for k, v in vermap.iteritems():
                if k in unamestr:
                    self.version = v

        elif unamestr.count("[boot loader]"):
            #we are parsing a boot.ini file
            # AB: What uh, happens with foreign, non-english windowses?
            self.base = "Windows"
            #we assume the default one-os load...(this is essentially a bug on our part)
            if "Windows 2000" in unamestr:
                self.version = "2000"
            elif "Windows XP" in unamestr:
                self.version = "XP"

            elif "2003" in unamestr:
                self.version = "2003"
            #etc
            #for now we assume x86
            self.arch = "x86"
            families = ["Professional", "Server", "Home", "Ultimate", "Basic"]
            for f in families:
                if f in unamestr:
                    self.family = f

            return self.base

        else:
            x = re.split("\s+", unamestr)
            last_index = None
            for index in range(0, len(x)):
                print "[x] uname token: " + x[index]
                devlog("all", "uname token: " + x[index])
                if x[index+0] == "Windows":
                    self.base = x[index+0]
                    self.arch = "x86"
                    self.major = x[index+3]
                    self.build = x[index+5]
                    last_index = index
                    break

                elif x[index+0] == "CYGWIN":
                    self.base = "Windows"
                    self.cygwin = True
                    self.arch = "x86"
                    last_index = index
                    break

                elif x[index+0] == "Darwin":
                    self.base = "OSX"

                    if "PPC" in unamestr:
                        self.arch = "PPC"
                    elif "x86_64" in unamestr:
                        self.arch = "x64"
                    else:
                        self.arch = "x86"
                    last_index = index
                    break
                elif x[index+0] == "Linux":
                    self.base = "Linux"
                    if "x86_64" in unamestr:
                        self.arch = "x64"
                    if "x86" in unamestr:
                        self.arch = "x86"
                    last_index = index
                    break
                    
                elif x[index+0] == "NetWare": # Hey, you think I'm crazy? Seriously. Netware.
                    self.arch = "x86"
                    self.base = x[0]
                    last_index = index
                    break

                elif x[index+0] == "SunOS":
                    self.base = "Solaris"
                    if "sun4u" in unamestr:
                        self.arch = "SPARC"
                    last_index = index
                    break

            start_index = 0 if last_index is None else last_index

            if len(x) >= 3:
                self.version = x[start_index+2]

            if self.base == "":
                self.base = x[0]

            for var in x86es:
                if var in unamestr:
                    self.arch = x86es[var]
                    break

            if "SMP" in unamestr:
                self.SMP = True



        return self.base

    def load_from_clientheader(self, clientheader):
        """
        Loads our internal variables from a libs.spkproxy.clientheader
        object - this is most often used by client-side exploits
        """
        #devlog("canvasos", "headerValueDict: %s"%clientheader.headerValuesDict)
        user_agent=clientheader.headerValuesDict.get("User-Agent")
        if user_agent:
            user_agent="".join(user_agent) #we store this as a list, which should have only one member
            devlog("canvasos", "Clientheader User-Agent: %s"%user_agent)
            if "Windows" in user_agent:
                self.base="Windows"
                self.arch="x86"
                if "Windows NT 5.1" in user_agent:
                    self.version="XP"
                elif "Windows NT 6.0" in user_agent:
                    self.version="Vista"

        return self.base


    def isUnix(self):
        """
        Returns true if we are a unix-like os
        Cygwin under Windows is included as unix-like
        """
        if self.cygwin:
            return True
        Unixes=["Linux","BSD","OSX","Solaris", "FreeBSD", "OpenBSD", "Unix", "AIX"]
        for u in Unixes:
            if u==self.base:
                return True
        return False

    def guess_from_rpcdump(self, resultList):
        """
        Looks at an rpcdump result and then sets our
        own variables as necessary
        """
        for i in resultList:
            rpcnum=i[0]
            port=i[4]
            devlog("osdetect", "rpcnum: %d port %d"%(rpcnum,port))

            if rpcnum==391002 and port>1024:
                self.base='Linux'
            if rpcnum==100232:
                self.base='Solaris'
            if rpcnum==100230 and port>32000:
                self.base="Solaris"
            if rpcnum==100422:
                #this rpc number was introduced in Solaris 10
                self.base="Solaris"
                self.version=["10","11"]

        return

def new(base):
    """
    Return a new canvasos class with type of "base"
    """
    return canvasos(base)

def fromModule(mod):
    """
    Returns a list of canvasos objects, one describing each platform that the module's PROPERTY dict suggests should be vunlnerable
    PROPERTY dicts are funny things. Our general format is
    ARCH: OS major class, eg Windows, Solaris, OSX, Supposed to be a list of lists, where each element is ["OS", "Version", "Version" ...]
    VERSION: In the event that there's only one entry in ARCH, then VERSION contains the list of things that were meant to be in ARCH :)

    Note that the above structure gets mangled during load, and ends up different, so calling this on a module after it's been loaded
    doesnt work :(
    """

    archMap= { "i86pc":"x86",
              "i386":"x86",
              "Intel":"x86",
              "intel":"x86"}

    rv = []

    if not hasattr(mod, "PROPERTY"):
        return rv

    p = mod.PROPERTY
    if p.has_key("Unix hack"):
        return [new("Unix")]

    # Short cut if OS is already set, eg for legacy affectsList=["Windows"]
    if p.has_key("OS") and len(p["OS"]):
        if not p.has_key("ARCH") or (p.has_key("ARCH") and p['ARCH'] == []):
            for os in p["OS"]:
                rv.append(new(os))
            return rv

    phaseOne = []
    if p.has_key("ARCH"):
        for a in p["ARCH"]:
            base = a[0]
            if base.startswith("_"):
                base = base[1:]

            if len(a) == 1:
                x = new(base)
                phaseOne.append(x)
                continue

            archs = a[1:]

            for all in ["All", "ALL", "_all"]:
                if all in archs:
                    x = new(base)
                    phaseOne.append(x)

            if len(phaseOne):
                continue

            for z in archs:
                if z.startswith("_"):
                    z = z[1:]

                x = new(base)
                if z in archMap.keys():
                    x.arch = archMap[z]
                else:
                    x.arch = z
                phaseOne.append(x)

    if p.has_key("VERSION") and len(p["VERSION"]):

        for v in p["VERSION"]:
            if v.startswith("_"):
                v = v[1:]

            if v in ["all", "All", "ALL"]:
                rv = phaseOne
                break

            for j in phaseOne:
                x = copy.copy(j)
                x.version = v
                rv.append(x)
    else:
        rv = phaseOne


    return rv


def main():
    """
    Tester for this class
    """
    print "Testing CanvasOS object"
    cos=canvasos()
    cos.addRole(cos.MAIL_SERVER)

    return

if "__main__"==__name__:
    main()

