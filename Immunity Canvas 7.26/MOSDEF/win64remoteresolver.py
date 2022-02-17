#! /usr/bin/env python

# Win64 follows LLP64 conventions, short = 16 bits, int == 32 bits, long == 32 bits, long long == 64 bits
# http://www.intel.com/cd/ids/developer/asmo-na/eng/197664.htm?page=2

MAXCACHESIZE = 1000

from remoteresolver import remoteresolver
import threading
import random
from internal import devlog

class win64remoteresolver(remoteresolver):
    def __init__(self, proc = 'X64', version = None):

        if hasattr(self, 'fd'):
            devlog('win64remoteresolver', 'Warning: reinitializing! Our FD=%s' % self.fd)

        self.isapidict          = {}
        self.arch               = 'X64'
        self.functioncache      = {}
        self.localcache         = {}
        self.xorkey             = random.randint(1, 250)

        remoteresolver.__init__(self, 'Win64', proc, version)

        self.remoteFunctionsUsed = {}
        self.remotefunctioncache = {}
        self.remotefunctioncache["kernel32.dll|GetProcAddress"] = 0x0102030405060708
        self.remotefunctioncache["ws2_32.dll|send"]             = 0x0102030405060708

    def getremote(self,func):
        if func in self.remotefunctioncache:
            return self.remotefunctioncache[func]
        self.savefunctioncache()
        self.clearfunctioncache()
        self.restorefunctioncache()
        self.remotefunctioncache[func] = 0x0102030405060708
        return 0x0102030405060708

    def initLocalFunctions(self):
        self.localfunctions["checkvm"]=("asm","""
           checkvm:
            xorl %rax, %rax
            subl $0x10, %rsp
            sidt (%rsp)
            movb 0x5(%rsp), %al
            addl $0x10, %rsp
            andl $0xff, %rax
            movl %eax, %r13d
            ret
            """)

        self.localfunctions['callbuf'] = ('asm', """
            callbuf:
                pushl %rbp
                movl %rsp,%rbp
                pushad
                movl 16(%rbp),%rdi
                call *%rdi
                popad
                movl %rbp,%rsp
                popl %rbp
                ret $8
            """)

        # XXX: check these ...
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

        # LLP64
        self.localfunctions["sendlonglong"] = ("c", """
            #import "local", "writeblock2self" as "writeblock2self"
            void sendlonglong(unsigned long long myint) {
                unsigned long long i;
                i = myint;
                writeblock2self(&i, 8);
            }
        """)

        self.localfunctions["sendint"] = ("c", """
            #import "local", "writeblock2self" as "writeblock2self"
            void sendint(unsigned int myint) {
                int i;
                i = myint;
                writeblock2self(&i, 4);
            }
        """)

        devlog('win64remoteresolver', 'Initialized sendint with fd=%s' % self.fd)
        self.localfunctions["sendstring"]=("c","""
            #import "local","strlen" as "strlen"
            #import "local","sendint" as "sendint"
            #import "local","writeblock2self" as "writeblock2self"

            void sendstring(char * instr) {
                if(instr)
                {
                    sendint(strlen(instr));
                    writeblock2self(instr,strlen(instr));
                }
                else
                {
                    sendint(0);
                }
            }
        """)

        self.localfunctions["sendunistring2self"]=("c","""
            #import "local","msvcrt.dll|wcslen" as "wcslen"
            #import "local","sendint" as "sendint"
            #import "local","writeblock2self" as "writeblock2self"

            void sendunistring2self(short * instr) {
                long long size;
                if(instr)
                {
                    size = wcslen(instr);
                    size = size*2;
                    sendint(size);
                    writeblock2self(instr, size);
                }
                else
                {
                    sendint(0);
                }
            }
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
            //#import "local", "debug" as "debug"

            int xorblock(char * instr, int size) {
                int i;
                char *p;
                char newbyte;
                char key;

                //debug();
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
        print "XORKEY=%x"%self.xorkey

        #uses the reliable writeblock
        self.localfunctions["send_array"]=("c","""
            #import "local","writeblock" as "writeblock"
            #import "local","sendint" as "sendint"
            int send_array(int fd, char * outstr,int size) {
                if(size) {
                    sendint(size);
                    writeblock(fd,outstr,size);
                }
                else
                {
                    sendint(0);
                }
            }
        """)

        #uses the reliable writeblock
        self.localfunctions["writestring"]=("c","""
            #import "local","send_array" as "send_array"
            #import "local","strlen" as "strlen"
            int writestring(int fd, char * outstr) {
                if(outstr) {
                    send_array(fd,outstr,strlen(outstr));
                }
                else
                {
                    send_array(fd,outstr,0);
                }
            }
        """)

        #our reliable reading function
        self.localfunctions["readdata"] = ("c", """
            #import "local", "ws2_32.dll|recv" as "recv"
            #import "local", "ws2_32.dll|WSAGetLastError" as "WSAGetLastError"

            int readdata(int fd, char *outstr, int size) {
                int left;
                int i;
                char *p;
                left = size;
                p = outstr;
                int err;
                int fault;

                while (left > 0) {
                    i = recv(fd, p, left, 0);
                    if (i == 0xffffffff) {
                        fault = 0;
                        err = WSAGetLastError();

                        // Handle WSAEWOULDBLOCK
                        if (err != 0x2733) {
                            fault = 1;
                        }

                        // Handle WSAEINTR
                        if (err != 0x2714) {
                            fault = fault + 1;
                        }

                        if (fault == 2) {
                            left = 0;
                        }
                    }
                    else {
                        left = left - i;
                        p = p + i;
                    }
                }

                // Handle error cases
                if (fault == 2) {
                    return 0;
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
                #import "local", "ecb|readclient" as "readclient"

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
                """.replace("CONTEXT", str(self.context))
        self.localfunctions["readdatafromself"] = ("c", code)

        #uses the reliable readdata
        self.localfunctions["readintfromself"] = ("c", """
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

        self.localfunctions["readlonglongfromself"]=("c","""
            #import "local","readdatafromself" as "readdatafromself"
            int readlonglongfromself() {
                char buf[8];
                unsigned long long *p;
                unsigned long long ret;
                p = buf;
                readdatafromself(buf, 8);
                ret = *p;
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
            #import "local","kernel32.dll|GlobalAlloc" as "GlobalAlloc"

            char * malloc(int size) {
                char * buf;
                // not using GMEM_MOVABLE, so uses real pointer which is 64 bit
                buf = GlobalAlloc(0, size);
                return buf;
            }
        """)

        self.localfunctions["free"]=("c","""
            #import "local", "kernel32.dll|GlobalFree" as "GlobalFree"

            int free(unsigned long long handle) {
                unsigned long long ret;
                // we don't use globalalloc with GMEM_MOVABLE so handle is 64b
                ret = GlobalFree(handle);
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

        code = """
            #import "local","writeblock2self" as "writeblock2self"
            #import "local","sendint" as "sendint"
            int senddata2self(char * buf, int size) {
                sendint(size);
                writeblock2self(buf,size);
            }
            """
        self.localfunctions["senddata2self"]=("c",code)

        # our reliable writing function
        self.localfunctions["writeblock"] = ("c", """
            #import "local", "ws2_32.dll|send" as "send"
            #import "local", "ws2_32.dll|WSAGetLastError" as "WSAGetLastError"

            int writeblock(int fd, char *instr, int size) {
                int left;
                int i;
                int err;
                char *p;
                int a;
                left = size;
                p = instr;
                int fault;

                while (left > 0) {
                    i = send(fd, p, left, 0);
                    if (i == 0xffffffff) {
                        fault = 0;
                        err = WSAGetLastError();

                        // Handle WSAEWOULDBLOCK
                        if (err != 0x2733) {
                            fault = 1;
                        }

                        // Handle WSAEINTR
                        if (err != 0x2714) {
                            fault = fault + 1;
                        }

                        if (fault == 2) {
                            left = 0;
                        }
                    }
                    else {
                        left = left - i;
                        p = p + i;
                    }
                }

                // Handle error cases
                if (fault == 2) {
                    return 0;
                }

                return 1;
            }
        """)

        if self.isapidict == {}:
            code = """
                #import "local", "writeblock" as "writeblock"
                #import "local", "xorblock" as "xorblock"

                int writeblock2self(char *buf, int size) {
                    int ret;

                    xorblock(buf, size);
                    ret = writeblock(FD, buf, size);
                    xorblock(buf, size); // restore

                    return ret;
                }
            """
            code = code.replace("FD",str(int(self.fd)))
            devlog("win64remoteresolver", "writeblock2self compiled with fd=%s"%self.fd)
        else:
            print "Using ISAPI code in win64 remoteresolver"
            code = """
                #import "local","ecb|writeclient" as "writeclient"

                #import "local","xorblock" as "xorblock"

                int writeblock2self(char * buf, int size) {
                    int newsize;
                    int sentsize;
                    sentsize = 0;
                    xorblock(buf, size);
                    while (sentsize < size) {
                        newsize = size - sentsize;
                        writeclient(CONNID, buf, &newsize);
                        sentsize = sentsize + newsize;
                    }

                    xorblock(buf, size); // restore
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

        self.localfunctions["call3ArgFuncPtr"]=("asm", """
            call3ArgFuncPtr:
            push %rbp
            movq %rsp,%rbp

            movq 0x10(%rbp),%rdi    // rdi stores func ptr
            movq 0x18(%rbp),%rcx
            movq 0x20(%rbp),%rdx
            movq 0x28(%rbp),%r8


            // Stack space
            push %r9
            push %r8
            push %rdx
            push %rcx

            call %rdi

            movq %rbp, %rsp
            pop %rbp
            ret $32
        """)

        self.localfunctions["call4ArgFuncPtr"]=("asm", """
            call4ArgFuncPtr:
            push %rbp
            movq %rsp,%rbp

            movq 0x10(%rbp),%rdi    // rdi stores func ptr
            movq 0x18(%rbp),%rcx
            movq 0x20(%rbp),%rdx
            movq 0x28(%rbp),%r8
            movq 0x30(%rbp),%r9


            // Stack space
            push %r9
            push %r8
            push %rdx
            push %rcx

            call %rdi

            movq %rbp, %rsp
            pop %rbp
            ret $40
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
    w = win64remoteresolver()
