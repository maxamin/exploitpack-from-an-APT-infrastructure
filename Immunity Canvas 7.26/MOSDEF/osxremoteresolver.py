#! /usr/bin/env python

MAXCACHESIZE = 1000

from remoteresolver import remoteresolver
from unixremoteresolver import unixremoteresolver

# non-arch specific functions
class osxremoteresolver(remoteresolver):
    def __init__(self, proc, version='10.5'):
        remoteresolver.__init__(self, 'OSX', proc, version)
        
    def initLocalFunctions(self):
        # sysctl
        self.localfunctions['sysctl'] = ('c', """
        #import "local","syscall6" as "syscall6"
        
        int sysctl(int *name, unsigned int namelen, void *oldp, unsigned long *oldlenp, void *newp, unsigned long newlen)
        {
          int i;
          i = syscall6(%d, name, namelen, oldp, oldlenp, newp, newlen);
          return i;
        }
        """ % self.libc.getdefine('SYS___sysctl'))
        
        # getcwd .. no syscall .. fd = open(".", 0, 0) / fcntl(fd, F_GETPATH, buf[1024])
        self.localfunctions['getcwd'] = ('c', """
        #import "local", "fcntl" as "fcntl"
        #import "local", "open" as "open"
        #import "local", "close" as "close"

        int getcwd(char *buf, int size)
        {
          int fd;
          int ret;

          if (size < 1024) // has to be >= MAXPATHLEN
          {
             return -1;
          }
          
          fd = open(".", 0, 0);
          ret = fcntl(fd, %d, buf);
          close(fd);
          
          return ret;
        }""" % self.libc.getdefine('F_GETPATH'))
        
        # waitpid .. wait4(arg, arg, arg, 0)
        self.localfunctions['waitpid'] = ('c', """
        #import "local", "syscall4" as "syscall4"
        
        int waitpid(int pid, int *stat_loc, int options)
        {
          int ret;
          ret = syscall4(%d, pid, stat_loc, options, 0);
          return ret;
        }""" % self.libc.getdefine('SYS_wait4'))
        
        # SYS_send is a SYS_sendto on OS X
        self.localfunctions['send'] = ('c', """
        #import "local", "syscall6" as "syscall6"
        
        int send(int socket, char *buffer, int length, int flags)
        {
          int ret;
          ret = syscall6(%d, socket, buffer, length, flags, 0, 0);
          return ret;
        }""" % self.libc.getdefine('SYS_sendto'))
        
        # SYS_recv is a SYS_recvfrom on OS X
        self.localfunctions['recv'] = ('c', """
        #import "local", "syscall6" as "syscall6"
        
        int recv(int socket, char *buffer, int length, int flags)
        {
          int ret;
          ret = syscall6(%d, socket, buffer, length, flags, 0, 0);
          return ret;
        }""" % self.libc.getdefine('SYS_recvfrom'))

# intel specific functions
class x86osxremoteresolver(osxremoteresolver, unixremoteresolver):
    def __init__(self, proc='x86', version='10.5'):
        osxremoteresolver.__init__(self, 'x86', version)
        unixremoteresolver.__init__(self)
        
        self.remoteFunctionsUsed = {}
        self.remotefunctioncache = {}
    
    def initLocalFunctions(self):
        osxremoteresolver.initLocalFunctions(self)

        # debug
        self.localfunctions['debug'] = ('asm', """
        debug:
            int3
            ret
        """)

        self.localfunctions['sendpointer'] = ("c", """
        #import "local", "sendint" as "sendint"
        void sendpointer(int ptr)
        {
            sendint(ptr);
        }
        """)
        
        
        # pipe returns in eax and edx
        self.localfunctions['pipe'] = ('asm', """
        pipe:
          pushl %%ebp
          movl %%esp,%%ebp
          movl 8(%%ebp),%%eax
          pushl %%eax
          movl $%d,%%eax
          pushl %%eax
          int $0x80
          jb pipe_error
          movl 8(%%ebp),%%edi
          movl %%eax,(%%edi)
          movl %%edx,4(%%edi)
          xorl %%eax,%%eax
          popl %%edi         
        pipe_error:
          movl %%ebp,%%esp
          popl %%ebp
          ret $4
        """ % self.libc.getdefine('SYS_pipe'))
        
        # fork on XNU has pid in eax, and parent flag in edx: 0 == parent, 1 == child
        self.localfunctions['fork'] = ('asm', """
        fork:
          pushl %%ebp
          pushl %%ebx // save .. remember to adjust +4 for any ebp offsets
          movl %%esp,%%ebp
          movl $%d,%%eax
          pushl %%eax
          int $0x80
          test %%edx,%%edx
          jz parent
          xorl %%eax,%%eax // zero out ret if we're child
        parent:
          movl %%ebp,%%esp
          popl %%ebx // restore
          popl %%ebp
          ret
        """ % self.libc.getdefine('SYS_fork'))
        
        ###
        ### Add local functions for remote resolving
        ###
        
        # Position independent OSX remote symbol resolver/shared library loader
        # Works as is on 10.4, 10.5 and 10.6
        # Need to have the following in mind when loading shared libraries. If
        # they pull in OSX frameworks (like Core Foundation) they need to be
        # loaded from the main thread (the initial thread), because CF will
        # send SIGTRAP and kill the process if it not initialized there.
        
        # Also, since this resolver is kind of primitive, we are only using it
        # to load _dlsym and _dlopen which we then use for all resolutions
        
        self.localfunctions['resolve'] = ("asm", """
        resolve: 
        // Resolves symbols present in dyld image using hashed names
        movl    4(%esp),%eax
        pushl   %eax
        call    hash
        addl    $4, %esp
        
        pushl   %eax
        movl    12(%esp), %eax
        pushl   %eax
        call    macho_resolve
        addl    $8,%esp
        ret

        macho_resolve: 
        // Resolves symbols present in given image
        pushl   %ebp
        movl    %esp,%ebp
        subl    $12, %esp
        pushl   %ebx
        pushl   %esi
        pushl   %edi

        movl    8(%ebp),%ebx            // mach-o image base address
        movl    16(%ebx),%eax           // mach_header->ncmds
        movl    %eax,-4(%ebp)           // ncmds

        addb    $28,%bl                 // Advance ebx to first load command
        mrloadcmd: 
        // Load command loop
        xorl    %eax,%eax
        cmpl    %eax, -4(%ebp)
        je      mrfinish

        incl    %eax
        cmpl    %eax,(%ebx)
        je      mrsegment
        incl    %eax
        cmpl    %eax,(%ebx)
        je      mrsymtab
        mrnextloadcmd: 
        // Advance to the next load command
        decl    -4(%ebp)
        addl    4(%ebx),%ebx
        jmp     mrloadcmd
        mrsegment: 
        // Look for "__TEXT" segment
        cmpl    $0x54584554, 10(%ebx)
        je      mrtext
        // Look for "__LINKEDIT" segment
        cmpl    $0x4b4e494c, 10(%ebx)
        je      mrlinkedit

        jmp     mrnextloadcmd
        mrtext: 
        movl    24(%ebx),%eax
        movl    %eax,-8(%ebp)           // save image preferred load address
        jmp     mrnextloadcmd
        mrlinkedit: 
        // We have found the __LINKEDIT segment
        movl    24(%ebx),%eax           // segcmd->vmaddr
        pushl   %ebx
        movl    -8(%ebp), %ebx
        subl    %ebx,%eax               // image preferred load address
        popl    %ebx
        addl    8(%ebp),%eax            // actual image load address

        pushl   %ebx
        movl    32(%ebx), %ebx
        subl    %ebx,%eax               // segcmd->fileoff
        popl    %ebx
        movl    %eax,-12(%ebp)          // save linkedit segment base

        jmp     mrnextloadcmd

        mrsymtab: 
        // Examine LC_SYMTAB load command
        movl    12(%ebx),%ecx           // ecx = symtab->nsyms
        mrsymbol: 
        xorl    %eax,%eax
        cmpl    %eax,%ecx
        je      mrfinish
        decl    %ecx

        pushl   %ecx
        imul    $12, %ecx
        movl    %ecx, %edx
        popl    %ecx

        addl    8(%ebx),%edx            // edx += symtab->symoff
        addl    -12(%ebp),%edx          // adjust symoff relative to linkedit

        movl    (%edx),%esi             // esi = index into string table
        addl    16(%ebx),%esi           // esi += symtab->stroff
        addl    -12(%ebp),%esi          // adjust stroff relative to linkedit

        pushl   %esi
        call    hash
        addl    $4,%esp

        mrcompare: 
        cmpl    12(%ebp),%eax
        jne     mrsymbol

        movl    8(%edx),%eax            // return symbols[ecx].n_value
        pushl   %ebx
        movl    -8(%ebp),%ebx
        subl    %ebx,%eax               // adjust to actual load address
        popl    %ebx
        addl    8(%ebp),%eax
        mrfinish: 
        popl    %edi
        popl    %esi
        popl    %ebx
        leave
        ret

        hash: 
        // Return a 32bit hash of given string
        pushl   %ebp
        movl    %esp,%ebp

        pushl   %esi
        pushl   %edi

        movl    8(%ebp),%esi    // string
        xorl    %edi,%edi
        cld
        hloop: 
        // hash = (hash >> 13) | ((hash & 0x1fff) << 19) + c    
        xorl    %eax,%eax
        lodsb
        cmpb    %ah,%al
        je      hexit
        ror     $13, %edi
        addl    %eax,%edi
        jmp     hloop
        hexit: 
        movl    %edi,%eax
        popl    %edi
        popl    %esi
        leave
        ret
        """)
        
        self.localfunctions['dlopen'] = ("c", """
        #import "remote","_dlopen" as "_dlopen"
        void *dlopen(char *library)
        {
            void *ret;
        
            ret = _dlopen(library, 1); // RTLD_LAZY
            return ret;
        }
        """)
        
        
        self.localfunctions['dlsym'] = ("c", """
        #import "remote", "_dlsym" as "_dlsym"
        void *dlsym(void *handle, char *symbol)
        {
            void *ret;

            if (handle == NULL) {
                ret = _dlsym(-2, symbol); // RTLD_DEFAULT
            } else {
                ret = _dlsym(handle, symbol);
            }
            
            return ret;
        }
        """)
        
# ppc specific functions
class ppcosxremoteresolver(osxremoteresolver):
    def __init__(self, proc = 'PowerPC', version = '10.4'):
        import threading
        self.fd=1
        self.arch="PPC"
        self.sfunctioncache = ()
        osxremoteresolver.__init__(self, 'PowerPC', version)
        self.remoteFunctionsUsed={} #a list of functions we've already used, so we don't double-define
        self.remotefunctioncache={}

        self.compilelock=threading.RLock()
        self.compilelibc = 0
    
    def getremote(self,func):
        if func in self.remotefunctioncache:
            #print "Found: returning."
            return self.remotefunctioncache[func]

        raise Exception, "Error, MOSDEF over OSX doesn't support remote dynamic linking (%s)" % func
    
    def savefunctioncache(self):
        self.sfunctioncache=(self.functioncache,self.remoteFunctionsUsed)
        
    def restorefunctioncache(self):
        (self.functioncache,self.remoteFunctionsUsed)=self.sfunctioncache

    def addToRemoteFunctionCache(self,function):
        self.remoteFunctionsUsed[function]=1
        #print "Added %s to remote functions used cache"%function
        return
    

    def createSyscall(self):
        for a in range(0, 7):
            shellcode="syscall%d:\n" % a
            shellcode+="  mflr  r0\n"
            shellcode+="  mr    r17, r0\n"
            shellcode+="  lwz   r0, 0(r2)\n"
            for arg in range(0, a):
                shellcode+="lwz   r%d, %d(r2)\n" % (3+arg, 4+arg*4)
            shellcode+="sc\n"
            shellcode+="xor   r9,r9,r9\n"
            shellcode+="mr    r13, r3\n"
            shellcode+="addi  r2, r2, %d\n" % ((a+1)*4)
            shellcode+="mtlr  r17\n"
            shellcode+="blr\n"
            self.localfunctions["syscall%d" % a] = ("asm", shellcode)

        # syscallE (syscall Error)
        #   change the sign of the return value, so its compatible with linux

        for a in range(0, 7):
            shellcode="syscallE%d:\n" % a
            shellcode+="  mflr  r0\n"
            shellcode+="  mr    r17, r0\n"
            shellcode+="  lwz   r0, 0(r2)\n"
            for arg in range(0, a):
                shellcode+="lwz   r%d, %d(r2)\n" % (3+arg, 4+arg*4)
            shellcode+="sc\n"
            shellcode+="neg   r3, r3\n"
            shellcode+="mr    r13, r3\n"
            shellcode+="addi  r2, r2, %d\n" % ((a+1)*4)
            shellcode+="mtlr  r17\n"
            shellcode+="blr\n"
            self.localfunctions["syscallE%d" % a] = ("asm", shellcode)
            
    def initLocalFunctions(self):
        osxremoteresolver.initLocalFunctions(self)
        
        #print "initLocalFunctions"
        self.createSyscall()
        
        self.localfunctions["syscall"]=("asm","""
syscall:
    mflr  r0
    mr r17, r0

    mr r0, r3       
    mr r3, r4
    mr r4, r5
    mr r5, r6
    mr r6, r7
    mr r7, r8
    sc
    xor  r6, r6, r6
    mr   r13, r3

    mtlr   r17
    blr
""")
        
        self.localfunctions["debug"]=("asm","""
debug:
!mflr r0
trap
!mtlr r0
blr
        """)
        
        #includes
        self.localfunctions["fstat.h"]=("header","""
        //this is from the kernel .h, since the libc one is not what the
        //system call returns
        struct stat {
        unsigned long st_dev;
        unsigned long st_ino;
        unsigned short st_mode;
        unsigned short st_nlink;
        
        unsigned long st_uid;
        unsigned long st_gid;
        unsigned long st_rdev;
        
        unsigned long  st_atime;
        unsigned long  st_atimensec;
        unsigned long  st_mtime;
        unsigned long  st_mtimensec;
        unsigned long  st_ctime;
        unsigned long  st_ctimensec;
        unsigned long  st_size;
        unsigned long  st_blocks;
        unsigned long  st_blksize;
        unsigned long  st_flags;
        unsigned long  st_gen;
        unsigned long  st_lspare;
        unsigned long  st_qspare1;
        unsigned long  st_qspare2;
        };


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

        self.localfunctions["sysinfo"]=("c","""
        #import "local", "syscall" as "syscall"
        int
        sysinfo(int request, char *buf, int buflen) {
          int i;
          i = syscall(139, request, buf, buflen);
          return i;
        }
        """)

        self.localfunctions["fstat"]=("c","""
        #import "local","syscall2" as "syscall2"
        #include "fstat.h"
        int
        fstat(int fd, struct stat *buf) {
          int i;
          i = syscall2(189, fd, buf);
          return i;
        }
        """)
        self.localfunctions["mmap"] = ("asm", """
        mmap:
mflr   r0
mr     r17, r0
li     r0, 197
lwz    r3, 0(r2)
lwz    r4, 4(r2)
lwz    r5, 8(r2)
lwz    r6, 12(r2)
lwz    r7, 16(r2)
lwz    r8, 20(r2)
lwz    r9, 20(r2)  ! oddities of mmap
sc
xor    r6,r6,r6
mr     r13, r3
addi   r2, r2, 24
mtlr   r17
blr
        """)
        
        self.localfunctions["munmap"] = ("c", """
        #import "local", "syscall2" as "syscall2"
        int munmap(unsigned long addr, unsigned long len) {
            int i;
            i = syscall2(73, addr, len);
            return i;
        }
        """)
        self.localfunctions["FD_ZERO"]=("c","""
        #import "local", "memset" as "memset"
        int
        FD_ZERO(int *fd_set) {
           memset(fd_set,0,128);
           return 1;
        }
        """)

        self.localfunctions["FD_SET"]=("c","""
        void
        FD_SET(int fd, int *fd_set) {
           int index;
           int flag;
           int *p;
           int bucket;
           int oldvalue;
           int newvalue;
                               
           flag=1;
           index=fd%32;
           
           bucket=fd/32;

           while (index>0) {
             flag=flag<<1;
             index=index-1;
           }
           
           //now flag has our bit value set
           
           p=fd_set+bucket;

           oldvalue=*p;
           newvalue=oldvalue|flag;
           *p=newvalue;
        }
        """)

        self.localfunctions["select"]=("c","""
        #import "local","syscall5" as "syscall5"
        int
        select(int n, char *readfds, char *writefds, char *exceptfds, char *timeout) {
        int i;
        //debug();
        i=syscall5(0x5d, n, readfds, writefds, exceptfds, timeout);
        return i;
        }
        """)

        
        #(type,code)
        self.localfunctions["sendint"]=("asm","""
sendint:
mflr   r0
mr     r17, r0

lwz    r3, 0(r2)
subi   r2, r2, 8
stw    r3, 0(r2)


li     r3, FDVAL
mr     r4, r2
li     r5, 4
mr     r0, r5

sc
xor    r4, r4, r4
mr     r13, r3

addi   r2, r2, 12

mtlr   r17
blr
        """.replace("FDVAL",str(self.fd)))
        
        #print "Initialized sendint with fd=%s"%self.fd

        
        self.localfunctions["sendstring"]=("c","""
        #import "local","sendblock" as "sendblock"
        #import "local","strlen" as "strlen"
        void sendstring(char * instr) {
         int i;
         sendblock(FD, instr, strlen(instr));
        }
        """.replace("FD",str(self.fd)))
        print "FD: %d" % self.fd
        
        self.localfunctions["chdir"]=("c","""
        #import "local","syscall1" as "syscall1"
        int
        chdir(char * path) {
          int i;
          i = syscall1(12, path);
          return i;
        }
   
        """)
        
        # int * fildes is ptr to int fildes[2]
        self.localfunctions["pipe"]=("asm","""
pipe:
mflr   r0
mr     r17, r0

li     r0, 42
lwz    r12, 0(r2)
!mr     r12, r3
sc
xor    r4, r4, r4
stw    r3, 0(r12)
stw    r4, 4(r12)
li     r13, 0

addi   r2, r2, 4

lwz  r3, -16(r1)   ! restoring registers
lwz  r4, -20(r1)   ! restoring registers
lwz  r5, -24(r1)   ! restoring registers
lwz  r6, -28(r1)   ! restoring registers
lwz  r7, -32(r1)   ! restoring registers
lwz  r8, -36(r1)   ! restoring registers
mtlr   r17
blr
        """)

        self.localfunctions["wait4"]=("c","""
        #import "local","syscall4" as "syscall4"
        int wait4(int pid, int *status, int options, void *rusage)
        {
          int i;
          i = syscall4(SYS_wait4, pid, status, options, rusage);
          return i;
        }
        """)
        
        self.localfunctions["wait"]=("c","""
        #import "local","wait4" as "wait4"
        int wait(int *status)
        {
          int i;
          i = wait4(-1, status, 0, 0);
          return i;
        }
        """)

        # arg is either an int or a ptr to a data structure
        self.localfunctions["ioctl"]=("c","""
        #import "local","syscall3" as "syscall3"
        int ioctl(int fildes, int request, int arg) 
        {
            int i;
            i = syscall3(54, fildes, request, arg);
            return i;
        }
        """)
                          
        # arg is either an int or a ptr depending on cmd
        self.localfunctions["fcntl"]=("c","""
        #import "local","syscall3" as "syscall3"
        int fcntl(int fildes, int cmd, long arg) 
        {
            int i;
            i = syscall3(92, fildes, cmd, arg);
            return i;
        }
        """)
        
        self.localfunctions["setsockopt"]=("c","""
        #import "local", "syscall5" as "syscall5"
        int setsockopt(int s, int level, int optname, int optval, int optlen)
        {
          int i;
          i = syscall5(105, s, level, optname, optval, optlen);
          return i;
        }
        """)

        self.localfunctions["getsockopt"]=("c","""
        #import "local","syscall5" as "syscall5"
        
        int getsockopt(int s, int level, int optname, int optval, int optlen)
        {
          int i;
          
          i = syscall5(118, s, level, optname, optval, optlen);
          
          return i;
        }
        """)

        # SunOS does not have a dup2 syscall, the syntax is:
        # fcntl(old, F_DUP2FD, new), F_DUP2FD is 9
        self.localfunctions["dup2"]=("c","""
        #import "local","syscall2" as "syscall2"
        int dup2(int old, int new)
        {
          int i;
          i = syscall2(90, old, new);
          return i;
        }
        """)
        
        self.localfunctions["close"]=("c","""
        #import "local","syscall1" as "syscall1"
        int close(int fildes) 
        {
          int i;
          i = syscall1(6, fildes);
          return i;
        }
        """)
        
        self.localfunctions["signal"]=("c","""
        #import "local","syscall3" as "syscall3"
        struct sigaction {
            unsigned long sa_handler;
            unsigned long  sa_mask;
           int            sa_flags;
         };

        int signal(int signum, unsigned long sighandler)
        {
          int i;
          struct sigaction sa;
          struct sigaction osa;
          
          sa.sa_handler = sighandler;
          sa.sa_flags = 0 ;
          
          i = syscall3(46, signum, &sa, &osa);
          return i;
        }
        """)
        
        
        self.localfunctions["exit"]=("c","""
        #import "local","syscall1" as "syscall1"
        int exit(int val) 
        {
          int i;
          i = syscall1(1, val);
          return i;
        }
        """)

        
        self.localfunctions["getpid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int getpid() 
        {
          int i;
          i = syscall0(20);
          return i;
        }
        """)
        
        # SYS_?? fix me to be proper getppid
        
        self.localfunctions["getppid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int getppid(char * dest) {
            int i;
            //ALERT: fix me to be proper getppid!
            i=syscall0(20);
            return i;
        }
        """)
        
        # getpgrp is a subcode of SYS_pgrpsys (39) on SunOS
        #
        # * subcodes:
        # *      getpgrp()         :: syscall(39,0)
        # *      setpgrp()         :: syscall(39,1)
        # *      getsid(pid)       :: syscall(39,2,pid)
        # *      setsid()          :: syscall(39,3)
        # *      getpgid(pid)      :: syscall(39,4,pid)
        # *      setpgid(pid,pgid) :: syscall(39,5,pid,pgid)
    
        self.localfunctions["getpgrp"]=("c","""
        #import "local","syscall1" as "syscall1"
        int getpgrp() 
        {
            int i;
            i = syscall1(39, 0);
            return i;
        }
        """)
        
        
        self.localfunctions["getuid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int getuid() 
        {
            int i;
            i = syscall0(24);
            return i;
        }
        """)

        # SYS_?? ... using getuid for now

        self.localfunctions["geteuid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int geteuid() 
        {
            int i;
            // ALERT: fix me to have proper euid !
            i=syscall0(25);
            return i;
        }
        """)
        
        self.localfunctions["setuid"]=("c","""
        #import "local","syscall1" as "syscall1"
        int setuid(int uid) 
        {
            int i;
            i = syscall1(23, uid);
            return i;
        }
        """)

        self.localfunctions["seteuid"]=("c","""
        #import "local","syscall1" as "syscall1"
        #import "local","debug" as "debug"
        int seteuid(int euid) 
        {
            int i;
            i = syscall1(183, euid);
            return i;
        }
        """)

        
        self.localfunctions["setegid"]=("c","""
        #import "local","syscall1" as "syscall1"
        int setegid(int egid) 
        {
            int i;
            i = syscall1(136, egid);
            return i;
        }
        """)
        
        self.localfunctions["setgid"]=("c","""
        #import "local","syscall1" as "syscall1"
        int setgid(int gid) 
        {
            int i;
            i = syscall1(46, gid);
            return i;
        }
        """)
        
        self.localfunctions["getgid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int getgid() 
        {
            int i;
            i = syscall0(47);
            return i;
        }
        """)
        
        # SYS_?? fix me to get proper egid
        
        self.localfunctions["getegid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int getegid() {
            int i;
            //ALERT: needs to be egid, using getgid call for a bit
            i=syscall0(43);
            return i;
        }
        """)
        
        self.localfunctions["fork"]=("asm","""
fork: 
mflr   r0
mr     r17, r0

li     r0, 2
sc
xor    r6, r6, r6
mr     r13, r4 ! parent(r4==0) or child (r4==1)

mtlr   r17
blr
        """)
        
        self.localfunctions["open"]=("c","""
        #import "local","syscall3" as "syscall3"
        int open(char * path, int oflag, int mode) 
        {
            int i;
            i = syscall3(5, path, oflag, mode);
            return i;
        }
        """)

        self.localfunctions["unlink"]=("c","""
        #import "local","syscall1" as "syscall1"
        int unlink(char * path) 
        {
            int i;
            i = syscall1(10, path);
            return i;
        }
        """)
        
        
        # a bit like popen
        self.localfunctions["fexec"]=("c","""
        #import "local","syscall" as "syscall"
        int fexec(char *command) {
           
        }
        
        """)
        
        self.localfunctions["write"]=("c","""
        #import "local","syscall3" as "syscall3"
        int write(int fildes, char * buf,  int nbyte)
        {
          int i;
          i = syscall3(4, fildes, buf, nbyte);
          return i;
        }
        """)
        
        self.localfunctions["poll"]=("c","""
        #import "local","syscall3" as "syscall3"
               struct pollfd {
                       int fd;           
                       short events;     
                       short revents;    
               };

        int poll(struct pollfd *ufds, int nfds, int timeout)
        {
          int i;
          i = syscall3(230, ufds, nfds, timeout);
          return i;
        }
        """)        

        self.localfunctions["read"]=("c","""
        #import "local","syscall3" as "syscall3"
        int read(int fildes, char * buf, int nbyte)
        {
          int i;
          i = syscall3(3, fildes, buf, nbyte);
          return i;
        }
        """)        
        
        
        self.localfunctions["connect"]=("c","""
        #include "socket.h"
        #import "local", "syscall3" as "syscall3"
        int connect(int s, struct sockaddr *name, int namelen)
        {
          int i;
          i = syscall3(98, s, name, namelen);
          return i;
        }
        
        """)

        self.localfunctions["recvfrom"]=("c","""
        #include "socket.h"
        #import "local", "syscall6" as "syscall6"
        int recvfrom(int s, char * buf, int len, int flags, char *sockaddr, int *fromlen)
        {
          int i;
          i = syscall6(29, s, buf, len, flags, sockaddr, fromlen);
          return i;
        }
        
        """)
        
        self.localfunctions["recv"]=("c","""
        #include "socket.h"
        #import "local", "recvfrom" as "recvfrom"
        int recv(int s, char * buf, int len, int flags)
        {
          int i;
          i = recvfrom(s, buf, len, flags, 0, 0);
          return i;
        }
        
        """)

         
        self.localfunctions["bind"]=("c","""
        #include "socket.h"
        #import "local", "syscall3" as "syscall3"
        int bind(int s, struct sockaddr * name, int * namelen)
        {
          int i;
          i = syscall3(104, s, name, namelen);
          return i;
        }
        
        """)

        self.localfunctions["sendto"]=("c","""
        #include "socket.h"
        #import "local", "syscall6" as "syscall6"
        int sendto(int s, char * buf, int len, int flags, char *sockaddr, int *fromlen)
        {
          int i;
          i = syscall6(133, s, buf, len, flags, sockaddr, fromlen);
          return i;
        }
        
        """)
        
        self.localfunctions["send"]=("c","""
        #import "local", "sendto" as "sendto"
        int send(int s, char * buf, int len, int flags)
        {
          int i;
          i = sendto( s, buf, len, flags, 0x0, 0x0);
          return i;
        }
        """)
        
        self.localfunctions["listen"]=("c","""
        #include "socket.h"
        #import "local", "syscall3" as "syscall3"
        int listen(int s, int backlog)
        {
          int i;
          i = syscall3(106, s, backlog, 0);
          return i;
        }
        
        """)

        self.localfunctions["accept"]=("c","""
        #include "socket.h"
        #import "local", "syscallE3" as "syscallE3"
        int accept(int s, struct sockaddr *addr, int * addrlen)
        {
          int i;
          i = syscallE3(30, s, addr, addrlen);
          return i;
        }
        
        """)
        
        # SYS_so_socket ! MIGHT CHANGE !

        # uses so_socket internally so we need to fill in 
        # so_socket(AF_INET, SOCK_STREAM, IPPROTO_IP, "", SOV_DEFAULT)

        self.localfunctions["socket"]=("c","""
        #import "local","syscall3" as "syscall3"
        int socket(int domain, int type, int protocol)
        {
         int i;
         i = syscall3(97, domain, type, protocol);
         return i;
        }
        """)
        
        self.localfunctions["execve"]=("c","""
        #import "local","syscall3" as "syscall3"
        int execve(char * filename, char **argv, char **envp)
        {
          int i;
          i = syscall3(59, filename, argv, envp);
          return i;
        }
        """)        

        
        #
        #end syscalls, begin libc functions
        #
        self.localfunctions["htons"]=("c","""
        int htons(unsigned short int port) {
        unsigned short ret;
        unsigned short ret2;
        ret=port & 0xff;
        ret=ret << 8;
        ret2=port & 0xff00;
        ret2=ret2 >> 8;
        ret=ret+ret2;
        return ret;
        }
        """)
                                      
        self.localfunctions["htonl"]=("c","""
        #import "local", "debug" as "debug"
        int htonl(unsigned int port) {
        unsigned int ret;
        unsigned int ret2;
        unsigned int ret3;
        unsigned int ret4;
        //debug();
        //ret=4;
        ret=port & 0x000000ff;
        ret=ret << 24;
        
        ret2=port & 0x0000ff00;
        ret2=ret2 << 8;

        ret3=port & 0x00ff0000;
        ret3=ret3 >> 8;

        ret4=port & 0xff000000;
        ret4=ret4 >> 24;

        ret=ret+ret2+ret3+ret4;
        return ret;
        }
        """)
         
        self.localfunctions["strlen"]=("c","""
        int strlen(char *instr) {
         int i;
         char * p;
         i=0;
         p=instr;
         while (*p!=0) {
          p=p+1;
          i=i+1;
         }
         return i;
        }
        """)
   
        
         
        self.localfunctions["strcpy"]=("c","""
        int strcpy(char * outstr, char *instr) {
         int i;
         char * p;
         char * y;
         char c;
         i=0;
         p=instr;
         y=outstr;
         while (*p!=0) {
          c=*p;
          *y=c;
          y=y+1;
          p=p+1;
          i=i+1;
         }
         *y=0;
         return i;
        }
        """)
   
        
        self.localfunctions["memset"]=("c","""
        int memset(char * instr,int outbyte, int size) {
         int i;
         char *p;
         
         i=0;
         p=instr;
         while (i<size) {
          i=i+1;
          *p=outbyte;
          p=p+1;
         }
         return i;
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
        #import "local","writeblock" as "writeblock"
        #import "local","strlen" as "strlen"
        #import "local","sendint" as "sendint"
        
        int sendblock2self(char * buf, int size) {
          sendint(size);
          writeblock(FD,buf,size);
        }
        """
        code=code.replace("FD",str(self.fd))
        self.localfunctions["sendblock2self"]=("c",code)
        
        code="""
        #import "local","writeblock" as "writeblock"
        #import "local","strlen" as "strlen"
        #import "local","sendint" as "sendint"
        
        int writeblock2self(char * buf, int size) {
          writeblock(FD,buf,size);
        }
        """
        code=code.replace("FD",str(self.fd))
        self.localfunctions["writeblock2self"]=("c",code)
        
        self.localfunctions["writestring"]=("c","""
        #import "local","sendblock" as "sendblock"
        #import "local","strlen" as "strlen"
        int writestring(int fd, char * outstr) {
         sendblock(fd,outstr,strlen(outstr));
        }
        """)
        
        #our reliable reading function
        self.localfunctions["readblock"]=("c","""
        #import "local","read" as "read"
        #import "local","strlen" as "strlen"
        int readblock(int fd, char * outstr,int size) {
          int left;
          int i;
          char * p;
          left=size;
          p=outstr;
          while (left > 0) {
            i=read(fd,p,left);
            if (i<0) {
              return 0;
            }
            left=left-i;
            p=p+i;
          }
         return 1; 
        }
        """)
        
        
        #our reliable writing function
        self.localfunctions["writeblock"]=("c","""
        #import "local","write" as "write"
        int writeblock(int fd, char * instr,int size) {
          int left;
          int i;
          char * p;
          left=size;
          p=instr;
          while (left > 0) {
            i=write(fd,p,left);
            if (i<0) {
              return 0;
            }
            left=left-i;
            p=p+i;
          }
         return 1; 
        }
        """)

        self.localfunctions["sendshort"]=("c","""
        #import "local","writeblock" as "writeblock"
        void sendshort(short tosend)
        {
           short i;
           i=tosend;
           writeblock(SOCKETFD, &i,2);
        }
        """.replace("SOCKETFD",str(self.fd)))

    def BYE_clearfunctioncache(self):

        self.compilelock.acquire()
        self.functioncache={}
        #self.compilelock.release()
        return

    
    def getlocal(self,name,importedlocals):
        """
        Returns a function which will get included 
        in the remote shellcode as a library call
        
        Needs to return code as IL
        """
        #print "Getting local: %s"%name

        if name in self.functioncache.keys() and self.localfunctions[name][0]!="header":
            if self.compilelibc:
                return "", self.functioncache[name]
            else:
                return "",""

        suffix=""
        suffixtype=self.localfunctions[name][0]
        suffixcode=self.localfunctions[name][1]
        
        if suffixtype=="IL":
            #don't assemble into IL before passing it back
            suffix=suffixcode
        elif suffixtype=="asm":
            #change to IL before returning
            for line in suffixcode.split("\n"):
                suffix+="asm %s\n"%line
        elif suffixtype=="c":
            #we need to change this to IL as well
            suffix=self.compile_to_IL(suffixcode,importedlocals)
        elif suffixtype=="header":
            suffix=self.gettypes(suffixcode)
        else:
            print "Didn't recognize suffix type: %s"%suffixtype

        self.functioncache[name]= suffix
        return "",suffix
    
    def BYE_compile_to_IL(self,code,imported):
        """compiles it into something useful"""
        import mosdef
        vars={}
        ret="\n"+mosdef.compile_to_IL(code,vars,self,imported=imported)+"\n"
        return ret
    
    def BYE_compile_to_ASM(self, ilcode):
        import il2ppc
        return il2ppc.generate(ilcode)
    
    def BYE_gettypes(self,code):
        """called on header files to get the types defined within"""
        import mosdef
        ret=mosdef.getCtypes(code,self)
        return ret
    
    def BYE_compile(self,code,vars, imported=None):
        """
        Compiles the code, linking in the remote addresses when necessary
        """
        #print "Compiling code: %s"%code
        import mosdef
        unit=code+str(vars)
        #print "unit=%s"%unit
        if unit in self.localcache:
            ret=self.localcache[unit]
            self.compilelock.release()            
            return ret
        
        #self.compilelock.acquire()
        #imported is none, because we are not recursive yet
        ret=mosdef.compile(code,self.arch,vars,self, imported)
        self.compilelock.release()
        if len(self.localcache.keys())>MAXCACHESIZE:
            self.localcache={} #reset
        self.localcache[unit]=ret #add it to our cache
        
        #debug line
        #print "Compiled to %d bytes"%len(ret)
        return ret

    
    #Remote MOSDEF libc working.
                                                                           
    #Basically, at startup() we call: createRemoteLibc() on remoteresolver.
    #(createRemoteLibc is a generic function, it can pretty much work on any
     #+*nix, so probably im gonna move it into shellsever)
                                                                           
    #createRemoteLibc loop over localfunctions (MOSDEF's libc) and compile 
     #every piece of code into opcode (asm or C), that is putted into a bug
     #buffer.
     #Once this is ready, we mmap some space and send the buf to the remote
     #host. The remotefunctioncache is filled with "libc!function_name".
                                                                           
     #So, at any time on our code we can do a
     ##import "remote", "libc!getuid" as "getuid"
     #and we will be using remote libc, saving a lot of bandwidth:
                                                                           
     #Some stats, just on OSX startup there is a difference of 9108 bytes
     #(findHost and findInterface) and so on. I expecting this will speed up
      #bouncing.
                                                                           
      #Also, if anyone want to port to his architecture, keep in mind that you
      #will (at least) need:
        #if func in self.remotefunctioncache:
            ##print "Found: returning."
            #return self.remotefunctioncache[func]
                                                                           
      #on getremote (even tho, you dont have a dlsym shellcode).

      # The only needed functions to make this function work is:
      #     def mmap(self, addr=0, needed=0, prot = 7, flags= 0x1002, fd=-1, offset=0):
      #     def remoterecv(self, fd, buf, length, request_buf):
      #  on *MosdefShellServer
      #
      #  and obviously, call createRemoteLibc() at startup()
    
    def createRemoteLibc(self):
          ndx = 0
          libc=[]
          libc_buffer = []
          import mosdef
          BASE_ADDRESS = 0x60400000L  # just some random address that we expect not 
                                      # to be remotely mmaped
                                                
          self.compilelibc = 1
          for ke in self.localfunctions.keys():
               suffixtype = self.localfunctions[ke][0]
               suffixcode = self.localfunctions[ke][1]
               if suffixtype=="asm":
                    buf=mosdef.assemble(suffixcode, self.arch)
                    
               elif suffixtype == "c":
                    code = "jump %s\n" % ke 
                    code+= mosdef.compile_to_IL(suffixcode,{}, self,  None, not_libc=0)
                                        
                    code = self.compile_to_ASM(code)
                    
                    buf = mosdef.assemble(code, self.arch)

                    # IMPORTANT: never forget to clearfunctioncache
               else:
                    continue

               libc.append("libc!"+ke)
               self.remotefunctioncache["libc!" + ke] = ndx + BASE_ADDRESS
               libc_buffer.append( buf )
               ndx+=len(buf)
          
          self.clearfunctioncache()
                    
          self.compilelibc = 0
          libc_buffer = "".join(libc_buffer)
          
          # mapping the libc
          self.log("Remote libc size: 0x%08x" % ndx)
          ret = self.mmap(addr = BASE_ADDRESS, needed = ndx)
          if ret == 0xFFFFFFFFL:
               raise Exception, "Failed to mmap libc at address 0x%08x with size: %d" % (BASE_ADDRESS, ndx)

          self.remoterecv( self.fd, ret, ndx, libc_buffer)
          
          self.log("MOSDEF libc mapped at address: 0x%08x" % ret)

          # Instead of patching, everything, i can try to mmap at a know address,
          # in case it doesn't work, i can re patch with the given address.

          if ret != BASE_ADDRESS:
               self.log("Repatching the remotelibc")
               for ke in libc:
                    self.remotefunctioncache[ke] = self.remotefunctioncache[ke] - BASE_ADDRESS + ret
    


# intel specific functions
class x64osxremoteresolver(osxremoteresolver, unixremoteresolver):
    def __init__(self, proc='x64', version='10.6'):
        osxremoteresolver.__init__(self, 'x64', version)
        unixremoteresolver.__init__(self)
        
        self.remoteFunctionsUsed = {}
        self.remotefunctioncache = {}
    
    def initLocalFunctions(self):
        osxremoteresolver.initLocalFunctions(self)

        # pipe returns in eax and edx
        self.localfunctions['pipe'] = ('asm', """
        pipe:
          pushq %rbp
          movq %rsp,%rbp
          and $0xfffffffffffffff0,%rsp
          movq $SYSNUM,%rax
          syscall
          test %rax,%rax
          jb pipe_error
          movq 16(%rbp),%rdi
          movl %eax,(%rdi)
          movl %edx,4(%rdi)
          xor %rax,%rax
        pipe_error:
          movq %rax,%r13
          movq %rbp,%rsp
          popq %rbp
          ret
        """.replace("SYSNUM", str(self.libc.getdefine('SYS_pipe')+0x2000000)) )
        
        # fork on XNU has pid in eax, and parent flag in edx: 0 == parent, 1 == child
        self.localfunctions['fork'] = ('asm', """
        fork:
          pushq %rbp
          movq %rsp,%rbp
          and $0xfffffffffffffff0,%rsp
          movq $SYSNUM,%rax
          syscall
          test %rdx,%rdx
          jz parent
          xor %rax,%rax // zero out ret if we're child
        parent:
          movq %rax,%r13
          movq %rbp,%rsp
          popq %rbp
          ret
        """.replace("SYSNUM",str(self.libc.getdefine('SYS_fork')+0x2000000)) )

        
        self.localfunctions['sendpointer'] = ("c", """
        #import "local", "sendlonglong" as "sendlonglong"
        void sendpointer(unsigned long long ptr)
        {
            sendlonglong(ptr);
        }
        """)

        self.localfunctions['resolve'] = ("asm", """
        resolve:
        pushq	%rbp
        movq	%rsp, %rbp
        pushq	%r14
        pushq	%r12
        pushq	%rbx
        
        movq    24(%rbp), %r14
        movq    32(%rbp), %rdi

        movq    %r14, %rax
        addl    $0x10, %rax
        movl	(%rax), %r8d
        movq    %r14, %rsi
        addl    $0x20, %rsi
        xorl	%ebx, %ebx
        xorl	%r12d, %r12d

        jmp	L2
L3:
        movl	(%rsi), %eax
        cmpl	$25, %eax
        jne	L4
        movl	10(%rsi), %eax
        cmpl	$1415071060, %eax
        jne	L6
        movq	24(%rsi), %rbx
        jmp	L8
L6:
        cmpl	$1263421772, %eax
        jne	L8
        movq	24(%rsi), %rax
        movq	40(%rsi), %rdx
        test	%rbx, %rbx
        je	L10
        subq	%rbx, %rax
        pushq   %rax
        addq    %r14, %rax
        movq	%rax, %r12
        popq    %rax
        subq	%rdx, %r12
        jmp	L8
L4:
        cmpl	$2, %eax
        jne	L8
        movl	12(%rsi), %r9d
        test    %r9d, %r9d
        je	L10
        movl	%r9d, %eax
        imul	$16, %eax
        cltq
        pushq   %rax
        subq    $0x10, %rax
        addq    %r12, %rax
        movq	%rax, %r10
        popq    %rax
        
        movq	%r14, %rdi
        subq	%rbx, %rdi
        jmp	L14
L15:
        pushq   %rdx
        movl    8(%rsi), %edx
        xor     %rax, %rax
        cmpl    $0, %edx
        jge     POS
        movq    $0xFFFFFFFF, %rax
        shl     $32, %rax
POS:
        movl    %edx, %eax
        popq    %rdx
        addq    %r10, %rax
        
        movq	%rdi, %r11
        add	8(%rax), %r11
        movl	(%rax), %edx
        movl	16(%rsi), %eax
        test	%r13, %r13
        je	L16
        addq    %rdx, %rax
        cltq
        addq	%r12, %rax
        movq	%r13, %rcx
        jmp	L18
L19:
        test	%dl, %dl
        je	L20
        inc	%rcx
        inc	%rax
L18:
        pushq   %rax
        movq    (%rcx), %rax
        xorl    %edx, %edx
        movb    %al, %dl
        popq    %rax
        cmpb	(%rax), %dl
        je	L19
L16:
        dec	%r9d
        subq	$16, %r10
L14:
        test	%r9d, %r9d
        jg	L15
L8:
        pushq   %rdx
        movl    4(%rsi), %edx
        xor     %rax, %rax
        cmpl    $0, %edx
        jge     POS2
        movq    $0xFFFFFFFF, %rax
        shl     $32, %rax
POS2:
        movl    %edx, %eax
        popq    %rdx
        add	%rax, %rsi
        dec   	%r8d
L2:
        test	%r8d, %r8d
        jg	L3
L10:
        xorl	%r11d, %r11d
L20:
        movq	%r11, %rax
        movq    %r11, %r13
        
        popq	%rbx
        popq	%r12
        popq	%r14
        leave
        ret
        """)
        
        self.localfunctions['dlopen'] = ("c", """
        #import "remote64", "_dlopen" as "_dlopen"
        void *dlopen(char *library)
        {
            void *ret;

            ret = _dlopen(library, 1); // RTLD_LAZY
            return ret;
        }
        """)

        self.localfunctions['dlsym'] = ("c", """
        #import "remote64", "_dlsym" as "_dlsym"
        void *dlsym(void *handle, char *symbol)
        {
            void *ret;

            if (handle == NULL) {
                ret = _dlsym(-2, symbol); // RTLD_DEFAULT
            } else {
                ret = _dlsym(handle, symbol);
            }

            return ret;
        }
        """)
