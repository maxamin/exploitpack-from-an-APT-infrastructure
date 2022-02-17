#! /usr/bin/env python

"""
the xBSD remote resolver. A kind of combination of libc and a few other things...
"""

MAXCACHESIZE=1000

from remoteresolver import remoteresolver

class bsdremoteresolver(remoteresolver):
    """
    Our remote resolver for x86 *BSD
    """

    def __init__(self, proc, version = '5.2'):
        remoteresolver.__init__(self, 'BSD', proc, version)

    def initLocalFunctions(self):
        self.functioncache={}

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

          unsigned long st_atime;
          unsigned long st_atimeensec;
          unsigned long st_mtime;
          unsigned long st_mtimeensec;
          unsigned long st_ctime;
          unsigned long st_ctimeensec;

          unsigned long st_size;
          unsigned long st_size_high;
          unsigned long st_blocks;
          unsigned long st_blocks_high;

          unsigned long st_blksize;
          unsigned long st_flags;
          unsigned long st_gen;
          unsigned long st_lspare;

          unsigned long st_birthtime;
          unsigned long st_birthtimeensec;

          unsigned long __unused1;
          unsigned long __unused2;
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
             unsigned int addr; //sin_addr, whatever.
             char pad[6];
           };
        """)

        self.localfunctions["fstat"]=("c","""
        #import "local","syscall2" as "syscall2"
        #include "fstat.h"
        //#import "local","debug" as "debug"
        int
        fstat(int fd, struct stat *buf) {
        int i;
        //debug();
        i=syscall2(189,fd,buf);
        return i;
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
   
        self.localfunctions["FD_ZERO"]=("c","""
        #import "local", "memset" as "memset"
        int 
        FD_ZERO(int *fd_set) {
           memset(fd_set,0,128);
           return 1;
        }
        """)

        self.localfunctions["FD_SET"]=("c","""
        #import "local", "memset" as "memset"
        void
        FD_SET(int fd, int *fd_set) {
           int index;
           int flag;
           int *p;
           int bucket;
           int oldvalue;
           int newvalue;
           
           flag=0;
           index=fd%32;
           index=32-index;
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
        
        
        #a reliable send function
        self.localfunctions["senddatatoself"]=("c","""
    #import "local","syscall6" as "syscall6"
    int senddatatoself(char * data, int length) {
        int i;
        int flags;
        int tosend;
        char * dataptr;
        
        flags=0;
        tosend=length;
        dataptr=data;
        //sys_sendto 0x85
        while (tosend>0) {
           //call sendto
           i=syscall6(0x85,FDVAL,dataptr,tosend,flags,0,0);
           if (i==-1) {
             //some kind of error. 
             tosend=0;
           } else {
             tosend=tosend-i;
             dataptr=dataptr+i;
           }
           
        } //end while loop
        
    } //end function
        """.replace("FDVAL",str(self.fd)))

        #(type,code)
        self.localfunctions["sendint"]=("c","""
        #import "local","senddatatoself" as "senddatatoself"
        
        int 
        sendint(int myint) {
        int i;
        i=myint;
        i=senddatatoself(&i,4);
        return i;
        }
        """)

        #print "Initialized sendint with fd=%s"%self.fd
        
        self.localfunctions["sendstring"]=("c","""
        #import "local","senddatatoself" as "senddatatoself"
        #import "local","sendint" as "sendint"
        #import "local","strlen" as "strlen"
        void sendstring(char * instr) {
         int i;
         i=strlen(instr);
         sendint(i); //block header
         senddatatoself(instr,i); //block body
        }
        """)
        
        
        self.localfunctions["chdir"]=("c","""
        #import "local","syscall1" as "syscall1"
        //#import "local","debug" as "debug"
        int
        chdir(char * dir) {
        int i;
        //debug();
        i=syscall1(12,dir);
        return i;
        }
   
        """)
        
        self.localfunctions["getcwd"]=("c","""
        #import "local","syscall2" as "syscall2"
        int getcwd(char * dest, int size) {
            int i;
            i=syscall2(326,dest,size);
            return i;
        }
        
        """);
        
        #/usr/include/asm/unistd.h:#define __NR_pipe              42
        self.localfunctions["pipe"]=("c","""
        #import "local","syscall1_2rets" as "syscall1_2rets"
        int pipe(char * dest) {
            int i;
            i=syscall1_2rets(42,dest);
            return i;
        }
        
        """)
        
        self.localfunctions["ioctl"]=("c","""
        #import "local","syscall3" as "syscall3"
        int ioctl(int sock, int method, char * buffer) {
            int i;
            i=syscall3(54,sock,method,buffer);
            return i;
        }
        """)
                          
   
        self.localfunctions["sysctl"]=("c","""
        #import "local", "syscall6" as "syscall6"
        int sysctl(int *mib,int size,char * obuf,int *obuflen,char *nbuf, int* nbuflen) {
           int i;
           i=syscall6(0xca,mib,size,obuf,obuflen,nbuf,nbuflen);
           return i;
        }
        """)
        
        self.localfunctions["fcntl"]=("c","""
        #import "local","syscall3" as "syscall3"
        int fcntl(int sock, int method, long arg) {
            int i;
            i=syscall3(92,sock,method,arg);
            return i;
        }
        """)
        
        self.localfunctions["setsockopt"]=("c","""
       #import "local", "syscall5" as "syscall5"
        int setsockopt(int sock, int level, int arg, int value)
        {
          int i;
          i=value;
          i=syscall5(105,sock,level,arg,&i,4);
          return i;
        }
        """)

        self.localfunctions["dup2"]=("c","""
        #import "local","syscall2" as "syscall2"
        int dup2(int src, int dest) {
            int i;
            i=syscall2(90,src,dest);
            return i;
        }
        """)
        self.localfunctions["close"]=("c","""
        #import "local","syscall1" as "syscall1"
        int close(char * dest) {
            int i;
            i=syscall1(6,dest);
            return i;
        }
        """)
        
        self.localfunctions["signal"]=("c","""
        #import "local","syscall3" as "syscall3"
        struct sigaction_str {
           int sigfunc;
           int flags;
           int mask;
        };
        
        int signal(int signum, unsigned int sighandler)
        {
          int i;
          //this is really sigaction
          struct sigaction_str action;
          action.sigfunc=sighandler;
          action.flags=0;
          action.mask=0;
          //call sigaction
          i=syscall3(0x1a0,signum,&action,0);
          return i;
        }
        """)
        
        self.localfunctions["waitpid"]=("c","""
        #import "local","syscall4" as "syscall4"
        int waitpid(int pid, int * status, int options)
        {
          int i;
          //wait4 system call
          i=syscall4(7,pid,status,options,0);
          return i;
        }
        """)
        
        
        self.localfunctions["exit"]=("c","""
        #import "local","syscall1" as "syscall1"
        int exit(char * dest) {
            int i;
            i=syscall1(1,dest);
            return i;
        }
        """)

        
        self.localfunctions["getpid"]=("c","""
        #import "local","syscall1" as "syscall1"
        int getpid(char * dest) {
            int i;
            i=syscall1(20,dest);
            return i;
        }
        """)
        
        
        self.localfunctions["getppid"]=("c","""
        #import "local","syscall1" as "syscall1"
        int getppid(char * dest) {
            int i;
            i=syscall1(39,dest);
            return i;
        }
        """)
        
        
        self.localfunctions["getpgrp"]=("c","""
        #import "local","syscall0" as "syscall0"
        int getpgrp() {
            int i;
            i=syscall0(81);
            return i;
        }
        """)
        
        
        self.localfunctions["getuid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int getuid() {
            int i;
            i=syscall0(24);
            return i;
        }
        """)

        self.localfunctions["geteuid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int geteuid() {
            int i;
            i=syscall0(25);
            return i;
        }
        """)
        
        self.localfunctions["setuid"]=("c","""
        #import "local","syscall1" as "syscall1"
        int setuid(int uid) {
            int i;
            i=syscall1(23,uid);
            return i;
        }
        """)

        self.localfunctions["seteuid"]=("c","""
        #import "local","syscall3" as "syscall3"
        int seteuid(int uid) {
            int i;
            i=syscall1(25,uid);
            return i;
        }
        """)

        self.localfunctions["setreuid"]=("c","""
        #import "local","syscall2" as "syscall2"
        int seteuid(int ruid,int euid) {
            int i;
            i=syscall2(0x7e,ruid,euid);
            return i;
        }
        """)
        
        self.localfunctions["setegid"]=("c","""
        #import "local","syscall1" as "syscall1"
        int setegid(int gid) {
            int i;
            i=syscall1(182,gid);
            return i;
        }
        """)
        
        self.localfunctions["setgid"]=("c","""
        #import "local","syscall1" as "syscall1"
        int setgid(int gid) {
            int i;
            i=syscall1(181,gid);
            return i;
        }
        """)
        
        self.localfunctions["getgid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int getgid() {
            int i;
            i=syscall0(47);
            return i;
        }
        """)
        
        
        self.localfunctions["getegid"]=("c","""
        #import "local","syscall0" as "syscall0"
        int getegid() {
            int i;
            i=syscall0(43);
            return i;
        }
        """)
        
        self.localfunctions["fork"]=("c","""
        #import "local","syscall0" as "syscall0"
        int fork() {
            int i;
            i=syscall0(2);
            return i;
        }
        """)
        
        self.localfunctions["open"]=("c","""
        #import "local","syscall3" as "syscall3"
        int open(char * pathname,int flags, int mode) {
            int i;
            i=syscall3(5,pathname,flags, mode);
            return i;
        }
        """)
        
        # a bit like popen
        self.localfunctions["fexec"]=("c","""
        #import "local","syscall0" as "syscall0"
        int fexec(char *command) {
        //not done yet   
        }
        
        """)
        
        self.localfunctions["write"]=("c","""
        #import "local","syscall3" as "syscall3"
        int write(int fd, char * buf,  int count)
        {
          int i;
          i=syscall3(4,fd,buf,count);
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
          i=syscall3(209, ufds, nfds, timeout);
          return i;
        }
        """)        

        self.localfunctions["read"]=("c","""
        #import "local","syscall3" as "syscall3"
        int read(int fd, char * buf, int count)
        {
          int i;
          i=syscall3(3, fd, buf, count);
          return i;
        }
        """)        
        
                
        self.localfunctions["getsockopt"]=("c","""
        #include "socket.h"
        #import "local", "syscall5" as "syscall5"
        int getsockopt(int s, int level, int optname, char *optval, char *optlen)
        {
          int i;
          i=syscall5(118, s, level, optname, optval, optlen);
          return i;
        }
        
        """)

        self.localfunctions["connect"]=("c","""
        #include "socket.h"
        #import "local", "syscall3" as "syscall3"
        int connect(int fd, struct sockaddr *serv_addr, int length)
        {
          int i;
          i=syscall3(98,fd,serv_addr,length);
          return i;
        }
        
        """)

        
        
        self.localfunctions["recv"]=("c","""
        #include "socket.h"
        #import "local", "syscall6" as "syscall6"
        int recv(int fd, char * buf, int length, int flags)
        {
          int i;
          i=syscall6(29,fd,buf,length,flags,0,0);
          return i;
        }
        
        """)

        
        self.localfunctions["bind"]=("c","""
        #include "socket.h"
        #import "local", "syscall3" as "syscall3"
        int bind(int fd, struct sockaddr *serv_addr, int length)
        {
          int i;
          i=syscall3(104,fd,serv_addr,length);
          return i;
        }
        
        """)
        
        self.localfunctions["send"]=("c","""
        #import "local", "syscall6" as "syscall6"
        int send(int fd, char * buf, int len, int flags)
        {
          int i;
          i=syscall6(0x85,fd,buf,len,flags,0,0);
          return i;
        }
        """)
        
        self.localfunctions["listen"]=("c","""
        #include "socket.h"
        #import "local", "syscall2" as "syscall2"
        int listen(int fd, int backlog)
        {
          int i;
          i=syscall2(106,fd,backlog);
          return i;
        }
        
        """)

        self.localfunctions["accept"]=("c","""
        #include "socket.h"
        #import "local", "syscall3" as "syscall3"
        int accept(int fd, struct sockaddr *serv_addr, int *length)
        {
          int i;
          i=syscall3(30,fd,serv_addr,length);
          return i;
        }
        
        """)
        
        self.localfunctions["socket"]=("c","""
        #import "local","syscall3" as "syscall3"
        int socket(int domain, int type, int protocol)
        {
         int i;
         //SYS_socket 0x61
         i=syscall3(0x61,domain,type,protocol);
         return i;
        }
        """)
        
        self.localfunctions["execve"]=("c","""
        #import "local","syscall3" as "syscall3"
        int execve(char * filename, char **argv, char **envp)
        {
          int i;
          i=syscall3(59, filename, argv, envp);
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
   
        self.localfunctions["memcpy"]=("c","""
           int memcpy(char * outstr,char  * instr, int size) {
                   int i;
                   char *p;
                   char *p2;
                   char outbyte;
                   i=0;
                   p=instr;
                   p2=outstr;
                   while (i<size) {
                   i=i+1;
                   outbyte=*p;
                   *p2=outbyte;
                   p=p+1;
                   p2=p2+1;
                   }
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

class x86bsdremoteresolver(bsdremoteresolver):

    def __init__(self, proc='i386', version = '5.2'):
        bsdremoteresolver.__init__(self, 'i386', version)

    def initLocalFunctions(self):
        bsdremoteresolver.initLocalFunctions(self)

        self.localfunctions["debug"]=("asm","""
        debug:
        .byte 0xcc
        ret
        """)
        
        #######################################
        #SYSCALLS
        #######################################
        self.localfunctions["syscall0"]=("asm","""
        //syscall0(int syscallnum)
        syscall0:
        push %ebp
        mov %esp, %ebp
        push %ebx //save

        movl 8(%ebp), %eax //syscall number
        push %eax //dummy
        int $0x80
        jb syscall0_errno
        jmp syscall0_done

        // patching out, but keeping -1 ret behavior in case we rely on it
        // XXX: this whole shellserver should be redone from scratch
        syscall0_errno: 
        //push %edi //save off
        //mov %eax, %edi //save off errno
        //mov %esp, %eax
        //orl $0xffff, %eax
        //sub $4, %eax
        //mov %edi, (%eax) //put this as the top dword in our stack
        //pop %edi //restore
        mov $-1,%eax

        syscall0_done:
        add $4, %esp //return from system call arguments...
        pop %ebx //restore
        mov %ebp, %esp
        pop %ebp
        ret $4 //clear args and return       
        
        """)
        
        
        self.localfunctions["syscall1_2rets"]=("asm","""
        //syscall1_2rets(syscallnum,int ret[2]);
        //pipe() returns its arguments in eax and edx, for example
        //this acts like syscall0 a bit
        syscall1_2rets:
        //.byte 0xcc
        push %ebp
        mov %esp, %ebp
        push %ebx //save
        push %edx //save
   
        //movl 12(%ebp), %eax
        //pushl %eax
        movl 8(%ebp), %eax //syscall number
        pushl %eax //dummy
        int $0x80
        jb syscall1_2rets_errno
        //else, we succeeded, so lets manually do that arg
        movl 12(%ebp), %ebx //ret is loaded
        movl %eax, (%ebx)
        movl %edx, 4(%ebx)
        jmp syscall1_2rets_done

        // patching out, but keeping -1 ret behavior in case we rely on it
        // XXX: this whole shellserver should be redone from scratch
        syscall1_2rets_errno: 
        //push %edi //save off
        //mov %eax, %edi //save off errno
        //mov %esp, %eax
        //orl $0xffff, %eax
        //sub $4, %eax
        //mov %edi, (%eax) //put this as the top dword in our stack
        //pop %edi //restore
        mov $-1,%eax

        syscall1_2rets_done:
        add $4, %esp //return from system call arguments...
        pop %edx //restore since system call clobbers it
        pop %ebx //restore
        mov %ebp, %esp
        pop %ebp
        ret $8 //clear args and return               
        
        """)
        self.localfunctions["syscall1"]=("asm","""
        //syscall1(int syscallnum, void *arg)
        syscall1:
        push %ebp
        mov %esp, %ebp
        push %ebx //save

        movl 12(%ebp), %eax
        pushl %eax
        movl 8(%ebp), %eax //syscall number
        push %eax //dummy
        int $0x80
        jb syscall1_errno
        jmp syscall1_done

        // patching out, but keeping -1 ret behavior in case we rely on it
        // XXX: this whole shellserver should be redone from scratch
        syscall1_errno: 
        //push %edi //save off
        //mov %eax, %edi //save off errno
        //mov %esp, %eax
        //orl $0xffff, %eax
        //sub $4, %eax
        //mov %edi, (%eax) //put this as the top dword in our stack
        //pop %edi //restore
        mov $-1,%eax

        syscall1_done:
        addl $8, %esp //return from system call arguments...
        pop %ebx //restore
        mov %ebp, %esp
        pop %ebp
        ret $8 //clear args and return               
        """)

        self.localfunctions["syscall2"]=("asm","""
       // syscall2(syscallnum,arg,arg)
        syscall2:
        push %ebp
        mov %esp, %ebp
        push %ebx //save

        movl 16(%ebp), %eax
        pushl %eax
        movl 12(%ebp), %eax
        pushl %eax
        movl 8(%ebp), %eax //syscall number
        push %eax //dummy
        int $0x80
        jb syscall2_errno
        jmp syscall2_done

        // patching out, but keeping -1 ret behavior in case we rely on it
        // XXX: this whole shellserver should be redone from scratch
        syscall2_errno: 
        //push %edi //save off
        //mov %eax, %edi //save off errno
        //mov %esp, %eax
        //orl $0xffff, %eax
        //sub $4, %eax
        //mov %edi, (%eax) //put this as the top dword in our stack
        //mov $-1, %eax
        //pop %edi //restore
        mov $-1,%eax

        syscall2_done:
        add $12, %esp //return from system call arguments...
        pop %ebx //restore
        mov %ebp, %esp
        pop %ebp
        ret $12//clear args and return   
        """)
        
        
        self.localfunctions["syscall3"]=("asm","""
        
        syscall3:
        //.byte 0xcc
        push %ebp
        mov %esp, %ebp
        push %ebx //save

        movl 20(%ebp), %eax
        pushl %eax
        movl 16(%ebp), %eax
        pushl %eax
        movl 12(%ebp), %eax
        pushl %eax
        
        push %eax //dummy
        movl 8(%ebp), %eax //syscall number
        int $0x80
        //.byte 0xcc
        jb syscall3_errno
        jmp syscall3_done

        // patching out, but keeping -1 ret behavior in case we rely on it
        // XXX: this whole shellserver should be redone from scratch
        syscall3_errno: 
        //push %edi //save off
        //mov %eax, %edi //save off errno
        //mov %esp, %eax
        //orl $0xffff, %eax
        //sub $4, %eax
        //mov %edi, (%eax) //put this as the top dword in our stack
        //pop %edi //restore
        mov $-1,%eax

        syscall3_done:
        add $16, %esp //return from system call arguments...
        pop %ebx //restore
        mov %ebp, %esp
        pop %ebp
        ret $16 //clear args and return
        
        """)
        

        self.localfunctions["syscall4"]=("asm","""
        // syscall4(syscallnum,arg,arg,arg,arg)
        syscall4:
        push %ebp
        mov %esp, %ebp
        push %ebx //save

        movl 24(%ebp), %eax
        pushl %eax
        movl 20(%ebp), %eax
        pushl %eax
        movl 16(%ebp), %eax
        pushl %eax
        movl 12(%ebp), %eax
        pushl %eax
        movl 8(%ebp), %eax //syscall number
        push %eax //dummy
        int $0x80
        jb syscall4_errno
        jmp syscall4_done

        // patching out, but keeping -1 ret behavior in case we rely on it
        // XXX: this whole shellserver should be redone from scratch
        syscall4_errno: 
        //push %edi //save off
        //mov %eax, %edi //save off errno
        //mov %esp, %eax
        //orl $0xffff, %eax
        //sub $4, %eax
        //mov %edi, (%eax) //put this as the top dword in our stack
        //pop %edi //restore
        mov $-1, %eax

        syscall4_done:
        add $20, %esp //return from system call arguments...
        pop %ebx //restore
        mov %ebp, %esp
        pop %ebp
        ret $20 //clear args and return
        """)        

        self.localfunctions["syscall5"]=("asm","""
        // syscall6(syscallnum,arg,arg,arg,arg,arg,arg)
        syscall5:
        push %ebp
        mov %esp, %ebp
        push %ebx //save

        movl 28(%ebp), %eax
        pushl %eax
        movl 24(%ebp), %eax
        pushl %eax
        movl 20(%ebp), %eax
        pushl %eax
        movl 16(%ebp), %eax
        pushl %eax
        movl 12(%ebp), %eax
        pushl %eax
        movl 8(%ebp), %eax //syscall number
        push %eax //dummy
        int $0x80
        jb syscall5_errno
        jmp syscall5_done

        // patching out, but keeping -1 ret behavior in case we rely on it
        // XXX: this whole shellserver should be redone from scratch
        syscall5_errno: 
        //push %edi //save off
        //mov %eax, %edi //save off errno
        //mov %esp, %eax
        //orl $0xffff, %eax
        //sub $4, %eax
        //mov %edi, (%eax) //put this as the top dword in our stack
        //pop %edi //restore
        mov $-1, %eax

        syscall5_done:
        add $24, %esp //return from system call arguments...
        pop %ebx //restore
        mov %ebp, %esp
        pop %ebp
        ret $24 //clear args and return   
        """)        
        
        self.localfunctions["syscall6"]=("asm","""
        // syscall6(syscallnum,arg,arg,arg,arg,arg,arg)
        syscall6:
        push %ebp
        mov %esp, %ebp
        push %ebx //save

        movl 32(%ebp), %eax
        pushl %eax
        movl 28(%ebp), %eax
        pushl %eax
        movl 24(%ebp), %eax
        pushl %eax
        movl 20(%ebp), %eax
        pushl %eax
        movl 16(%ebp), %eax
        pushl %eax
        movl 12(%ebp), %eax
        pushl %eax
        movl 8(%ebp), %eax //syscall number
        push %eax //dummy
        int $0x80
        jb syscall6_errno
        jmp syscall6_done

        // patching out, but keeping -1 ret behavior in case we rely on it
        // XXX: this whole shellserver should be redone from scratch
        syscall6_errno: 
        //push %edi //save off
        //mov %eax, %edi //save off errno
        //mov %esp, %eax
        //orl $0xffff, %eax
        //sub $4, %eax
        //mov %edi, (%eax) //put this as the top dword in our stack
        //mov $-1, %eax
        //pop %edi //restore

        mov $-1,%eax

        syscall6_done:
        add $28, %esp //return from system call arguments...
        pop %ebx //restore
        mov %ebp, %esp
        pop %ebp
        ret $28 //clear args and return       
        """)        
        
        ##################################################
        #END OF SYSCALLS
        ##################################################        

        self.localfunctions["checkvm"]=("asm","""
            checkvm:
            xorl %eax,%eax
            subl $6,%esp
            sidt (%esp)
            movb 0x5(%esp),%al
            addl $6,%esp
            // jge 0xd0, 0xff --> vmware, 0xe8 virtual pc
            // from joanna's redpill thingy
            cmpb $0xd0,%al
            jg virtualmachine
            xorl %eax,%eax

            virtualmachine:
            // return value of !zero == virtualmachine
            ret
            """)

        
