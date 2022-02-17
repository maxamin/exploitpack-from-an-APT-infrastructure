#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
#
# vim: sw=4 ts=4 expandtab

from MLCutils import MLCutils
from C_headers import C_headers

class subC(MLCutils, C_headers):
    
    def __init__(self):
        # Warning: self.localfunctions could have be initialized before.
        # XXX where ? something weird here, since MLCutils is called after.
        if not hasattr(self, 'localfunctions'):
            self.localfunctions = {}
        if not hasattr(self, 'LP64'):
            self.LP64 = False
        MLCutils.__init__(self)
        C_headers.__init__(self)
        self._subC_initLocalFunctions()
    
    def init_shortcut_vars(self):
        if hasattr(self, 'O_NONBLOCK'):
            self.O_BLOCK = ~self.O_NONBLOCK
        if hasattr(self, 'S_IRWXU') and hasattr(self, 'S_IRWXG') and hasattr(self, 'S_IRWXO'):
            self.MODE_ALL = self.S_IRWXU|self.S_IRWXG|self.S_IRWXO
        # XXX <stdio.h>
        self.EOF = -1
    
    def _subC_initLocalFunctions(self):
        #print "subC_initLocalFunctions: %s"%(str(self.localfunctions.get("htons")))
        #############
        #
        #  string.h
        #
        #############
        
        self.localfunctions["memset"] = ("c", """
        int
        memset(char *outstr, int outbyte, int size)
        {
            int i;
            char *p;
            
            i = 0;
            p = outstr;
            while (i < size) {
                i = i + 1;
                *p = outbyte;
                p = p + 1;
            }
            
            return i;
        }
        """)

        self.localfunctions['memmove'] = ('c', """
        void *
        memmove(char *dst, char *src, int n)
        {
            char c;

            if (n == 0)
                return dst;

            if (dst == src)
                return dst;

            if (src < dst)
            {
                src = src + n;
                dst = dst + n;

                while (n != 0)
                {
                    n = n - 1;
                    dst = dst - 1;
                    src = src - 1;

                    c = *src;
                    *dst = c;
                }
            }
            else
            {
                while (n != 0)
                {
                    c = *src;
                    *dst = c;
                    
                    src = src + 1;
                    dst = dst + 1;
                    n = n - 1;
                }
            }
        }
        """)
        
        self.localfunctions["memcpy"] = ("c", """
        char *
        memcpy(char *dst, char *src, int size)
        {
            char c;
            char *ret;
            
            ret = dst;
            while (size > 0) {
                c = *src;
                *dst = c;
                src = src + 1;
                dst = dst + 1;
                size = size - 1;
            }
            
            return ret;
        }
        """)
        
        self.localfunctions["strlen"] = ("c", """
        int strlen(char *instr)
        {
            int i;
            char *p;
            
            i = 0;
            p = instr;
            while (*p != 0) {
                p = p + 1;
                i = i + 1;
            }
            
            return i;
        }
        """)

        self.localfunctions["strchr"] = ("c", """
        #include <string.h>

        char *strchr(char *s, int __c)
        {
                int length;
                char ch;
                char c;
                int i;

                c = __c;

                length = strlen(s);
                for (i = 0; i < length; i = i + 1) {
                        ch = s[i];

                        // Found it.
                        if (ch == c) {
                                return s + i;
                        }
                }

                return NULL;
        }
        """)

        self.localfunctions["strrchr"] = ("c", """
        #include <string.h>

        char *strrchr(char *s, int __c)
        {
                int length;
                char ch;
                char c;
                int i;

                c = __c;

                length = strlen(s);
                for (i = length - 1; i >= 0; i = i - 1) {
                        ch = s[i];

                        // Found it.
                        if (ch == c) {
                                return s + i;
                        }
                }

                return NULL;
        }
        """)
        
        self.localfunctions["strcpy"] = ("c", """
        int strcpy(char *outstr, char *instr)
        {
            int i;
            char *p;
            char *y;
            char c;
            
            i = 0;
            p = instr;
            y = outstr;
            while (*p != 0) {
                c = *p;
                *y = c;
                y = y + 1;
                p = p + 1;
                i = i + 1;
            }
            *y = 0;
            
            // XXX should return outstr
            return i;
        }
        """)

        self.localfunctions["strcat"] = ("c", """
        int strcat(char *outstr, char *instr)
        {
            int i;
            char *y;
            char *p;
            char  c;
            i = 0;
            y = outstr;
            p = instr;
            
            while (*y != 0) {
                y = y + 1;
                i = i + 1;
            }
            
            while( *p != 0) {
                c = *p;
                *y = c;
                y = y + 1;
                p = p + 1;
                i = i + 1;
            }
            *y = 0;
            
            return i;
        }
        """)

        self.localfunctions["strcmp"] = ("c", """
        int strcmp(char *first, char *second)
        {
          int i;
          char a;
          char b;
          int cond;
          cond = 1;
          i=0;
          while( cond != 0 )
          {
            a = first[i];
            b = second[i];
            if(a != b){
              cond=0;
            }
            if (a==0){
              cond=0;
            }
            if (b==0){
              cond=0;
            }
            i = i+1;
          }
          if(a < b){
            return -1;
          }
          if(b < a){
            return 1;
          }
          return 0;
        }  
        """)
        
        #############
        #
        #  string.h
        #
        #############
        
        self.localfunctions["bzero"] = ("c", """
        #include <string.h>
        
        void
        bzero(char *ptr, int size)
        {
            memset(ptr, 0, size);
        }
        """)
        
        self.localfunctions["bcopy"] = ("c", """
        #include <string.h>
        
        void
        bcopy(char *src, char *dst, int size)
        {
            memcpy(dst, src, size);
        }
        """)
        
        #############
        #
        #  ctype.h
        #
        #############
        
        self.localfunctions["isdigit"] = ("c", """
        int
        isdigit(int c)
        {
            if (c < '0') {
                return 0;
            }
            if (c > '9') {
                return 0;
            }
            return 1;
        }
        """)
        
        #############
        #
        #  stdlib.h
        #
        #############
        
        self.localfunctions["exit"] = ("c", """
        #include <unistd.h>
        
        void exit(int status)
        {
            _exit(status);
        }
        """)
        
        self.localfunctions["atoi"] = ("c", """
        #include <ctype.h>
        
        int
        atoi(char *p)
        {
            int n;
            int cond;
            long t;
            long r;
            
            n = 0;
            if (*p == '-') {
                n = -1;
                p = p + 1;
            }
            r = 0;
            cond = 1;
            while (cond) {
                if (*p == '\0') {
                    cond = 0;
                } else {
                    if (isdigit(*p) == 0) {
                        cond = 0;
                    }
                }
                if (cond) {
                    t = *p;
                    t = t - '0';
                    r = r * 10;
                    r = r + t;
                    p = p + 1;
                }
            }
            if (n) {
                r = r * n;
            }
            return r;
        }
        """)
        
        self.localfunctions["malloc"] = ("c", """
        #include <sys/mman.h>

        // Very basic and retarded malloc implementation.  It allocates
        // a page per malloc() request, thus wasting a lot of space.
        // Implementing more complicated allocators will suck until
        // MOSDEF C gets support for globally scoped variables.
        char *malloc(int size)
        {
            unsigned int *p;
            char *ret;

            // Add 4 bytes for the length, and align to PAGE_SIZE.
            size = size + 4;
            if (size % 4096) {
                size = size / 4096;
                size = size + 1;
                size = size * 4096;
            }

            ret = mmap(NULL, size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (ret == MAP_FAILED)
                return NULL;

            // All hail the MOSDEF C parsing mafia.
            p = ret;
            *p = size;

            return ret + 4;
        }
        """)

        self.localfunctions["strdup"] = ("c", """
        #include <string.h>
        #include <stdlib.h>

        char *strdup(char *string)
        {
                char *ret;
                int size;

                size = strlen(string);
                ret = malloc(size + 1);
                if (ret == NULL) {
                        return NULL;
                }

                strcpy(ret, string);

                return ret;
        }
        """)

        self.localfunctions["free"] = ("c", """
        #include <sys/mman.h>
        
        void
        free(char *ptr)
        {
            unsigned int *p;
            
            p = ptr - 4;
            munmap(p, p[0]);
        }
        """)
        
        #############
        #
        #  stdio.h
        #
        #############
        
        # XXX '\n' breaks MOSDEF here.
        self.localfunctions["puts"] = ("c", """
        #include <unistd.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        
        int
        puts(char *s)
        {
            int len;
            int ret;
            char *p;
            
            len = strlen(s);
            p = malloc(len + 1);
            if (p == NULL) {
                return EOF;
            }
            memcpy(p, s, len);
            p[len] = 0x0a; // MOSDEF problem with 'back n'
            len = len + 1;
            ret = write(STDOUT_FILENO, p, len);
            free(p);
            if (ret != len) {
                return EOF;
            }
            return len;
        }
        """)
        
        ################
        #
        # network utils
        #
        ################
        
        self.localfunctions["writeblock"]=("c","""
        #import "local", "write" as "write"
        int writeblock(int fd, char *instr, int size) {
            int left;
            int i;
            char *p;
            
            left = size;
            p = instr;
            
            while (left > 0) {
                i = write(fd, p, left);
                if (i < 0) {
                    return 0;
                }
                left = left - i;
                p = p + i;
            }
            return 1;
        }
        """)
        
        self.localfunctions["sendblock"]=("c","""
        #import "local", "writeblock" as "writeblock"
        #import "local", "sendint" as "sendint"
        
        int sendblock(int fd, char *buf, int size)
        {
            int i;
            
            sendint(size);
            i = writeblock(fd, buf, size);
            
            return i;
        }
        """)
        
        # FIXME is that really useful?
        self.localfunctions["writestring"]=("c","""
        #import "local","sendblock" as "sendblock"
        #import "local","strlen" as "strlen"
        
        int writestring(int fd, char *string) {
            
            sendblock(fd, string, strlen(string));
            
        }
        """)
        
        # XXX yo wtf is that?
        # TODO: move it in CANVAS/MOSDEFShellServer or CANVAS/MOSDEF/MOSDEFlibc/libs/libhttp or something.
        # move below in initStaticFunctions() at least
        # XXX
        #reads an HTTP header from an FD
        #also takes in a timeout value
        #if the timeout value expires, returns 0
        #else returns 1 and then the header as a block of data
        #this function avoids having loops on the Python side
        if 0:
            self.localfunctions["readHTTPheader"]=("c","""
            #import "local", "sendblock" as "sendblock"
            #import "local", "sendint" as "sendint"
            #import "local", "readLineFromFD" as "readLineFromFD"
            #import "local", "malloc" as "malloc"
            #import "local,  "free" as "free"
            #import "local", "isactive" as "isactive"
            int readHTTPheader(int fd, int timeout)
            {
                int done;
                int i;
                char buf[3000]; //a three thousand byte buffer for our header.            
                int size;
                char * p;
                char * p2;
                int ret;
                
                p=buf;
                size=0;
                done=0;
                while (!done) {
                   //fd must have something on it otherwise we'll get stuck if we're not in async mode
                    if isactive(fd,timeout) {
                       ret=recv(fd,p,1,0); //recv our one byte
                       if (ret<0) {
                         done=-1; //we are done, but with an error.
                       }
                       size=size+1;
                       if (size==3000)
                       {
                          //we recved a massive header - and hence we're done with some error val.
                          done=-1;
                       }
                       if (size >=4 ) {
                           //check for \r\n\r\n
                           p2=p-4; //go four bytes back
                           if (!strcmp(p2,"\r\n\r\n"))
                           {
                             //we have found the end of our buffer!
                             done=1;
                           }
                       }
                    } else {
                       //we are done but with an error due to timeout
                       done=-1;
                    }
                    
                
                sendblock(STATIC_FD, buf, size);
                
                return i;
            }
            """.replace("STATIC_FD",str(self.fd)))
        
    def initStaticFunctions(self, kvars = {'fd': 666}):
        for key in kvars.keys():
            #if hasattr(self, key):
            #    print "overwritting self.%s = %d" % (key, getattr(self, key))
            #print "STATIC[%s] = %s" % (key, kvars[key])
            setattr(self, key, kvars[key])
        
        self.localfunctions["sendint"] = ("c", """
        #import "local", "write" as "write"
        
        int sendint(int val)
        {
            int r;
            int i;
            
            i = val;
            r = write(STATIC_FD, &i, 4);
            
            return r;
        }
        """.replace("STATIC_FD", str(self.fd)))
        
        self.localfunctions["sendlonglong"] = ("c", """
        #import "local", "write" as "write"
        
        int sendlonglong(unsigned long long val)
        {
            int r;
            unsigned long long i;
            
            i = val;
            r = write(STATIC_FD, &i, 8);
            
            return r;
        }

        """.replace("STATIC_FD", str(self.fd)))

        # we are implementing a new function send pointers and dont have to rewrite
        # currently working functions.
        # TODO: maybe it should me moved anywhere else and renamed to sendsizet
        if self.LP64:
            self.localfunctions["sendlong"] = \
                ("c", self.localfunctions["sendlonglong"][1].replace('sendlonglong','sendlong'))
        else :
            self.localfunctions["sendlong"] = \
                ("c", self.localfunctions["sendint"][1].replace('sendint','sendlong'))
        
        self.localfunctions["sendstring"]=("c","""
        #import "local", "sendblock" as "sendblock"
        #import "local", "strlen" as "strlen"
        
        int sendstring(char *instr)
        {
            int i;
            int len;
            
            len = strlen(instr);
            i = sendblock(STATIC_FD, instr, len);
            
            return i;
        }
        """.replace("STATIC_FD", str(self.fd)))

        self.localfunctions["sendblock2self"]=("c","""
        #import "local","writeblock" as "writeblock"
        #import "local","strlen" as "strlen"
        #import "local","sendint" as "sendint"
        
        int sendblock2self(char * buf, int size) {
            int ret;

            sendint(size);
            ret = writeblock(FD,buf,size);

            return ret;
        }
        """.replace("FD",str(self.fd)))

        self.localfunctions["writeblock2self"]=("c","""
        #import "local","writeblock" as "writeblock"
        #import "local","strlen" as "strlen"
        #import "local","sendint" as "sendint"

        int writeblock2self(char * buf, int size) {
            int ret;

            ret = writeblock(FD,buf,size);

            return ret;
        }
        """.replace("FD",str(self.fd)))

        self.localfunctions["writestring"]=("c","""
        #import "local","sendblock" as "sendblock"
        #import "local","strlen" as "strlen"
        int writestring(int fd, char * outstr) {
            int ret;

            ret = sendblock(fd,outstr,strlen(outstr));

            return ret;
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

        self.localfunctions["sendshort"]=("c","""
        #import "local","writeblock" as "writeblock"
        void sendshort(short tosend)
        {
            short i;
            i=tosend;
            writeblock(SOCKETFD, &i,2);
        }
        """.replace("SOCKETFD",str(self.fd)))

        self.localfunctions["memcmp"]=("c","""
        int memcmp(void *s1, void *s2, int size)
        {
                char *__s1;
                char *__s2;
                char c1;
                char c2;
                int i;

                for (i = 0; i < size; i = i + 1) {
                        __s1 = s1;
                        __s2 = s2;
                        c1 = __s1[i];
                        c2 = __s2[i];
                        if (c1 != c2) {
                                if (c1 > c2) {
                                        return 1;
                                } else {
                                        return -1;
                                }
                        }
                }

                return 0;
        }
        """)

        self.localfunctions["mkdtemp"]=("c","""
        #import "local","exit" as "exit"
        #import "local","memcmp" as "memcmp"
        #import "local","strlen" as "strlen"
        #import "local","write" as "write"
        #import "local","mkdir" as "mkdir"
        #include <errno.h>
        #include <sys/time.h>

        int mkdtemp(char *template)
        {
                struct timeval tv;
                char *letters;
                int random;
                int count;
                char *ptr;
                int len;
                int ret;
                int v;

                letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                len = strlen(template);

                if (len < 6) {
                        return - EINVAL;
                }

                if (memcmp(template + len - 6, "XXXXXX", 6) != 0) {
                        return - EINVAL;
                }

                ptr = template + len - 6;

                // This shouldn't error, as we have no condition that can error.
                gettimeofday(&tv, NULL);

                random = tv.tv_usec << 16;
                random = random ^ tv.tv_sec;
                random = random ^ getpid();

                for (count = 0; count < 62 * 62 * 62; count = count + 1) {
                        v = random;

                        ptr[0] = letters[v % 62];
                        v = v / 62;
                        ptr[1] = letters[v % 62];
                        v = v / 62;
                        ptr[2] = letters[v % 62];
                        v = v / 62;
                        ptr[3] = letters[v % 62];
                        v = v / 62;
                        ptr[4] = letters[v % 62];
                        v = v / 62;
                        ptr[5] = letters[v % 62];

                        ret = mkdir(template, S_IRUSR | S_IWUSR | S_IXUSR);
                        if (ret != - EEXIST) {
                                return ret;
                        }

                        random = random + 7777;
                }

                return ret;
        }
        """)

        # XXX: bunch of helper functions for file access and transfers
        # over the network.  Should be moved to a more appropriate place.

        self.localfunctions["read_no_eintr"]=("c", """
        #import "local","read" as "read"
        #include <errno.h>
        int read_no_eintr(int fd, void *buf, int count)
        {
                int ret;

                do {
                        ret = read(fd, buf, count);
                } while (ret == - EINTR);

                return ret;
        }
        """)

        self.localfunctions["close_no_eintr"]=("c", """
        #import "local","close" as "close"
        #include <errno.h>
        int close_no_eintr(int fd)
        {
                int ret;

                do {
                        ret = close(fd);
                } while (ret == - EINTR);

                return ret;
        }
        """)

        # int mosdef_readn(int fd, void *buf, int count)
        #
        # Guarantees to read() count bytes from descriptor fd.
        # This can still return a short read when receiving EOF, but will
        # handle all other forms of short reads.
        self.localfunctions["mosdef_readn"]=("c", """
        #import "local","read_no_eintr" as "read_no_eintr"
        #include <errno.h>
        int mosdef_readn(int fd, void *buf, int count)
        {
                int ret;
                int rd;

                rd = 0;
                do {
                        ret = read_no_eintr(fd, buf + rd, count - rd);
                        if (ret <= 0) {
                                return ret;
                        }

                        rd = rd + ret;
                } while (rd != count);

                return rd;
        }
        """)

        self.localfunctions["write_no_eintr"]=("c", """
        #import "local","write" as "write"
        #include <errno.h>
        int write_no_eintr(int fd, void *buf, int count)
        {
                int ret;

                do {
                        ret = write(fd, buf, count);
                } while (ret == - EINTR);

                return ret;
        }
        """)

        self.localfunctions["mosdef_writen"]=("c", """
        #import "local","write_no_eintr" as "write_no_eintr"
        #include <errno.h>
        int mosdef_writen(int fd, void *buf, int count)
        {
                int ret;
                int wd;

                wd = 0;
                do {
                        ret = write_no_eintr(fd, buf + wd, count - wd);
                        if (ret <= 0) {
                                return ret;
                        }

                        wd = wd + ret;
                } while (wd != count);

                return wd;
        }
        """)

        self.localfunctions["file_send_line"]=("c","""
        #import "local","sendblock" as "sendblock"
        #import "local","read_no_eintr" as "read_no_eintr"
        #import "local","mosdef_writen" as "mosdef_writen"
        int file_send_line(int sd, int fd)
        {
                char buf[4096];
                int index;
                int done;
                char ch;
                int ret;

                done = 0;
                index = 0;
                do {
                        ret = read_no_eintr(fd, &ch, 1);
                        // Failed reading from file or EOF.  We don't want this
                        // to throw the remote off guard, so we pretend we saw
                        // a newline to signal the end of the string.
                        if (ret != 1) {
                                done = 1;
                        } else {
                                buf[index] = ch;
                                if (ch == '\\n') {
                                        done = 1;
                                }

                                index = index + 1;
                        }

                        // If we have filled the buffer, send out a chunk.
                        // XXX: sendblock does not handle EINTR.
                        if (index == 4096) {
                                if (sendblock(sd, buf, index) == 0) {
                                        return -1;
                                }

                                index = 0;
                        } else {
                                // On EOF or error, flush the write buffer.
                                if (done != 0) {
                                        if (index != 0) {
                                                if (sendblock(sd, buf, index) == 0) {
                                                        return -1;
                                                }
                                        }
                                }
                        }
                } while (done == 0);

                // Signal we have reached the end of the line.
                sendint(0);

                // Forward the error number as well.
                sendint(ret);

                return ret;
        }
        """)

        # Reads a string from the remote MOSDEF node descriptor into
        # the local process image, and return a pointer to this
        # dynamically allocated data.
        self.localfunctions["mosdef_read_string"]=("c", """
        #include <stdlib.h>
        #include <errno.h>
        #import "local","mosdef_readn" as "mosdef_readn"

        char *mosdef_read_string(void)
        {
                char *string;
                int size;
                int ret;

                ret = mosdef_readn(STATIC_FD, &size, 4);
                if (ret <= 0) {
                        return NULL;
                }

                // We now know the length of the string; allocate data for it.
                string = malloc(size + 1);
                if (string == NULL) {
                        return NULL;
                }

                // And read it in over the network.
                ret = mosdef_readn(STATIC_FD, string, size);
                if (ret <= 0) {
                        free(string);
                        return NULL;
                }
                string[ret] = 0;
                
                return string;
        }
        """.replace("STATIC_FD",str(self.fd)))
