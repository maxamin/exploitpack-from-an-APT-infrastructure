#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
# vim: sw=4 ts=4 expandtab

NOTE = """
yo this is not exactly the same syntax than previous MOSDEF includes.
please dont mess up
"""

import re

class C_headers:
    
    def __init__(self):
        self._includes_initLocalFunctions()
    
    def add_smth(self, type, name):
        return '#import "%s", "%s" as "%s"\n' % (type, name, name)
    
    def add_include(self, path):
        return '#include <%s>\n' % path
    
    def add_define(self, define):
        #no need to add defines into your code! They're in the #define list
        return "" #self.add_smth('int', define)
    
    def add_function(self, function):
        return self.add_smth('local', function)
    
    def add_structure(self, structure):
        return structure
    
    def add_header(self, name, dict):
        gname = re.sub("[/<>\".]", "_", name).upper()
        header = "#ifndef %s\n# define %s\n\n" % (gname, gname)
        for key in ['include', 'structure', 'define', 'function']:
            if dict.has_key(key):
                if type(dict[key]) != type([]):
                    header += getattr(self, 'add_%s' % key)(dict[key])
                else:
                    for entry in dict[key]:
                        if entry[0] != '.': # not yet implemented
                            header += getattr(self, 'add_%s' % key)(entry)
        header += "\n#endif\n"
        self.localfunctions[name] = ('header', header)
    
    def _includes_initLocalFunctions(self):
        
        self.add_header('<sys/types.h>', {})
        
        self.add_header('<mosdef.h>', {
            'function': ["sendint"]
        })
        
        self.add_header('<stddef.h>', {'define': ["NULL"]})
        
        self.add_header('<stdio.h>', {
            'include': ["stddef.h"],
            'function': ["puts", "rename"],
            'define': ["EOF"]
        })
        
        self.add_header('<stdlib.h>', {
            'include': ["stddef.h", "ctype.h"],
            'function': ["exit", "malloc", "free", "atoi", "mkdtemp"]
        })
        
        self.add_header('<sys/fcntl.h>', {
            'define': ["F_DUPFD", "F_GETFD", "F_SETFD", "F_GETFL", "F_SETFL", "F_DUP2FD", 'O_NONBLOCK'],
            'function' : ['fcntl']
        })
        
        self.add_header('<fcntl.h>', {
            'define': ["O_RDONLY", "O_WRONLY", "O_RDWR", "O_DIRECTORY"]
        })
        
        self.add_header('<unistd.h>', {
            'function': ["access", ".euidaccess", ".lseek", "close", "read", "write", ".pread",
                ".pwrite", "pipe", ".alarm", ".sleep", ".usleep", ".pause", "chown", "fchown", "lchown",
                "chdir", "fchdir", "getcwd", ".get_current_dir_name", ".getwd", "dup", "dup2", "execve",
                ".fexecve", ".execv", ".execle", ".execl", ".execvp", ".execlp", ".nice", "_exit", ".pathconf",
                ".fpathconf", ".sysconf", ".confstr", "getpid", "getppid", "getpgrp", ".getpgid", ".setpgid",
                ".setpgrp", "setsid", ".getsid", "getuid", "geteuid", "getgid", "getegid", ".getgroups",
                ".group_member", "setuid", ".setreuid", "seteuid", "setgid", ".setregid", "setegid",
                ".getresuid", ".getresgid", ".setresuid", ".setresgid", "fork", ".vfork", ".ttyname",
                ".ttyname_r", ".isatty", ".ttyslot", "link", ".symlink", "readlink", "unlink", "rmdir",
                ".tcgetpgrp", ".tcsetpgrp", ".getlogin", ".getlogin_r", ".setlogin", ".gethostname",
                ".sethostname", ".sethostid", ".getdomainname", ".setdomainname", ".vhangup", ".revoke",
                ".profil", ".acct", ".getusershell", ".endusershell", ".setusershell", ".daemon", ".chroot",
                ".getpass", ".fsync", ".gethostid", ".sync", ".getpagesize", ".getdtablesize", ".truncate",
                ".ftruncate", ".brk", ".sbrk", ".syscall", ".lockf", ".fdatasync", ".crypt", ".encrypt",
                ".swab", ".ctermid"],
            'define': ["STDIN_FILENO", "STDOUT_FILENO", "STDERR_FILENO",
                       "F_OK", "X_OK", "W_OK", "R_OK"]
        })
        
        self.add_header('<signal.h>', {
            'define': ["SIG_ERR", "SIG_DFL", "SIG_IGN", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL",
                "SIGTRAP", "SIGABRT", ".SIGIOT", "SIGBUS", ".SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV",
                "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", ".SIGSTKFLT", ".SIGCLD", "SIGCHLD",
                "SIGCONT", "SIGSTOP", ".SIGTSTP", ".SIGTTIN", ".SIGTTOU", ".SIGURG", ".SIGXCPU", ".SIGXFSZ",
                ".SIGVTALRM", ".SIGPROF", ".SIGWINCH", ".SIGPOLL", ".SIGIO", ".SIGPWR", ".SIGSYS", ".SIGUNUSED",
                ".SIGRTMIN", ".SIGRTMAX"],
            'function': ["signal"]
        })

        self.add_header('<errno.h>', {
            'define': ["EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO",
                "E2BIG", "ENOEXEC", "EBADF", "ECHILD", "EDEADLK", "ENOMEM",
                "EACCES", "EFAULT", "EBUSY", "EEXIST", "EXDEV", "ENODEV",
                "ENOTDIR", "EISDIR", "EINVAL", "ENFILE", "EMFILE", "ENOTTY",
                "EFBIG", "ENOSPC", "ESPIPE", "EROFS", "EMLINK", "EPIPE",
                "EDOM", "ERANGE", "EAGAIN"]
        })

        self.add_header('<sys/stat.h>', {
            'include': ["asm/stat.h"], # XXX: this is where our struct stat comes from ! arch dependent
            'function': ["chmod", "fchmod"],
            'define': [ "S_IFMT", "S_IFSOCK", "S_IFLNK", "S_IFREG",
                        "S_IFBLK", "S_IFDIR", "S_IFCHR", "S_IFIFO",
                        "S_ISUID", "S_ISGID", "S_ISVTX",
                        "S_IRWXU", "S_IRUSR", "S_IWUSR", "S_IXUSR",
                        "S_IRWXG", "S_IRGRP", "S_IWGRP", "S_IXGRP",
                        "S_IRWXO", "S_IROTH", "S_IWOTH", "S_IXOTH" ]
        })
            
        self.add_header('<sys/resource.h>', {
            'structure': """
                struct rlimit { // _FILE_OFFSET_BITS == 32
                    long rlim_cur;
                    long rlim_max;
                };""",
            # struct rusage
            'define': ["RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_DATA", "RLIMIT_STACK", "RLIMIT_CORE"],
            'function': ["getrlimit", "setrlimit", "getrusage"]
        })
            
        self.add_header('<sys/socket.h>', {
            'structure': """
                struct sockaddr {
                    unsigned short int sa_family;
                    char data[14];
                };
                
                struct in_addr {
                    unsigned int s_addr;
                };
                
                struct sockaddr_in {
                    unsigned short int sin_family;
                    unsigned short int sin_port;
                    //struct in_addr sin_addr;
                    unsigned int sin_addr_s_addr; // XXX: we cant do sa->sin_addr.s_addr in mosdef
                    char pad[8];
                };
                
                struct sockaddr_storage {
                    char padding[128];
                };

                // linklayer addressing
                struct sockaddr_ll {
                    unsigned short sll_family; // always AF_PACKET
                    unsigned short sll_protocol; // physical layer protocol
                    int sll_ifindex; // interface number
                    unsigned short sll_hatype; // header type
                    char sll_pkttype; // packet type
                    char sll_halen; // length of address
                    char sll_addr[8]; // physical layer address
                };
                """,
            'define': ["AF_INET", "AF_INET6", "SOCK_STREAM", "SOCK_DGRAM", "IPPROTO_TCP", "IPPROTO_UDP"],
            'function': ["socket", "connect", "accept", "listen", "bind", "getsockopt", "setsockopt",
                    "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg","htonl","htons", 'shutdown']
        })
        
        self.add_header('<netinet/in.h>', {
            'function': [".htonl", ".htons", ".ntohl", ".ntohs"],
            'define': ["IPPROTO_IP", "IPPROTO_ICMP", "IPPROTO_TCP", "IPPROTO_UDP", "IPPROTO_IPV6", "IPPROTO_RAW",
                        "INADDR_ANY", "INADDR_BROADCAST", "INADDR_NONE", "IN_LOOPBACKNET", "INADDR_LOOPBACK",
                        "INET_ADDRSTRLEN", "INET6_ADDRSTRLEN"]
        })
        
        self.add_header('<sys/mman.h>', {
            'define': ["PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC", "MAP_FAILED", "MAP_PRIVATE", "MAP_ANONYMOUS"],
            'function': ["mmap", "mprotect", "munmap"]
        })
        
        self.add_header('<arpa/inet.h>', {
            'include': ["netinet/in.h", "ctype.h"]
        })
        
        self.add_header('<ctype.h>', {
            'function': ["isdigit"]
        })
        
        self.add_header('<sys/poll.h>', {
            'structure': """
                struct pollfd {
                    int fd;
                    short events;
                    short revents;
                };
                """,
            'define': ["POLLIN", "POLLOUT", "POLLERR", "POLLHUP", "POLLNVAL"],
            'function': ["poll"]
        })
        
        self.add_header('<string.h>', {
            'function': ["strlen", "strcpy", "memset", "memcpy", 'memmove',
                         "strchr", "strrchr", "strdup"]
        })
        
        self.add_header('<strings.h>', {
            'function': ["bcopy", "bzero"]
        })
        
        self.add_header('<sys/socketvar.h>', {
            'define': ["SOV_STREAM", "SOV_DEFAULT", "SOV_SOCKSTREAM", "SOV_SOCKBSD", "SOV_XPG4_2"]
        })
        
        self.add_header('<ustat.h>', {
            'function': ["ustat"]
            # include <sys/types.h> for dev_t
            # struct ustat *
        })
        
        self.add_header('<sys/utssys.h>', {
            'function': ["fusers"],
            'define': ["UTS_UNAME", "UTS_UMASK", "UTS_USTAT", "UTS_FUSERS", "F_FILE_ONLY", "F_CONTAINED",
                        "F_CDIR", "F_RDIR", "F_TEXT", "F_MAP", "F_OPEN", "F_TRACE", "F_TTY"]
        })
        
        self.add_header('<sys/ioctl.h>', {
            'function': ["ioctl"]
        })

        self.add_header('<sys/time.h>', {
            'structure': """
                struct timeval {
                        int     tv_sec;
                        int     tv_usec;
                };
                """,
            'function': ["gettimeofday", "settimeofday"]
        })

        self.add_header('<sys/statfs.h>', {
            'structure': """
                struct statfs {
                        long                f_type;
                        long                f_bsize;
                        long                f_blocks;
                        long                f_bfree;
                        long                f_bavail;
                        long                f_files;
                        long                f_ffree;
                        // XXX: normally a nested struct, but MOSDEF-C sucks.
                        // Also getitemsize() will fail if we make this an
                        // array.
                        int                 f_fsid0;
                        int                 f_fsid1;
                        long                f_namelen;
                        long                f_frsize;
                        long                f_spare[5];
                };
                """,
            'define' : ["ST_RDONLY", "ST_NOSUID", "ST_NODEV", "ST_NOEXEC", "ST_SYNCHRONOUS",
                        "ST_MANDLOCK", "ST_WRITE", "ST_APPEND", "ST_IMMUTABLE", "ST_NOATIME",
                        "ST_NODIRATIME", "ST_RELATIME"],
            'function': ["statfs"]
        })

        self.add_header('<net/if.h>', {
            'structure': """
                struct ifreq {
                    char ifr_name[16];
                    int ifr_index;
                    char arg[16];
                };
                
                struct ifconf {
                    int ifc_len;
                    char *addr;
                };
                """,
            'define': ["POLLIN", "POLLOUT", "POLLERR", "POLLHUP", "POLLNVAL"],
            'function': ["poll"]
        })
        
        self.localfunctions['<mosdef/asm.h>'] = ('header', """
        # ifdef __x86__
        #  ifndef __i386__
        #   define __i386__
        #  endif
        # endif
        # ifdef __i386__
        #  include <asm/i386.h>
        # endif
        # ifdef __AMD64__
        #  include <asm/amd64.h>
        # endif
        # ifdef __sparc__
        //#  include <asm/sparc.h>
        # endif
        # ifdef __ppc__
        #  include <asm/ppc.h>
        # endif
        # ifdef __arm__
        #  include <asm/arm.h>
        # endif
        # ifdef __arm9__
        #  include <asm/arm.h>
        # endif
        # ifdef __mips__
        //#  include <asm/mips.h>
        # endif
        """)

