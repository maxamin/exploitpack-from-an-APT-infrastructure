#include <stdio.h>

#define ISMOD(val, mod) ((val) % (mod) == ((mod) - 1))
#if defined(__i386__) || defined(WINDOWS) || defined(__CYGWIN__) || defined(WIN32)
# define LINERETPAD     8
#else
# define VALPAD         4
# define LINERETPAD     16
#endif

void
bufferdump(void *buffer, size_t count)
{
  int i;
  unsigned char *p = buffer;

  for (i=0; i<count; i++)
    {
      printf("%2.2x ",p[i]);
      #ifdef VALPAD
      if (ISMOD(i,VALPAD))
        printf("  ");
      #endif
      if (ISMOD(i,LINERETPAD))
        putchar('\n');
    }
  if (!ISMOD(i,LINERETPAD))
    putchar('\n');
}

