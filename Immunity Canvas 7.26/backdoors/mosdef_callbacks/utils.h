#ifndef UTILS_H
#define UTILS_H

#ifndef __GNUC__
# define __asm__ asm
#endif

/*
 * gcc 3.3.2 (at least) is broken on AIX PowerPC
 *
 * if you try to jump at an address, like:
 * ((void(*)())(buffer))()
 * gcc will produce code that jump to '*buffer' instead of 'buffer'
 *
 * this fix try to avoid that bug
 */
#if defined(AIX) || defined(_AIX)
# warning "using AIX gcc longjump fix"
# define JUMPTOBUF(buffer) \
	/* we expect the buffer address in a register */ \
	__asm__ volatile ("mtctr %0\n\tbctrl" : : "r" (buffer));
#else
# define JUMPTOBUF(buffer) ((void(*)())(buffer))()
#endif

void bufferdump(void *, size_t);

#endif
