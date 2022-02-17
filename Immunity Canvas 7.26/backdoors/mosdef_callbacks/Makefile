# require GNU make, but is portable

CC = gcc
CPPFLAGS = -Wall
CFLAGS = -ggdb -static
PYMOD = .so
PYCC = $(CC)

OS = $(shell uname -s)
PROC = $(shell uname -m)
PYVERSION_EXT=$(wordlist 1,2,$(subst ., ,$(word 2, $(shell python -V 2>&1))))
PYVERSION_MAJ=$(word 1, $(PYVERSION_EXT))
PYVERSION_MIN=$(word 2, $(PYVERSION_EXT))
PYVERSION=python$(PYVERSION_MAJ)$(PYVERSION_MIN)

ifeq ($(findstring CYGWIN, $(OS)),CYGWIN)
    OS = cygwin
    PROC = i386
    OSPROC = win32
    PYMOD = .pyd
    CPPFLAGS += -DWIN32 -DWINDOWS
    CFLAGS += -mno-cygwin
    LDFLAGS += -lws2_32
    PYCPPFLAGS = $(CPPFLAGS) -I include
    PYCFLAGS = $(CFLAGS) -mwin32
    MAKEDLL = dllwrap -dllname $@ --driver-name=gcc -o $@ $^ -s --target=i386-mingw32 --export-all-symbols
    EXT = .exe
    PYLINK = $(MAKEDLL) --entry _DllMain@12 -L libs -lpython24
endif
ifeq ($(OS),SunOS)
    OS = solaris
    LDFLAGS += -lsocket -lnsl
endif
ifeq ($(OS),Darwin)
    OS = macosx
    PYCPPFLAGS = $(CPPFLAGS) -I/usr/include/python2.3 -I/usr/include/python2.4
    PYCFLAGS = $(CFLAGS) -dynamic -fPIC
    PYLDFLAGS = -bundle -bundle_loader /usr/bin/python -lpython
    PYLINK = $(PYCC) $(PYCFLAGS) -o $@ $^ $(PYLDFLAGS)
endif
ifeq ($(OS),Linux)
    OS = linux
endif
ifeq ($(OS),AIX)
    OS = aix
endif
ifeq ($(OS),FreeBSD)
    OS = fbsd
endif
ifeq ($(PROC),i86pc)
    PROC = i386
endif
ifeq ($(PROC),i686)
    PROC = i386
endif
ifeq ($(PROC),i386)
    PROC = x86
endif
ifeq ($(findstring sparc, $(OS)),sparc)
    PROC = sparc
endif
ifeq ($(PROC),ppc)
    PROC = powerpc
endif
ifeq ($(findstring PowerPC, $(OS)),PowerPC)
    PROC = powerpc
endif
ifndef OSPROC
    OSPROC = $(OS)_$(PROC)
endif

PYNAME = _$(OSPROC)_$(PYVERSION)
COMPILE = $(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
LINK = $(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
PYCPPFLAGS += -DMODNAME=\"$*$(PYNAME)\" -DMODFUNC=init$*$(PYNAME)
PYCOMPILE = $(PYCC) -c $(PYCPPFLAGS) $(PYCFLAGS) -o $@ $<
COPY = cp $< $@
MOVE = mv $< $@

PYSYSTEMAPI = PySystemAPI
COMMONOBJ = tcpstuff.o utils.o
MOSDEFCALLBACK_EXT = mosdef_callback$(EXT)
MOSDEFCALLBACK_OSEXT =  mosdef_callback_$(OSPROC)$(EXT)
ifdef EXT
    MOSDEFCALLBACK =  mosdef_callback
endif

all: $(MOSDEFCALLBACK_EXT)
	@#echo "Target: $(OSPROC)"

pymodules: $(PYSYSTEMAPI)$(PYMOD)

%$(PYMOD): %.pyo
	$(PYLINK)
	cp $@ $*$(PYNAME)$(PYMOD)

%.o: %.c
	$(COMPILE)

%.pyo: %.c
	$(PYCOMPILE)

mosdef_calback%_$(OSPROC)$(EXT): mosdef_callback%$(EXT) $(COMMONOBJ)
	$(MOVE)

mosdef_callback%$(EXT): mosdef_callback%.o $(COMMONOBJ)
	$(LINK)

ifdef EXT
# win32 kludge
mosdef_callback%: mosdef_callback%$(EXT)
	@true
endif

clean:
	$(RM) $(COMMONOBJ) $(MOSDEFCALLBACK) $(MOSDEFCALLBACK_EXT) $(MOSDEFCALLBACK_OSEXT) *.o *.pyo *$(PYMOD)
