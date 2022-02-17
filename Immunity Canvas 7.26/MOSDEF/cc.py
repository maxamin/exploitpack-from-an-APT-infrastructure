#! /usr/bin/env python

import sys, os
import mosdef
from mosdefutils import dInt_n

def usage(errmsg = None):
    if errmsg:
        print "error:", errmsg
    print """\nUsage: %s [args] [files]
    -h              : Display this help.
    -v              : Increase verbose level.
    -o file         : Place output in file <file..

    -c              : Compile or assemble the source files, but do not link.
    -S              : Stop after the stage of compilation proper, do not assemble.
    -1              : Stop after the stage of intermediate language.
    -E              : Stop after the preprocessing stage, do not run the compiler proper.

    -s              : Strip the code, no debug.
    -d              : Add a TRAP just after entry point.

    -D name         : Define <name>.
    -D name=value   : Define <name> with <value>.
    -U name         : Does not define <name>, undefined it if defined.

    -t target_id    : Fill <target> flags with builtin list (use target_id=0 to display the list).
    -m OS           : Target OS.
    -p proc         : Target Processor.
    -k version      : Target kernel version.
    -r release      : Target OS release version.
    -T              : Save temp files.
    """ % sys.argv[0]
    #sys.exit(1) #no exit because we might be called from CANVAS!

_targets = {
     0: None,
     1: ["Linux",   "i386",    "2.4"],
     2: ["Linux",   "i386",    "2.6"],
     3: ["Linux",   "sparc",   "2.4"],
    #4: ["Linux",   "powerpc", "2.6"],
     4: ["Linux",   "ppc",     "2.6"],
   # 5: ["Linux",   "mips",    "2.6"],
     6: ["Linux",   "mipsel",  "2.6"],
   # 7: ["Linux",   "arm",     "2.6"],
   # 8: ["Linux",   "armel",   "2.6"],
   # 9: ["Linux",   "parisc",  "2.4"],
    10: ["Solaris", "sparc",   "2.7"],
    11: ["Solaris", "i86pc",    "10"],
    12: ["FreeBSD", "i386",    "6.1"],
   #13: ["FreeBSD", "sparc",   "5.3"],
    14: ["OpenBSD", "i386",    "3.9"],
   #15: ["OpenBSD", "sparc",   "3.9"],
   #16: ["MacOSX",  "powerpc","10.4"],
    16: ["OSX",     "x64",    "10.5"],
    17: ["OSX",     "x86",    "10.5"],
    18: ["AIX",     "powerpc", "5.1"],
    19: ["AIX",     "powerpc", "5.2"],
   #20: ["IRIX",    "mips",    "6.5"],
    21: ["Win32",   "i386",       ""],
    22: ["Win64",   "x64",        ""],
    23: ["Linux",   "armel",   "2.6"],
    24: ["Linux",   "x64",     "2.6"],
}

STAGE_LINK       = 0
STAGE_ASSEMBLE   = 1
STAGE_COMP       = 2
STAGE_INTERPRETE = 3
STAGE_CPP        = 4
STAGE_MAX        = 5

verbose = 0
_stage_e = {
    STAGE_LINK:       ["Linking",         ""],
    STAGE_ASSEMBLE:   ["Compiling",    ".sc"],
    STAGE_COMP:       ["Assembling",    ".s"],
    STAGE_INTERPRETE: ["ILing",        ".il"],
    STAGE_CPP:        ["Preprocessing", ".E"]
}

def stage_dispatcher(stage, data, remoteresolver):
    assert stage < STAGE_MAX
    global verbose
    if verbose:
        print "%s..." % _stage_e[stage][0]
    if stage == STAGE_CPP:
        # we do preprocess C
        return remoteresolver.cpreprocess(data)
    elif stage == STAGE_INTERPRETE:
        return remoteresolver.compile_to_IL(data, None)
    elif stage == STAGE_COMP:
        il2proc = __import__('il2%s' % remoteresolver.arch.lower())
        return il2proc.generate(data)
    elif stage == STAGE_ASSEMBLE:
        # and we do preprocess asm as well.
        data = remoteresolver.cpreprocess(data)
        return remoteresolver.assemble(data)
    elif stage == STAGE_LINK:
        return data
    #else:

def default_target():
    try:
        # UNIX only
        un = os.uname()
        i = un[2].find('.', 2)
        version = un[2][:i]
        proc = un[4]
        target=[un[0], proc, version]
    except AttributeError:
        ##Probably on Windows so lets make an arbitrary choice
        target=["Win32",   "i386",       ""]

    for t in _targets.values():
        if t == target:
            return target

    print "Autoselected target '%s' not known. Try selecting a target manually using -t. Use -t0 to see the available targets"%target
    sys.exit()

def list_targets():
    indexes = _targets.keys()
    indexes.sort()
    print "[supported targets]:\n"
    for index in indexes:
        values = _targets[index]
        if values == None:
            continue
        print "%d> %s, %s (%s)" % (index, values[0], values[1], values[2])
    sys.exit(0)

from threading import RLock
cc_main_lock=RLock()
cc_main_cache={}
def threadsafe_cc_main(args):
    """
    A threadsafe way to call cc_main, also includes a
    cache to prevent this from owning your cpu during massattack
    """
    global cc_main_lock
    global cc_main_cache

    cc_main_lock.acquire()
    cache_key=str(args)
    if cache_key in cc_main_cache:
        cc_main_lock.release()
        return cc_main_cache[cache_key]

    #we're not in the cache, so we need to do a
    #compile based on our args
    ret=cc_main(args)
    cc_main_cache[cache_key]=ret
    cc_main_lock.release()
    return ret

def cc_main(args):
    global verbose #yuuuuucky!
    import getopt
    _stage = {'c': 1, 'S': 2, '1': 3, 'E': 4}
    _targets_n = ['m', 'p', 'k']
    _target = {'m': "OS", 'p': "Proc", 'k': "Version"}

    try:
        # XXX -D arg
        opts, args = getopt.getopt(args, "hvo:cS1EsdD:U:m:p:k:r:t:T")
    except getopt.GetoptError, m:
        usage(m)
    #print opts, args

    # defaults
    target = {'OS': None, 'Proc': None, 'Version': None}
    stage = STAGE_LINK
    stage_start = max(_stage.values())
    debug = False
    defines = {}
    outfilename = None
    keep_tempfiles = False

    for _opt, arg in opts:
        opt = _opt[1:]
        #print opt, arg
        if opt == 'h':
            usage()
        elif opt == 't':
            try:
                arg = int(arg)
            except ValueError:
                usage("-t expect an integer as argument")
            if arg == 0:
                list_targets()
            for n in _targets_n:
                target[_target[n]] = _targets[arg][_targets_n.index(n)]
        elif opt == 'v':
            verbose += 1
        elif opt in _stage.keys():
            if _stage[opt] > stage:
                stage = _stage[opt]
        elif opt == 'o':
            outfilename = arg
        elif opt == 'd':
            debug = True
        elif opt in _target.keys():
            target[_target[opt]] = arg
        elif opt == 'D':
            define, value = arg, None
            if '=' in define:
                define, value = define.split('=')
                if dInt_n(value)!=None: #zero is a valid value, of course
                    value=dInt_n(value)
                    #print "Value=%d"%value

            defines[define] = value
        elif opt == 's':
            striped_is_default = True
        elif opt == 'T':
            keep_tempfiles = True
        else:
            print "Not implemented: %s" % ([_opt, arg])
            sys.exit(2)

    if args == []:
        usage("missing files to compile")

    #print "Targeting: %s"%target

    if None in target.values():
        print "You selected target with Values: %s"%str(target)
        # using host values
        t = default_target()
        print "Using target: %s"%(t)
        for n in _targets_n:
                target[_target[n]] = t[_targets_n.index(n)]
        #usage("you must set the <target> flags")

    if target["Version"] == "None":
        target["Version"] = None

    if verbose:
        print "Target: %s %s [%s]" % (target['OS'], target['Version'], target['Proc'])

    #print "[XXX] cc.py: %s .. %s .. %s" % (target['OS'], target['Proc'], target['Version'])

    rr = mosdef.getremoteresolver(target['OS'], target['Proc'], target['Version'])
    if rr == None:
        print "could not find the MOSDEF remote resolver."
        sys.exit(3)

    # TODO: remove -U defines here
    rr.defines.update(defines)

    outfile_data = ""
    # XXX handle multiples files...
    for filename in args:
        if len(filename) <= 2:
            print "wrong file name: %s" % filename
            continue

        filesep = filename.rfind('.')
        if filesep == -1:
            print "wrong file name: %s" % filename
            continue

        fileext = filename[filesep + 1:]
        fileprefix = filename[:filesep]
        if os.path.sep in fileprefix:
            fileprefix = fileprefix[fileprefix.rfind(os.path.sep) + 1:]

        for k in _stage_e.keys():
            if _stage_e[k][1] == filename[filesep:]:
                stage_start = k - 1
                break

        try:
            data = file(filename).read()
        except IOError:
            print "Error: can not open file %s" % filename
            continue

        if not outfilename:
            outfilename = fileprefix + _stage_e[stage][1]

        for s in range(stage_start, stage - 1, -1):

            sfilename = outfilename
            if s != stage:
                sfilename = fileprefix + _stage_e[s][1]
            if s == stage or keep_tempfiles:
                try:
                    outfile = file(sfilename, "wb")
                except IOError:
                    print "Error: can not open file %s" % outfilename
                    break

            data = stage_dispatcher(s, data, rr)
            assert data, "error at <%s> stage" % _stage_e[stage][0]
            if s != stage:
                if keep_tempfiles:
                    if verbose:
                        print "Writing output filename:", sfilename
                    outfile.write(data)
                    outfile.close()
            else:
                if stage == STAGE_LINK:
                    import makeexe
                    outfile.close()
                    outfile_data=makeexe.makeexe(target['OS'].lower(), data, outfilename, proc = rr.arch.upper())
                else:
                    outfile.write(data)
                    outfile.close()
    return outfile_data
    #print "Done."

"""
Sample commandline:
dave@dave-laptop ~/CANVAS $ MOSDEF/cc.py -m Linux -p x86 -D CBACK_PORT=1 -D CBACK_ADDR=1.1.1.1 -T backdoors/cback_mmap_rwx.c
"""
if __name__ == '__main__':
    ret=cc_main(sys.argv[1:])
    print "Returned data of length %d"%len(ret)
