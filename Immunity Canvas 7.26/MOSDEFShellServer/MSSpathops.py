#!/usr/bin/env python
#
# This interface is meant to be usable in a cross-platform manner, and should
# therefore handle path operations as a layer above the systemcall primitives.
#
#  -- Ronald Huizer
#
# vim: sw=4 ts=4 expandtab

import re

class MSSPathOperationsPOSIX:
    # XXX: As MSSPathOperations() is contained by MOSDEFShellServer this
    # design is note clean.  The systemcall wrappers in MOSDEFShellServer
    # should be refactored at a later point in its own appropriate subclass.
    #
    # Introducing better design is hard, but this class tries to anticipate
    # a better design, at which point it can rely on a class containing
    # the systemcall primitives.
    def __init__(self, shell):
        """
        @type   shell:    MOSDEFShellServer
        @param  shell:    The MOSDEF ShellServer we work on.
        """
        self.shell = shell

        # XXX: Maybe these can be class variables?  Don't know if POSIX
        # mentions anything about their values.
        self.S_IFLNK = shell.libc.getdefine('S_IFLNK')
        self.S_IFDIR = shell.libc.getdefine('S_IFDIR')
        self.S_ISUID = shell.libc.getdefine('S_ISUID')
        self.X_OK = shell.libc.getdefine('X_OK')
        self.F_OK = shell.libc.getdefine('F_OK')

    def isAbsolute(self, pathname):
        """
        Returns whether a pathname on the MOSDEFShellServer is absolute.

        @type   pathname: string
        @param  pathname: The pathname of the file to test.
        @rtype          : boolean
        @return         : True if pathname is absolute, False otherwise.
        """
        return pathname.startswith(self.separator())

    def isRelative(self, pathname):
        """
        Returns whether a pathname on the MOSDEFShellServer is relative.

        @type   pathname: string
        @param  pathname: The pathname of the file to test.
        @rtype          : boolean
        @return         : True if pathname is relative, False otherwise.
        """
        return not self.isAbsolute(pathname)

    def isSymlink(self, pathname):
        """
        Returns whether a pathname on the MOSDEFShellServer is a symbolic link.

        @type   pathname: string
        @param  pathname: The pathname of the file to test.
        @rtype          : boolean
        @return         : True if pathname is setuid root, False otherwise.
        """
        (ret, st) = self.shell.stat(pathname)
        return ret >= 0 and st["st_mode"] & self.S_IFLNK

    def isDirectory(self, pathname):
        """
        Returns whether a pathname on the MOSDEFShellServer is a directory.

        @type   pathname: string
        @param  pathname: The pathname of the file to test.
        @rtype          : boolean
        @return         : True if pathname is setuid root, False otherwise.
        """
        (ret, st) = self.shell.stat(pathname)
        return ret >= 0 and st["st_mode"] & self.S_IFDIR

    def isExecutable(self, pathname):
        """
        Returns whether a pathname on a MOSDEFShellServer can be executed.

        @type   pathname: string
        @param  pathname: The pathname of the file to test.
        @rtype          : boolean
        @return         : True if pathname is executable, False otherwise.
        """
        return self.shell.access(pathname, self.X_OK)

    def exists(self, pathname):
        """
        Returns whether a pathname on a MOSDEFShellServer exists.

        @type   pathname: string
        @param  pathname: The pathname of the file to test.
        @rtype          : boolean
        @return         : True if pathname exists, False otherwise.
        """
        return self.shell.access(pathname, self.F_OK)

    def separator(self):
        """
        Returns the path separator in use by this MOSDEFShellServer.

        @rtype : string
        @return: The string holding the pathname separator.
        """
        return "/"

    def baseName(self, pathname):
        """
        Returns the base name portion of the pathname.

        Assumes that pathname is indeed valid, that is, has at least a dirname
        and basename portion to it.

        @type   pathname: string
        @param  pathname: The pathname to return the base name for.
        @rtype          : string
        @return         : The base name for the given pathname.
        """
        index = pathname.rfind(self.separator());
        if index == -1:
            return None

        return pathname[index + 1:]

    def dirName(self, pathname):
        """
        Returns the dir name portion of the pathname.

        Assumes that pathname is indeed valid, that is, has at least a dirname
        and basename portion to it.

        @type   pathname: string
        @param  pathname: The pathname to return the base name for.
        @rtype          : string
        @return         : The dir name for the given pathname.
        """
        index = pathname.rfind(self.separator());
        if index == -1:
            return None

        return pathname[:index]

    def absolute(self, pathname):
        """
        Returns the absolute version of the pathname.

        The absolute version will be created by prepending the current
        working directory to the pathname if it is relative.

        This will not remove symlinks, or ".", ".." and multiple slash
        components.

        @type   pathname: string
        @param  pathname: The pathname to return the absolute name for.
        @rtype          : string
        @return         : The absolute pathname.
        """
        if self.isAbsolute(pathname):
            return pathname

        return self.join(self.current(), pathname)

    def resolveSymlink(self, pathname):
        """
        Returns the target of the symbolic link pathname.

        @type   pathname: string
        @param  pathname: The symlink to return the target for or None in
                          case of failure.
        @rtype          : string
        @return         : The target of the symlink.
        """
        try:
            ret = self.shell.readlink(pathname)
        except MSSError, e:
            return None

        return ret

    def current(self):
        """
        Returns the current pathname.

        @rtype          : string
        @return         : The current working directory.
        """
        # XXX: can error.  With what exactly?
        pathname = self.shell.getcwd();

        # Strip the trailing '/'.  We do not use rstrip() as it does not
        # strip the suffix, but a set of characters.
        sep = self.separator()
        if pathname != sep and pathname.endswith(sep):
            return pathname[:-len(sep)]

        return pathname

#    def canonical(self, pathname):
#        """
#        Returns the canonicalized version of the pathname.
#
#        This will resolve all symbolic links, ".", "..", and multiple separator
#        components from the pathname and return the result.
#
#        @type   pathname: string
#        @param  pathname: The pathname to return the base name for.
#        @rtype          : string
#        @return         : The dir name for the given pathname.
#        """
#        sep = self.separator()

#        if self.isAbsolute(pathname):
#            parts = [sep] + filename.split(sep)[1:]
#        else:
#            parts = [''] + filename.split(sep)

#        for i in xrange(2, len(parts) + 1):
#            component = self.join(*parts[0:i])

        # Resolve symbolic links.
#        if self.islink(component):
#            resolved = self.resolveSymlink(component)
#            if resolved is None:
#                # Infinite loop -- return original component + rest of the path
#                return self.absolute(self.join(*([component] + parts[i:])))
#            else:
#                newpath = self.join(*([resolved] + parts[i:]))
#                return realpath(newpath)
#
#    return abspath(filename)

    def join(self, *pathnames):
        """
        Returns the concatenation of pathname and pathnames.

        This will introduce the separator between elements.

        @type   pathname: string
        @param  pathname: The pathname to return the base name for.
        @rtype          : string
        @return         : The joined pathname components.
        """
        return self.separator().join([ self.chomp(p) for p in pathnames ])

    def chomp(self, pathname):
        """
        Returns pathname with trailing separators removed.

        Be careful using this function on the "/" path, as it will result
        in the empty string.

        @type   pathname: string
        @param  pathname: The pathname to work on.
        @rtype          : string
        @return         : The chomped pathname.
        """

        sep = self.separator()
        while pathname.endswith(sep):
            pathname = pathname[:-len(sep)]

        return pathname

    def walk(self, top, topdown=True, onerror=None, followlinks=False, depth=-1):
        # We may not have read permission for top, in which case we can't
        # get a list of the files the directory contains.  os.path.walk
        # always suppressed the exception then, rather than blow up for a
        # minor reason when (say) a thousand readable directories are still
        # left to visit.  That logic is copied here.

#        try:
            # Note that listdir and error are globals in this module due
            # to earlier import-*.
        names = [ d[0] for d in self.shell.dodir(top) ]
#        except error, err:
#            if onerror is not None:
#                onerror(err)
#            return

        dirs, nondirs = [], []
        for name in names:
            if name != "." and name != "..":
                if self.isDirectory(self.join(top, name)):
                    dirs.append(name)
                else:
                    nondirs.append(name)

        if topdown:
            yield top, dirs, nondirs

        for name in dirs:
            new_path = self.join(top, name)
            if followlinks or not self.isSymlink(new_path):
                if depth == -1:
                    for x in self.walk(new_path, topdown, onerror, followlinks, -1):
                        yield x
                elif depth != 0:
                    for x in self.walk(new_path, topdown, onerror, followlinks, depth - 1):
                        yield x

        if not topdown:
            yield top, dirs, nondirs

    def isSetuidRoot(self, pathname):
        """
        Returns whether a pathname on a MOSDEF node is setuid root.

        This method is specific to MSSPathOperationsPOSIX.

        @type   pathname: string
        @param  pathname: The pathname of the file to test.
        @rtype          : boolean
        @return         : True if pathname is setuid root, False otherwise.
        """
        (ret, st) = self.shell.stat(pathname)
        return ret >= 0 and st["st_mode"] & self.S_ISUID and st["st_uid"] == 0

    def subpaths(self, pathname):
        """
        Generates pathname components.

        An input path such as "/foo/bar/baz" will result in a generator 
        yielding "/foo", "/foo/bar", and "/foo/bar/baz".
        "////foo/bar/baz" and "///foo///bar//baz///" will yield the same result.

        "/" and "///" and so on will yield "/".

        @type   pathname: string
        @param  pathname: The pathname of the file to generate.
        @rtype          : boolean
        @return         : A generator for pathname components.
        """
        p = pathname
        sep = self.separator()
        parts = re.split(sep + "+", p)

        if parts[0] == "" and parts[1] == "":
            yield sep 

        for i in xrange(p.startswith(sep) + p.endswith(sep), len(parts)):
            yield sep.join(parts[0:i + (not p.endswith(sep))])

    def rsubpaths(self, pathname):
        """
        Generates pathname components in reverse order.

        An input path such as "/foo/bar/baz" will result in a generator 
        yielding "/foo/bar/baz", "/foo/bar", and "/foo".
        "////foo/bar/baz" and "///foo///bar//baz///" will yield the same result.

        "/" and "///" and so on will yield "/".

        @type   pathname: string
        @param  pathname: The pathname of the file to generate.
        @rtype          : string
        @return         : A generator for pathname components.
        """

        p = pathname
        sep = self.separator()
        parts = re.split(sep + "+", p)

        if parts[0] == "" and parts[1] == "":
            yield sep

        for i in range(len(parts) - p.endswith(sep), p.startswith(sep), -1):
            yield sep.join(parts[0:i])

    # XXX: right now will use /usr/bin/getenv to go this.  This is not clean,
    # but we can't just read the passwd file and expect it to work, as the
    # nsswitch layer in glibc deals with NIS, NIS+, LDAP and so on.
    #
    # We may want to consider dynamically importing glibc getpwuid() or so.
    def home(self):
        """
        Returns the home directory of the current user.

        @rtype          : string
        @return         : The home directory of the current user, or None.
        """

        uid = self.shell.getuid()

        # XXX: kludge
        pwdent = self.shell.runcommand("/usr/bin/getent passwd %d" % uid)
        pwdent = pwdent.split(':')

        # Sanity check, we want to make sure this is not the shell returning
        # errors that getent was not found.
        if len(pwdent) == 7 and int(pwdent[2]) == uid:
            return pwdent[5]

        return None
