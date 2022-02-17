#!/usr/bin/env python

class MSSFileMode:
    NotSet      = 0
    ReadOnly    = 1
    WriteOnly   = 2
    ReadWrite   = ReadOnly | WriteOnly
    Append      = 4
    Truncate    = 8
    Text        = 16
    Create      = 32
    AutoRemove  = 64

class MSSFile:
    def __init__(self, shell, pathname, mode = MSSFileMode.NotSet):
        self.shell = shell
        # XXX: should be canonicalized as open() follows symlinks.
        self.pathname = pathname
        self.fd = -1
        self.mode = mode

        # Cache the flags locally for now.  Needs better design.
        self.O_RDONLY = self.shell.libc.getdefine('O_RDONLY'),
        self.O_WRONLY = self.shell.libc.getdefine('O_WRONLY'),
        self.O_RDWR = self.shell.libc.getdefine('O_RDWR'),
        self.O_APPEND = self.shell.libc.getdefine('O_APPEND'),
        self.O_TRUNC = self.shell.libc.getdefine('O_TRUNC'),
        self.O_CREAT = self.shell.libc.getdefine('O_CREAT')

    def open(self, mode):
        # We close the old descriptor before raising a possible exception.
        if self.fd != -1:
            self.close()

        if not self.__valid_mode(mode):
            raise ValueError("Invalid combination of MSSFile.open() flags")

        flags = self.__translate_mode(mode)
        self.fd = self.shell.open(self.pathname, flags)
        self.mode = mode

    def close(self):
        if self.fd != -1:
            self.shell.close(self.fd)
            self.fd = -1

            # We only AutoRemove on close() if we open()ed in the past.
            if self.mode & MSSFileMode.AutoRemove:
                self.shell.unlink(self.pathname)

    # XXX: can give issues when running under 'with', think about this.
    # XXX: we may really want to separate out path operations from file
    # operations?  In so far that we switch to a new path, but not a real
    # file here?
    def rename(self, newpath):
        self.shell.rename(self.pathname, newpath)
        self.pathname = newpath

    # Return a new file object, propagating AutoRemove
    def link(self, newpath):
        self.shell.link(self.pathname, newpath)
        if self.mode & MSSFileMode.AutoRemove:
            return MSSFile(self.shell, newpath, MSSFileMode.AutoRemove)

        return MSSFile(self.shell, newpath)

    def __enter__(self):
        if self.mode != MSSFileMode.NotSet:
            self.open(self.mode)

        return self

    def __exit__(self, type, value, traceback):
        if self.fd != -1:
            self.close()
        else:
            # Allow auto-removal of unopened pathnames.
            if self.mode & MSSFileMode.AutoRemove:
                self.shell.unlink(self.pathname)

    def __valid_mode(self, mode):
        if mode == MSSFileMode.NotSet:
            return False

        # We allow only AutoRemove flagged files.  This will never open
        # a descriptor, but unlink the file in __exit__.
        if mode == MSSFileMode.AutoRemove:
            return True

        if not mode & MSSFileMode.ReadWrite:
            return False

        # Read-only and (append or truncate) are not allowed.
        if mode & MSSFileMode.ReadWrite == MSSFileMode.ReadOnly:
            if mode & MSSFileMode.Append:
                return False
            if mode & MSSFileMode.Truncate:
                return False

        return True

    def __translate_mode(self, mode):
        table = {
            MSSFileMode.NotSet : 0,
            MSSFileMode.ReadOnly : self.O_RDONLY,
            MSSFileMode.WriteOnly : self.O_WRONLY,
            MSSFileMode.ReadWrite : self.O_RDWR,
            MSSFileMode.Append : self.O_APPEND,
            MSSFileMode.Truncate : self.O_TRUNC,
            MSSFileMode.Create : self.O_CREAT
        }

        # Translate open flags into system open(2) flags.
        flags = table[(mode & MSSFileMode.ReadWrite)] | \
                table[(mode & MSSFileMode.Append)] |    \
                table[(mode & MSSFileMode.Truncate)] |  \
                table[(mode & MSSFileMode.Create)]

        return flags

if __name__ == "__main__":
    print "yadda"
