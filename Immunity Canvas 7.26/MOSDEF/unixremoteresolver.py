#! /usr/bin/env python

from internal import devlog

class ResolveException(Exception):
    """
    Base class for all exceptions thrown in unixremoteresolver.
    """
    pass

class NoResolver(ResolveException):
    """
    Exception raised when there is no remote resolver.
    """
    pass

class LibraryNotLoaded(ResolveException):
    """
    Exception raised when a library could not be dynamically loaded.
    """
    def __init__(self, library):
        self.library = library # name of the foreign library we tried to load

    def __str__(self):
        return 'Could not load foreign library %s' % self.library

class SymbolNotResolved(ResolveException):
    """
    Exception raised when a symbol could not be resolved.
    """

    def __init__(self, symbol, library):
        self.symbol  = symbol   # name of the symbol we tried to resolve
        self.library = library  # name of the library that symbol belongs to

    def __str__(self):
        return 'Could not resolve foreign symbol %s in %s' % (self.symbol, self.library)


class unixremoteresolver():
    """
    This class wraps remote resolving functionality into a consistent API
    (that is the same as that of the windows resolvers). It should be mixed-in
    to arch/cpu specific classes that inherit from remoteresolver. Examples
    include x86osxremoteresolver, x64osxremoteresolver etc.
    """

    def __init__(self):
        # True if remote resolver is working/active, False otherwise
        # Mixed in classes are supposed to set this once they have determined
        # the proper status at the remote end
        self.remote_resolver = False

    def getprocaddress_real(self, library, function):
        """
        Does the library loading and symbol resolution

        library should be a string of the form "libxxx.so.1" or "libxxx.dylib"
        function is the symbol to resolve
        """

        devlog('unix', 'getprocaddress_real: %s %s' % (library, function))
        if not self.remote_resolver: raise NoResolver('We do not have an active remote resolver')

        if library: # Try to load foreign library if it is needed first
            vars            = {}
            vars['library'] = library

            code = """
            #import "string", "library"     as "library"
            #import "local",  "dlopen"      as "dlopen"
            #import "local",  "sendpointer" as "sendpointer"

            void main()
            {
                void *ret;

                ret = dlopen(library);
                sendpointer(ret);
            }
            """
            self.savefunctioncache()
            self.clearfunctioncache()
            request = self.compile(code,vars)
            self.restorefunctioncache()
            self.sendrequest(request)
            ret = self.readpointer()
            self.leave()

            if ret == 0: raise LibraryNotLoaded(library)

        # Do symbol resolution after library loading
        vars             = {}
        vars['function'] = function
        vars['handle']   = ret if library else 0

        code = """
        #import "string",  "function" as "function"
        """

        if hasattr(self, "LP64") and self.LP64:
            code += """
            #import "long long", "handle" as "handle"
            """
        else:
            code += """
            #import "int", "handle" as "handle"
            """

        code += """
        #import "local", "sendpointer" as "sendpointer"
        #import "local", "dlsym"       as "dlsym"

        void main()
        {
            void *i;
            i = dlsym(handle, function);
            sendpointer(i);
        }
        """

        self.savefunctioncache()
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.restorefunctioncache()
        self.sendrequest(request)
        ret = self.readpointer()
        self.leave()

        if library and ret != 0:
            self.remotefunctioncache[library + "|" + function] = ret
        elif not library and ret != 0:
            self.remotefunctioncache[function] = ret
        else:
            raise SymbolNotResolved(function, library)

        devlog("unix", "getprocaddress for %s returned: %x" % (str(library) + "|" + function, ret))
        return ret


    def getprocaddress(self, functionspec):
        """
        emulate getprocaddress from windows

        functionspec can be of the form 'library|symbol' or 'symbol' we detect
        this and dispatch accordingly
        return address of function if found or throw exception otherwise
        """
        devlog("unix", "getprocaddress: %s" % functionspec)

        try:
            functionkey = self.remotefunctioncache[functionspec]
        except KeyError:
            functionkey = False

        if functionkey:
            devlog("unix", "Returning Cached value for %s->%x" % (functionspec, functionkey))
            return functionkey

        self.log("%s not in cache - retrieving remotely." % functionspec)

        tokens = functionspec.split('|')
        tokens_size = len(tokens)

        if tokens_size == 1: # Simple symbol resolution
            return self.getprocaddress_real(None, functionspec)
        elif tokens_size == 2: # Library load + symbol resolution
            return self.getprocaddress_real(tokens[0], tokens[1])
        else:
            raise ResolveException('malformed function specifier %s in getprocaddress()' % functionspec)


    def getRemoteFunctionCached(self,function):
        if function in self.remoteFunctionsUsed.keys():
            return 1
        return 0

    def addToRemoteFunctionCache(self,function):
        self.remoteFunctionsUsed[function] = 1

    def savefunctioncache(self):
        self.sfunctioncache = (self.functioncache,self.remoteFunctionsUsed)


    def restorefunctioncache(self):
        (self.functioncache,self.remoteFunctionsUsed)=self.sfunctioncache


    def getremote(self, function):
        self.savefunctioncache()
        procedure = self.getprocaddress(function)
        self.restorefunctioncache()
        return procedure # 0 if not found

