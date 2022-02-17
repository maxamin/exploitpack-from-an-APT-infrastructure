#!/usr/bin/env python
"""
automater.py

This module contains a few simple objects designed to be used from XML-RPC
and Immunity Debugger to automate the process of writing an exploit.

"""
import sys
if "." not in sys.path: sys.path.append(".")
from threading import Thread
import timeoutsocket
from exploitutils import *

class debugger_thread(Thread):
    """
    This object keeps a thread running for the XML-RPC server to use. Because
    we use Timeoutsocket, we need to handle socket accept timeouts, which is 
    nice because that way we can also be halted.
    """
    def __init__(self, server, debugger_object):
        self.debugger=debugger_object
        self.server=server 
        Thread.__init__(self)
        self.setDaemon(True)
        self.state="Setup"
        return 
    
    def run(self):
        self.state="Running"
        while 1:
            if self.state=="HALT":
                return 
            try:
                self.server.serve_forever()
            except timeoutsocket.Timeout:
                pass 
            except:
                #interupted system call...ignore...(essentially timeout)
                pass
            
            

    def halt(self):
        self.state="HALT"
        return 
    
class debugger_instance(object):
    """
    Object that stores remote debugger callbacks 
    for XML-RPC
    
    At this stage we will handle only very very simple exploits.
    Ok, our overall process is like so:
    1. You create (or a fuzzer creates) a buffer that crashes the remote target
    2. !sendstate <host> <port>
       First request sends EIP
    3. If EIP==0x41414141
       locate_bad_bytes()
       locate_eip_offset()
       put_int3
       put_shellcode
    
    locate_eip_offset():
       1. EIP is all A's so somewhere in our buffer is a string of A's
          Change this string to be our finder string
          imm.restart_process()
          imm.continue()
          Send attack
          Get EIP again and see what offset that is
          change buffer at offset to 0x41424344 and see if that works!
          
        Modify buffer object so we split it with our EIP object
        
        
          
    """
    def __init__(self, parent):
        self.parent=parent #parent is an appgui object
        self.state="InitialState"
        self.current_bad_char=None
        return
    
    def sendstate(self, debugger_state):
        """
        This is named "sendstate" but from our perspective it is really 
        "getstate".
        
        debugger_state is a tuple of:
        dname, regs, modules
        
        We return either a request for more information or not.
        """

        command = debugger_state[0]
        arguments= debugger_state[1]
        devlog("vs", "Got Command: %s"%command)
        func=getattr(self,"c_%s"%command)
        if not func:
            devlog("vs", "Command %s not found!"%command)
            return "Command %s not found!"%command
        ret=func(arguments)
        #After I return this, I need to sleep a couple seconds to 
        #give the process time to restart, and then resend our attack
        return ret
    
    def get_fuzz_packet(self):
        """
        Sets self.target_object from the first string of A's it finds
        """
        #self.parent is an appgui instance
        packet_list=self.parent.xpacketlist
        for packet in packet_list:
            treeviewcolumn = packet.get_column(0)
            model=packet.get_model()
            for x in model:
                #type of object
                name=x[3].NAME
                devlog("vs", "Found type of object %s"%name)
                #at least 4 A's
                if x[3].repeat>=4 and x[3].string=="A":
                    #this is most likely our object as it is a bunch of A's
                    #XXX: In future, check by changing to B's to be sure we have the right object.
                    self.target_object=x[3]
                    break
                
        if not self.target_object:
            devlog("vs","No target object found!!!")
            return None 

        self.length=self.target_object.repeat
        self.target_object.repeat=1

        return self.target_object
        
        
    def c_InitialSendState(self, arguments):
        """
        Handles the initial sendstate.py request from the debugger
        This will assume you already sent over your attack and it has crashed the target
        """
        #re-init this in case we're restarting
        self.current_bad_char=None
        
        #end re-init block
        
        regs=arguments[0] #first argument is registers
        #for reg in regs:
        #    devlog("vs", "Register: %s: %d"%(reg, dInt(regs[reg])))
        EIP=uint32(regs["EIP"])
        if EIP==uint32(0x41414141):
            self.log("Got EIP as 41414141 - now finding where EIP was in the string!")
            self.get_fuzz_packet() #set self.target_object
            return ("RestartAndRun", ["BadCharLoop"])
        else:
            return ("Done", ["Access Violation without EIP control not handled yet"])

    def c_FindEipOffset(self, arguments):
        """
        We've just send over a searchpattern, and now we'll get the EIP offset
        Arguments are the registers.
        """
        if self.state!="FindingEipOffset":
            #We've never been here before
            self.target_object.string=searchpattern(length/4)+"A"*(length%4)
            if len(self.target_object.string) != length:
                devlog("vs","Error length of target object: %d should be %d"%(len(self.target_object.string),length))
                self.log("Restarting process")
                self.state="FindingEipOffset"
        else:
            #we are finding the eip offset (we already have all the correct bad bytes!)
            regs=arguments[0]
            EIP=dInt(regs["EIP"])
            offset=getsearchpatternoffset(EIP)
            devlog("vs", "Offset for EIP %x is %d"%(EIP, offset))
            self.eip_offset=offset
            
            #set up our badchar loop
            self.badchars=""

        
        return ("RestartAndRun",["BadCharLoop"])
    
    def c_BadCharLoop(self, arguments):
        """
        This will be called over and over as we search for bad characters
        """
        #are we done?
        if self.current_bad_char==0x100:
            devlog("vs", "All bad characters have been found: %s"%prettyhexprint(self.current_bad_char))
            return ("FindEipOffset",[])

        #we're not done - so check to see first argument
        if arguments[0]=="Running":
            #we just called Restart and Run
            #We need to send our attack packet
            if self.current_bad_char==None:
                self.current_bad_char=0
                self.badchars="" #no bad chars to start with
            else:
                self.current_bad_char+=1
            self.target_object.string=("\\x%2.2x"%self.current_bad_char)*self.length
            self.log("Sending bad_char attack to triger AV")
            #now send this packet
            self.parent.regenerateExploitCode()
            self.parent.runExploitFromEngine(self.parent.saved_args)
            self.log("Sent bad char attack to trigger AV")
            #wait a few seconds and then report if there was an AV
            self.log("Waiting a few seconds ... then asking for status")
            ttl=10 #might take a while for us to send our attack as well?
            return ("ReportOnAV", ["BadCharLoop", ttl])
        #otherwise...
        #we've already run an attack looking for bad chars
        elif arguments[0]=="Timeout":
            #found a bad character (process did not crash)
            devlog("vs", "No crash -> badchars+=[0x%2.2x]"%(self.current_bad_char))
            self.badchars+=chr(self.current_bad_char)
        elif arguments[0]=="AV":
            regs=arguments[0]
            EIP=dInt(regs["EIP"])
            eip_string=chr(self.current_bad_char-1)*4 #what EIP should look like
            if EIP!=istr2int(eip_string):
                #found a bad character (could be transformed or neglected)
                devlog("vs", "EIP %x is not %s"%(EIP,prettyhexprint(eip_string)))
                devlog("vs", "Badchars+=[0x%2.2x]"%(self.current_bad_char))
                self.badchars+=chr(self.current_bad_char)
            #otherwise that character is ok
        else: 
            self.current_bad_char=0
        return ("RestartAndRun",["BadCharLoop"])
    
    def JmpToShellcode(self, arguments):
        #look at registers
        pass
    
    def log(self, msg):
        print msg 
        return 
    
def main():
    di=debugger_instance(None)
    regs={"EIP": 0x41414141}
    di.sendstate(("Initial Sendstate", [regs]))
    
    
if __name__=="__main__":
    main()