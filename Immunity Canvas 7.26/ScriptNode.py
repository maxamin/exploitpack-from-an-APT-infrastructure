#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
#Last modified by steven@immunityinc.com (2014)

"""
ScriptNode.py - used for remote connections from eval() in a scripting environment
"""

from CANVASNode import CrossPlatformNode
from exploitutils import *
from canvaserror import *
from MOSDEFNode import MOSDEFNode
from MOSDEFSock import MOSDEFSock

class ScriptNode(CrossPlatformNode, MOSDEFNode):
    def __init__(self):
        CrossPlatformNode.__init__(self)
        MOSDEFNode.__init__(self)
        self.nodetype="ScriptNode"
        self.pix="ScriptNode"
        self.capabilities +=  ["PHP","upload","download","sock"]
        self.activate_text()
        self.colour="yellow"
        # not working for now, but ill leave it here
        self.server_http = ["HTTP_HOST", 
                            "HTTP_USER_AGENT", 
                            "HTTP_ACCEPT", 
                            "HTTP_ACCEPT_LANGUAGE", 
                            "HTTP_ACCEPT_ENCODING", 
                            "HTTP_CONNECTION",
                            "PATH",
                            "SERVER_SIGNATURE"
                            ]
                            
        self.server_vars = ["SERVER_SOFTWARE", 
                            "SERVER_NAME", 
                            "SERVER_ADDR", 
                            "SERVER_PORT", 
                            "REMOTE_ADDR", 
                            "DOCUMENT_ROOT",
                            "SERVER_ADMIN",
                            "SCRIPT_FILENAME",
                            "REMOTE_PORT",
                            "GATEWAY_INTERFACE",
                            "SERVER_PROTOCOL",
                            "REQUEST_METHOD",
                            "QUERY_STRING",
                            "REQUEST_URI",
                            "SCRIPT_NAME",
                            "PHP_SELF",
                            "REQUEST_TIME_FLOAT",
                            "REQUEST_TIME"
                            ]
        self.env_vars    = ["PATH",
                            "LANG"
                            ]
        # ini settings are setup using a flag value
        # this is to determine if we are reading a string or not
        self.ini_settings = [("safe_mode",              0),
                             ("register_globals",       0), # are all the variables 
                             ("allow_url_fopen",        0), # can we include code remotley?
                             ("allow_url_include",      0), # can we include code remotley?
                             ("variables_order",        1), # Which superglobals are enabled?
                             ("register_argc_argv",     1), # CLI scripts anyone
                             ("register_globals",       0),
                             ("default_socket_timeout", 1), # I feel this would be important to know..
                             ("enable_dl",              0), # can we remotly load shared_objects?
                             ("extension",              1), # which extensions are loaded?
                             ("date.timezone",          1), # timezone of the target server
                             ("sql.safe_mode",          0), # sql safe mode???
                             ("session.name",           1), # get the current session name nornally PHPSESSID
                             ("disable_functions",      1), # the most important, get the list of disabled_functions
                             ]
                             
        
        return 
    
    def recv(self, sock, length):
        return MOSDEFNode.recv(self,sock,length)
    
    def send(self,sock,message):
        return MOSDEFNode.send(self,sock,message)
        
    def getInfo(self):
        
        self.shell.clearPHPSocket()
        
        dfi = self.shell.get_defined_functions_internal()
        self.hostsknowledge.get_localhost().add_knowledge("PHP internally defined functions", dfi, 100, 1)

        dfu = self.shell.get_defined_functions_user()
        self.hostsknowledge.get_localhost().add_knowledge("PHP user defined functions", dfu, 100,)
        
        sapi = self.shell.getPHPSAPI()
        self.hostsknowledge.get_localhost().add_knowledge("PHP SAPI", sapi, 100)
        
        phpver = self.shell.getPHPVersion()
        self.hostsknowledge.get_localhost().add_knowledge("PHP Version", phpver, 100)
        
        # start creating the dic here
        inis = {}

        for ini in self.ini_settings:
            inis[ini[0]] = self.shell.getPHPIniVal(ini[0], ini[1])
            self.log("PHP Node value: %s -> %s"%(ini[0], inis[ini[0]]))
        self.hostsknowledge.get_localhost().add_knowledge("PHP Config", inis, 100)
        
        ## code to populate our disabled_functions_tuple

        df = inis["disable_functions"].split(",") # comma seperated as per 
        self.shell.disable_functions = df
        # determine the available functions based on what is disabled
        self.shell.determine_exec_functions()
        
        
        info = {}
        # test to see if the SERVER superglobal is registered in zends symbol table (highley likely, but still)
        if "S" in inis["variables_order"]:
            #for i in (self.server_http + self.server_vars):
            for i in (self.server_vars):
                info[i] = self.shell.getPHPVar("_SERVER['%s']" % i)
            
        # test to see if the ENV superglobal is registered in zends symbol table
        if "E" in inis["variables_order"]:
            for i in self.env_vars:
                info[i] = self.shell.getPHPVar("_ENV['%s']" % i)
            
        
        self.hostsknowledge.get_localhost().add_knowledge("PHP INFO", info, 100)
        
        os = self.shell.getPlatformInfo()
        if os != None:
            self.hostsknowledge.get_localhost().add_knowledge("OS", os, 100)
        
        try:
            uid,euid,gid,egid = self.shell.ids()
        except NodeCommandError, i:
            pass
        
        #now try to get the pid
        try:
            pid=self.shell.getpid()
            self.log("PID: %d"%pid)
        except NodeCommandError, i:
            pass 
        
        if self.isOnAUnix():
            self.capabilities.append("Unix Shell")
            if hasattr(self.shell, "dospawn"):
                self.capabilities.append("spawn") #we emulate dospawn with the & shell character. This is important for converttomosdef module.
                self.spawn=self.unix_spawn
        return os

    def unix_spawn(self,filename):
        devlog("node", "unix_spawn called with filename: %s"%filename)
        ret = self.shell.dospawn(filename)
        devlog("node", "unix_spawn returning %s"%ret)
        return ret
    
    def createListener(self,addr,port):
        """Create a listener for a connectback"""
        fd=self.shell.getListenSock(addr,port)
        if fd==0:
            return 0
        devlog("phplistener","Created a listener socket: %d"%fd)
        s=MOSDEFSock(fd,self.shell) #a mosdef object for that fd (wraps send, recv, etc) and implements timeouts
        s.set_blocking(0) #set non-blocking
        s.reuse()
        return s
    
if __name__=="__main__":
    node=ScriptNode()

