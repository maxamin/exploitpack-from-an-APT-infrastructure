#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
sqllistener.py

Listener for connections to SQL servers

"""
import os, sys
from shellserver import shellserver

from exploitutils import binstring
import time
from libs import mysqllib, mssql

from internal import devlog
from canvaserror import *

class mysqllistener(shellserver):
    def __init__(self, mysqlobj ,logfunction=None):
        shellserver.__init__(self,mysqlobj._s,type="Active",logfunction=logfunction)

        self.m=mysqlobj
        self.na="This is a mysql listener, type sql command in Piped Command's box"
        return
    
    def startup(self):
        #we got data, and we need to read it...
        return ""
    
    
    def pwd(self):
        return self.na
        
    def sendraw(self,data):
        return 1
    
    def runcommand(self,command):
        """
        Running a command is easy with a shell
        """
        result=""
        command = command.strip()
        if command[ len(command)-1 ] == ";":
            command = command[: len(command)-1 ]
            
        try:
            r=self.m.query(command)
            self.m.fetch_result(r)
            for a in self.m.rows:
                result+= str(a) + "\n"
        except mysqllib.error, msg:
            result=str(msg) 
            
        return result
    
    def dospawn(self,command):
        return ""
    
    def dounlink(self,filename):
        return self.na
    
    def cd(self,directory):
        return self.na
    
    def dodir(self,directory):
        return self.na
    
    def upload(self,source,dest="."):
        raise NodeCommandUnimplemented(self.na)
    
    def download(self,source,destdir="."):
        raise NodeCommandUnimplemented(self.na)
    
    def get_shell(self):
        """
        spawn telnet client with remote end hooked to it
        TODO
        """
        
    def getRemoteHost(self):
        return "%s MySQL %s " % (self.m.getHost(), self.m.getServerVersion())    

    def interact(self):
        while 1:
            self.log("mysql> ", enter="")
            line=sys.stdin.readline().strip()
            if line[ len(line)-1 ] == ";":
                line = line[: len(line)-1 ]
            if line == "quit":
                self.m.close()
                break
            try:
                result=self.m.query(line)
                self.m.fetch_result(result)
                for a in self.m.rows:
                    print a        
            except mysqllib.error, msg:
                print msg

class mssqllistener(shellserver):
    def __init__(self, mssqlobj ,logfunction=None):
        shellserver.__init__(self,mssqlobj.s,type="Active",logfunction=logfunction)

        self.m=mssqlobj
        self.na="This is a mssql listener, only commands in Piped Command's box"
        return
    
    def startup(self):
        #we got data, and we need to read it...
        return ""
    
    def pwd(self):
        return self.runcommand("cd")
        
    def sendraw(self,data):
        return 1
    
    def runcommand(self,command):
        """
        Running a command is easy with a shell
        """
        result=""
        command = command.strip()
        if command[ len(command)-1 ] == ";":
            command = command[: len(command)-1 ]
            
        try:
            resp = self.m.query("xp_cmdshell \"%s\"" % command)
                
            if not resp:
                #returns an empty string on failure
                #typically, recv failed
                return "Failed to get SQL Command Executed"
            
            for a in resp.tokens:
                if a[0] == 0xd1:
                    result+= str(a[1]) + "\n"
                elif a[0] == 0xAA:
                    result=a[1][3]
                elif a[0] == 0x81: #TDS 7+ results
                    #tds results...
                    print "Token type 0x81"
                    result=a[1][-1]
                else:
                    devlog("mssql", "Token type not needed %x"%a[0])

        except mssql.MSSQLError, msg:
            result=str(msg) 
            
        return result

    def dospawn(self,command):
        return ""
        
    def dounlink(self,filename):
        return self.runcommand("del "+filename)
    

    def cd(self,directory):
        return self.runcommand("cd "+directory)
    
    def dodir(self,directory):
        return self.runcommand("dir "+directory)
    
    def upload(self,source,dest="."):
        raise NodeCommandUnimplemented(self.na)
    
    def download(self,source,destdir="."):
        raise NodeCommandUnimplemented(self.na)
    
    def get_shell(self):
        """
        spawn telnet client with remote end hooked to it
        TODO
        """
        
    def getRemoteHost(self):
        return "%s MySQL %s " % (self.m.getHost(), self.m.getServerVersion())    

    def interact(self):
        while 1:
            self.log("mssql> ", enter="")
            line=sys.stdin.readline().strip()
            if not line:
                continue
            if line[ len(line)-1 ] == ";":
                line = line[: len(line)-1 ]
            if line == "quit":
                #self.m.close()
                break
            try:
                resp=self.m.query("xp_cmdshell \"%s\"" % line)
                for a in resp.tokens:
                    if a[0] == 0xd1:
                        self.log(a[1])
                    elif a[0] == 0xAA:
                        self.log(a[1][3])
            except mssql.MSSQLError, msg:
                print "Error: " + str(msg) 
