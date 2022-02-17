#! /usr/bin/env python

"""

spike.py - a new version of spike

"""
import sys, os
if "." not in sys.path: sys.path.append(".")
sys.path.append("..")
sys.path.append("../")

from exploitutils import *
import socket 
import timeoutsocket 
import base64
import datetime

#ssl support
from libs.tlslite.api import *
 
"""
command="start %s"
files=os.listdir("\\\\.host\\Shared Folders\\tmp\\SPKOUT\\")
for fuzzfile in files:
   os.system(command%fuzzfile)
"""



#stolen from  http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/82465
#Python license which is now under CANVAS license
def dmkdir(newdir):
    """works the way a good mkdir should :)
        - already exists, silently complete
        - regular file in the way, raise an exception
        - parent directory(ies) does not exist, make them as well
    """
    if os.path.isdir(newdir):
        pass
    elif os.path.isfile(newdir):
        raise OSError("a file with the same name as the desired " \
                      "dir, '%s', already exists." % newdir)
    else:
        head, tail = os.path.split(newdir)
        if head and not os.path.isdir(head):
            dmkdir(head)
        #print "_mkdir %s" % repr(newdir)
        if tail:
            os.mkdir(newdir)
            print "Making %s"%newdir
            os.system("chmod 777 %s"%newdir)
    return 


strings=[]
integers=[]
for i in range(0,256):
    integers+=[i]
for x in range(8,33):
    #find border conditions
    for i in range(2**x-16,2**x+16):
        integers+=[i]
#for weird little MIME bugs
strings+=["=\n"*1024]

strings+=["\\\\?\\c:\\test_boot.ini","c:\\test_boot.ini","\\\\?\\PIPE"]
#some files from system32
strings+=[".","calc.exe","cmd.exe","winchat.exe"]
strings+=["%n"*10,"%s"*10,"%25555d","%222222s"]
for c in ["A"," ","\t","B","/","\\","\"","'","\xff","\x14","\x7f","\x00","+","~",".","../","=",";","%","%25","$","@","<",">","<>","*","*/"]:
#for c in ["A"," ","\t","B","/","\\","\"","'","\xff","\x14","\x7f","\x00","+","~",".","../","=",";","%","%25","$","@","<",">","<>"]:
    for i in [1, 50, 128, 300, 500, 512, 1023,1024, 1025,2020,2047,2048,2049,5000,9000,12000,25000,100000]:
        strings+=[c*i] #long strings
strings+=["localhost","127.0.0.1"]
#add a \ to the front of it and a / and a \\%s\
for s in strings[:]:
    strings+=["\\\\?\\", "\\"+s, "/"+s,"\\\\"+s+"\\","<"+s,"<"+s+">","["+s+"]","{"+s+"}","("+s+")"]

#A lot more strings, but we want to catch those off-by-ones!
for i in range(1,2200):
    strings+=["B"*i]

#try to smack printf likes
for stype in ['i','d','u','e','f','g']:
    for x in [15,16,17,30,31,32,33]:
        #find border conditions
        for i in range(2**x-16,2**x+16):
            strings+=["%%%d.%d%s"%(i,i,stype)]

strings+=["A\x00"*2000]

small_string_set=[]
small_string_set+=["B"*2048,"\\\\"+"A"*4096,"Q"*10000, "D"*500000]
#just for testing SMB connectbacks
#small_string_set+=["\\\\172.16.177.1\C\B"]


inttypes={1: "BINARYBIGENDIAN",
          2: "ASCII",
          3: "ONEBYTE",
          4: "BINARYLITTLEENDIANHALFWORD",
          5: "BINARYBIGENDIAN",
          6: "ZEROASCIIHEX",
          7: "ASCIIHEX",
          8: "ASCIIUNSIGNED",
          9: "INTELENDIANWORD",

          }
#16 bit:"BINARYBIGENDIANHALFWORD", "BIGENDIANHALFWORD"

def get_int_from_type(type_of_int, value):
    """
    This function returns a string, which represents that integer of type and value
    """
    ret=None 
    if type_of_int in ["BINARYBIGENDIANHALFWORD", "BIGENDIANHALFWORD"] :
        ret=int2str16(value)
    elif type_of_int=="BINARYLITTLEENDIANHALFWORD":
        ret=int2str16(value, swap=1)
    elif type_of_int in ["INTELENDIANWORD"]:
        #32 bits little endian
        ret=int2str32_swapped(value)
    elif type_of_int in ["ONEBYTE"]:
        ret=chr(value)
    elif type_of_int in ["ASCII"]:
        ret="%s"%value
    return ret 


class block:
    """
    Each SPIKE Block has a unique name and holds information
    that can only relate to one spike instance
    """
    def __init__(self,name,offset):
        self.name=name
        self.offset=offset
        self.endoffset=None #finalized when we end
        self.size=None #finalized when we end
        return

    def end(self,offset):
        self.endoffset=offset
        self.size=self.endoffset-self.offset
        return 

class block_listener:
    """
    Takes an action when a block ends. Essentially used to represent block sizes
    """
    def __init__(self,blockname,offset,mytype,adjustment=0,multiplier=1, data_size=None):
        self.blockname=blockname
        self.type=mytype
        self.adjustment=adjustment
        self.offset=offset #where in the spike_data's self.value we start
        self.multiplier=multiplier
        self.data_size=data_size
        return

    def get_str(self, size):
        """
        returns a string representation of size 
        """
        stringvalue=get_int_from_type(self.type, size)
        if self.type in ["ASCII"]: #TODO: Add to this 
            #limit it to the size we originally allocated, and make sure we pad it to that size
            stringvalue=stroverwrite(" "*self.data_size,stringvalue,0)[:self.data_size]
        return stringvalue

class spike:
    """
    A spike stores state information about our fuzzing progress
    and also has a weird data structure for fuzzing
    """
    def __init__(self):
        self.done=0
        self.allbasestrings=[] #strings for use in all variables
        self.spike_variables={}

        self.init_spike_variables()
        self.current_variable=0
        self.current_int=0
        self.current_string=0
        self.current_fuzz_variable=0
        self.max_fuzz_variable=0
        self.max_fuzz_int=len(self.spike_variables["ints"])
        self.value=spike_data() #our stored value
        self.last_got_string=""
        self.last_got_integer=0
        self.parent=None
        self.children=[]
        return 

    def get_status(self):
        """
        Returns a string of what our status is
        """
        tmp="spk: %s %s"%(self.current_fuzz_variable,self.current_string)
        return tmp

    def fuzz_this_variable(self):
        """
        returns 1 if we're to fuzz the current variable
        """
        #print "fuzz this variable called: %d=?%d"%(self.current_fuzz_variable,self.current_variable)
        ret=0
        if self.current_fuzz_variable==self.current_variable:
            ret=1
        self.inc_current_variable()
        return ret

    def inc_current_variable(self):
        """
        Increments both my current variable and my parents'
        """
        #print "Incrementing current variable: %d"%self.current_variable
        self.current_variable+=1
        if self.parent:
            self.parent.inc_current_variable()
        return

    def link(self, parent):
        """
        Add me to a parent's children list
        """        
        self.parent=parent
        self.current_fuzz_variable=self.parent.current_fuzz_variable
        self.current_int=self.parent.current_int
        self.current_string=self.parent.current_string
        self.current_variable=self.parent.current_variable

        self.parent.children.append(self)
        return 


    def inc_current_int(self):
        """
        Increments the current integer I am using
        """
        self.current_int+=1
        if self.parent:
            self.parent.inc_current_int()
        return 

    def inc_current_string(self):
        self.current_string+=1
        if self.parent:
            self.parent.inc_current_string()
        return 

    def increment(self):
        """
        This increments our state to the next state. If we just finished
        fuzzing an integer or a string, we increment our fuzz variable
        otherwise we continue to fuzz that string
        """
        self.max_fuzz_variable=self.current_variable
        for c in self.children:
            c.increment()
        if self.current_fuzz_variable==self.max_fuzz_variable:
            #print "Done! current_fuzz_variable: %d max_fuzz_variable: %d"%(self.current_fuzz_variable, self.max_fuzz_variable)
            self.done=1 #done fuzzing!
        if self.current_int==self.max_fuzz_int:
            self.current_int=0
            self.current_string=0
            self.current_fuzz_variable+=1
        if self.current_string==self.max_fuzz_string:
            self.current_string=0
            self.current_int=0
            self.current_fuzz_variable+=1
        self.current_variable=0
        self.value=spike_data()
        return 

    def get_int(self):

        value=self.spike_variables["ints"][self.current_int]
        devlog("spike", "Getting integer: %x"%value)
        self.last_got_integer=value
        self.inc_current_int()

        return value

    def get_string(self):
        value=self.spike_variables["strings"][self.current_string]
        self.last_got_string=value 
        self.inc_current_string()
        return value

    def init_spike_variables(self, stringset=None):
        if stringset==None:
            stringset=strings
        self.spike_variables["strings"]=stringset
        self.max_fuzz_string=len(self.spike_variables["strings"])

        self.spike_variables["ints"]=integers
        self.init_basestrings()
        return

    def init_basestrings(self):
        """
        Use these in your fuzzer for all strings if you like - the default string.
        """
        self.allbasestrings+=[None,"","localhost","\\127.0.0.1","\\"+"A"*5000,"http://127.0.0.1/"]
        return 

    def clear(self):
        """
        If we reuse this spike, we should call clear()
        """
        self.current_int=0
        self.current_string=0
        self.current_fuzz_variable=0
        self.current_variable=0
        self.done=0

        return 
    
    def clear_data(self):
        """
        This is used when you abort - you can't do parse_spk twice without it
        """
        self.value=spike_data()
        return 

    def s_int(self, value, type_of_int):
        type_of_int=inttypes.get(type_of_int,type_of_int)
        newvalue=get_int_from_type(type_of_int, value)

        if newvalue==None:
            print "Could not use integer of type %s"%type_of_int
            return False

        self.value.append(newvalue)
        return True

    def s_int_variable(self, value, type_of_int):
        """
        Fuzz an integer value
        """
        if self.fuzz_this_variable():
            ret=self.s_int(self.get_int(), type_of_int)
        else: 
            ret=self.s_int(value, type_of_int)
        return ret

    def s_string(self, astr):
        self.value.append(astr)

    def s_string_variable(self, defaultstring):
        """
        If this is our fuzz variable, then fuzz it
        if not, insert default string

        returns the string we used
        """
        if self.fuzz_this_variable():
            newstring=self.get_string()
        else: 
            newstring=defaultstring
        self.value.append(newstring)
        return newstring

    def s_block_size(self, blockname, blocktype, alloc_size=None):
        """
        Sets up a block size
        """
        return self.value.insert_size(blocktype, blockname, alloc_size)

    def binary(self, binary_str):
        return self.s_binary(binary_str)

    def s_binary(self, binary_str):
        self.value.append(binstring(binary_str))
        return 

    def uni_string(self, default_ascii_string, terminate=1):
        """
        Takes in "ABCD" and makes it "A\x00B\x00C\x00D\x00 and if terminate
        is true, also adds \x00\x00 to null terminate the string
        """
        tmp=[]
        for c in default_ascii_string:
            tmp+=[c,"\x00"]
        if terminate:
            tmp+=["\x00\x00"]
        ret="".join(tmp)
        self.value.append(ret )
        return

    def uni_string_var(self, default_ascii_string, terminate=1):
        "uni_string + variable"
        if self.fuzz_this_variable():
            newstring=self.get_string()
        else: 
            newstring=default_ascii_string
        self.uni_string(newstring, terminate)
        return newstring

    def get(self, encoding=None):
        if not encoding:
            ret=str(self.value)
        elif encoding=="base64":

            ret=base64.b64encode(str(self.value))
        return ret 

    def s_block_start(self, blockname):
        self.value.start_block(blockname)

    def s_block_end(self, blockname):
        self.value.end_block(blockname)




class spike_data:
    """
    Does the SPIKE Block structures
    """
    def __init__(self):
        self.value=""
        self.blocks={}
        self.listeners={}
        return

    def __str__(self):
        return self.value

    def log(self,msg):
        """ override this if you want more logging """
        print "[SPIKEBLOCK] %s"%msg
        return 

    def start_block(self,blockname):
        """
        Allocates a new block object - when this block ends it will check the listeners and do the work
        """
        if blockname in self.blocks:
            self.log("Serious error! SPIKE Block %s reused..."%blockname)
            return
        offset=len(self.value)
        #allocate new block
        self.blocks[blockname]=block(blockname,offset)
        return 

    def end_block(self,blockname):
        """
        Called whenever a block ends - also does listener work
        """
        if blockname not in self.blocks:
            self.log("Serious error. SPIKE Block %s not found!"%blockname)
            return 

        ended_block=self.blocks[blockname]
        offset=len(self.value)
        ended_block.end(offset)
        #now for each listener, figure out what it wants me to do
        #and do it...
        if blockname in self.listeners:
            #a list of our listeners
            for l in self.listeners[blockname]:
                self.resolve_listener(l)
        return

    def resolve_listener(self,listener):
        """
        Does the hard work of figuring out what to do with a listener and our current state
        """
        blockname=listener.blockname
        bl=self.blocks[blockname]
        blockoffset=bl.offset
        blocksize=bl.size
        if listener.type in ["sizeis_char_t","sizeis_wchar_t","sizeis_dceint"]:
            #for sizeis we cheat and rip the size right out of the string header 
            #strings are stored as <size><0><size> in characters...
            size=str2littleendian(self.value[blockoffset:blockoffset+4])
            if listener.type in ["sizeis_wchar_t"]:
                size=size*2 #size is in bytes, the string stored length in characters                
            elif listener.type in ["sizeis_dceint"]:
                size=size*4 #ints are 4 bytes each
            newstr=int2str32_swapped(sint32(size))
        else:
            newstr=listener.get_str(blocksize)
        self.value=stroverwrite(self.value,newstr,listener.offset)            
        return

    def insert_size(self,sizetype,blockname, alloc_size=None):
        """
        Inserts the size as a listener, also resolves this size if the
        block has already ended
        """
        if alloc_size==None:
            #default
            newint=get_int_from_type(sizetype, 0)
            size=len(newint)
        else:
            #mostly used for ascii string types
            size=alloc_size


        offset=len(self.value)
        bl=block_listener(blockname,offset,sizetype, data_size=size)
        resolved=False 
        if blockname in self.blocks:
            #if we already have this block and if
            #this block has already ended...
            if self.blocks[blockname].size!=None:
                self.resolve_listener(bl)
                resolved=True 

        if not resolved:
            #we did not have this block or it has not finished
            self.add_block_listener(bl)
            self.append("\x00"*size) #insert some padding here now for our integer later
        return 

    def add_block_listener(self, block_listener):
        """
        Adds a new block listener
        """
        #add it to the list in our dictionary here...
        blockname=block_listener.blockname
        if blockname not in self.listeners:
            self.listeners[blockname]=[block_listener]
        else:
            self.listeners[blockname].append(block_listener)
        return 

    def append(self,astr):
        """
        Appends to the end of our string. Quite bad in some ways because this is so clearly O(N)!
        """
        self.value+=astr


#############################################################
#End SPIKE data 
#############################################################

def load_spk(scriptname):
    lines=[]
    for directory in [".","fuzzers/SPIKESCRIPTS/","SPIKESCRIPTS/"]:
        fname=os.path.join(directory, scriptname)
        try:
            #you need ascii mode here so that windows people 
            #can write SPIKE scripts with \x0d\x0a as newlines.
            lines=file(fname,"ra").readlines()
        except:
            pass 
    return lines

def run_on_target(target,port,scriptname,protocol="TCP", ipver="IPv4", currentfuzzvariable=0, currentstring=0, sleeptime=0.2, linemode=False, oldstyle=False, threshold=1, maxlength=None, usessl=False, clientmode=False, multicast=False ):
    """
    Runs a script on our spike against our target using protocol, port and ip version as specified
    """
    stamp = get_current_time()
    print "Running script %s against %s:%d"%(scriptname,target,port)
    #deal with MAXLENGTH
    if maxlength:
        print "Setting maxlength to %d"%maxlength
        for tstring in strings:
            if len(tstring) > maxlength:
                strings.remove(tstring)
    #end deal with MAXLENGTH
    timeout=0.5
    lines=load_spk(scriptname)
    if lines==[]:
        print "Could not read %s"%scriptname
        usage()
        return 
    spk=spike()
    spk.current_fuzz_variable=currentfuzzvariable
    spk.current_string=currentstring
    connect_fail = 0
    if protocol=="UDP":
        prot=socket.SOCK_DGRAM
    elif protocol=="TCP":
        prot=socket.SOCK_STREAM
        
    if ipver=="IPv4":
        family=socket.AF_INET
    elif ipver=="IPv6":
        family=socket.AF_INET6

    if clientmode:
        #we get our socket now and bind it to our listening port and ip
        listensock=getudplistener(port)
        listensock.set_timeout(None)
        if not listensock:
            print "Could not listen on that host and port!"
            return 0
        if multicast:
            #multiaddress='239.255.255.250'
            #multiaddress='225.100.100.100'
            devlog("spike", "Setting up multicast listener on %s"%multicast)
            mreq = struct.pack('4sl', socket.inet_aton(multicast), socket.INADDR_ANY)
            listensock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s=listensock
            
    try:
        while not spk.done and connect_fail < threshold:
            devlog("spike","Spike is at %d %d"%(spk.current_fuzz_variable,spk.current_string))

            parse_spk(spk, lines, oldstyle=oldstyle)
            #now our spike is all set up
            #should use dictionary lookups here

            if not clientmode:
                devlog("spike", "Not in clientmode - getting tcp socket")
                #get our socket if we are not in clientmode
                s=socket.socket(family, prot)
                s.set_timeout(timeout)
                
                
            if clientmode:
                devlog("spike", "In clientmode: protocol=%s"%protocol)
                if protocol=="TCP":
                    s=listensock.accept()
                    data=s.recv(5000)
                elif protocol=="UDP":
                    print "Waiting for UDP packet"
                    data,addr=listensock.recvfrom(5000)
                    print "Data: %r"%data
                    
                
            else:
                
                try:
                    s.connect((target,port))
                except:
                    #import traceback
                    #traceback.print_exc(file=sys.stderr) 
                    stamp = get_current_time()
                    print "%s Failed to connect to %s:%d ...exiting"%( stamp, target,port)
                    print "Protocol: %s"%protocol
                    print "Spike was at %d %d"%(spk.current_fuzz_variable,spk.current_string)
                    print "Out of a maximum of %d %d"%(spk.max_fuzz_variable-1, spk.max_fuzz_string)
                    print "Last Gotten String (%d): %s"%(len(spk.last_got_string),prettyprint(spk.last_got_string))
                    print "Connection Failure #%d (Threshold: %d)" % ( connect_fail, threshold )
                    connect_fail += 1
    
                    spk.clear_data()
                    continue

            if usessl:
                #HANDLE SSL HERE
                settings=HandshakeSettings()
                settings.minKeySize=512 #some servers have a very small key
                settings.maxVersion=(3,1) #servers hate it when you are TLSv1.1

                devlog("spike","Doing TLS Connection")
                try:
                    connection=TLSConnection(s)
                    connection.handshakeClientCert(settings=settings)
                    s=connection
                except TLSAbruptCloseError:
                    print "TLS Abrupt Close Error"
                    connect_fail += 1
                    spk.clear_data()
                    continue
                except socket.error:
                    print "Connection failed to SSL server"
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    connect_fail +=1 
                    spk.clear_data()
                    continue

            if connect_fail >= threshold:
                stamp = get_current_time()
                print "%s Connection failure threshold reached, perhaps you should check the debugger." % stamp
                sys.exit(1)

            value=str(spk.value)
            if protocol=="UDP":
                value=value[:65500]

            try:   
                if linemode:
                    devlog("spike", "Linemode chosen")
                    try:
                        #wait for response
                        data=s.recv(5000)
                        devlog("spike", "Banner Data=%s"%prettyprint(data))
                    except timeoutsocket.Timeout:
                        pass 


                    #split into lines
                    datalines=value.split("\n")
                    for line in datalines:
                        #send line
                        devlog("spike","Sending %s"%prettyprint(line))
                        s.sendall(line+"\n")
                        #wait for response
                        data=s.recv(5000)
                        devlog("spike", "Data=%s"%prettyprint(data))
                else:
                    #not linemode
                    devlog("spike","Sending %s"%prettyprint(value[:256]))
                    if usessl:
                        try:
                            #send is the same as sendall()
                            ret=s.send(value)
                            print "Sent %s data"%ret 
                        except TLSAbruptCloseError:
                            print "TLS Abrupt Close Error"
                            connect_fail += 1
                    else:
                        if clientmode and protocol=="UDP":
                            ret=listensock.sendto(value,addr)
                        else:
                            ret=s.sendall(value)
                if not (clientmode and protocol=="UDP") :
                    s.close()
            except socket.error, message:
                stamp = get_current_time()
                print "%s Error: %s" % ( stamp, message )
            except timeoutsocket.Timeout:
                pass
            time.sleep(sleeptime)
            spk.increment()
    except KeyboardInterrupt:
        stamp = get_current_time()
        print "%s Interrupted. Spike was at %d %d" % ( stamp, spk.current_fuzz_variable,spk.current_string )
        print "Out of a maximum of %d %d" % ( spk.max_fuzz_variable-1, spk.max_fuzz_string)
        print "Last Gotten String (%d): %s" % ( len(spk.last_got_string),prettyprint(spk.last_got_string))
    print "%s Fuzzing has finished" % stamp
    return 

def get_current_time():

    now   = datetime.datetime.now()
    stamp = ("[%2d:%2d:%2d]=>" % ( now.hour, now.minute, now.second )).replace(" ","0")
    return stamp

def parse_spk(spk, lines, oldstyle=False):
    """
    """
    if type(lines) == type(""):
        #string, so is a filename
        lines=load_spk(lines)
        if lines==[]:
            print "Error reading file %s"%lines

    if oldstyle:
        for line in lines:
            #if the line is not a comment, execute it on our spike
            line=line.strip()
            if line!="" and line[0]!="#":
                toeval="spk."+line
                #print "Evaling %s"%toeval
                exec (toeval)
    else:
        #all in one file as a python script
        alllines="".join(lines)
        #print "Alllines: %s"%prettyprint(alllines)
        exec(alllines)
    return 

def run_on_files(fileheader, scriptname, currentfuzzvariable, currentstring, oldstyle):
    dmkdir("/tmp/SPKOUT/")
    print "Running script %s with fileheader: %s"%(scriptname,fileheader)
    try:
        lines=file(scriptname,"rb").readlines()
    except:
        print "Could not read %s"%scriptname
        usage()
        return 
    spk=spike()
    spk.current_fuzz_variable=currentfuzzvariable
    spk.current_string=currentstring
    try:
        while not spk.done:
            parse_spk(spk, lines, oldstyle)
            #now our spike is all set up
            value=str(spk.value)
            filename="/tmp/SPKOUT/%d_%d_%s"%(spk.current_fuzz_variable, spk.current_string, fileheader)

            fd=file(filename,"wb")
            fd.write(value)
            fd.close()
            print "Wrote %d bytes to %s"%(len(value),filename)
            spk.increment()
            #end while loop
    except KeyboardInterrupt:
        print "Interrupted. Spike was at %d %d"%(spk.current_fuzz_variable,spk.current_string)
        print "Out of a maximum of %d %d"%(spk.max_fuzz_variable-1, spk.max_fuzz_string)
        print "Last Gotten String (%d): %s"%(len(spk.last_got_string),prettyprint(spk.last_got_string))
    print "Fuzzing has finished"
    return 

def usage():
    print "USAGE: spike.py -t target -p port -s scriptname -P protocol -i ipver -S sleeptime -V currentvariable[:currentstring] -E -C IP"
    print "or: spike.py -s scriptname -F fileheader -V currentvariable[:currentstring]"
    print "-O for old-style spk scripts"
    print "-T timeout threshold (how many times you will allow a connect failure before giving up)"
    print "-L for linemode (FTP/SMTP, or similar)"
    print "-E is for SSL mode (currently not supported in Line-Mode, sorry)"
    print "-C <ip to listen on> for clientmode"
    print "-m for multicast"
    
    return 

def main(args):
    """
    Runs a SPIKE script against a target
    """
    import getopt
    #defaults
    target="localhost"
    port=80
    scriptname="test.spk"
    protocol="TCP"
    ipver="IPv4"
    currentfuzzvariable=0
    currentstring=0
    sleeptime=float("0")
    linemode=False 
    fileheader=""
    oldstyle=False
    threshold=1
    maxlength=None 
    usessl=False 
    clientmode=False 
    multicast=False 
    #getargs 
    try:
        (opt, args) = getopt.getopt(args, "t:p:s:P:i:V:S:LF:OT:M:EC:m:")
    except:
        usage()
        return 

    for o, a in (opt):
        if o == "-t":
            target=a
        if o == "-p":
            port=int(a)
        if o == "-s":
            scriptname=a
        if o == "-E": #for encryption
            usessl=True
        if o =="-P":
            protocol=a.upper()
        if o == "-i":
            ipver=a
        if o == "-S":
            sleeptime=float(a)
        if o == "-L":
            linemode=True 
        if o == "-F":
            fileheader=a
        if o == "-O":
            oldstyle=True 
        if o == "-T":
            threshold = int(a)
        if o == "-M":
            maxlength=int(a)
        if o == "-C":
            #clientmode gets the IP to listen on as an argument
            clientmode=a
        if o == "-m":
            multicast=a

        if o == "-V":
            if ":" in a:
                currentfuzzvariable, currentstring = a.split(":")
            else:
                currentfuzzvariable = a
            currentfuzzvariable=int(currentfuzzvariable)
            currentstring=int(currentstring)


    if not fileheader:    
        run_on_target(target, port, scriptname, protocol, ipver, currentfuzzvariable, currentstring, sleeptime, linemode, oldstyle, threshold, maxlength, usessl, clientmode, multicast)
    else:
        run_on_files(fileheader, scriptname, currentfuzzvariable, currentstring, oldstyle)
    return


if __name__=="__main__":
    main(sys.argv[1:])
