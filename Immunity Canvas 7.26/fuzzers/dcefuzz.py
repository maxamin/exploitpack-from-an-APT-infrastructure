#! /usr/bin/env python

"""
dcefuzz.py - an MSRPC fuzzer

"""
import sys
if "." not in sys.path:
    sys.path.append('.')
    
from libs.dcemarshall import *
import msrpc
from exploitutils import *
from fuzzers.spike import *

def get_tcp_port(UUID,target):
    """
    Returns an integer on success, None on failure
    """
    log("Mapping %s on %s"%(UUID,target))
    port=msrpc.epmappertotcp(UUID,target) #from msrpc.py
    log("Found port %s"%port)
    return port

def log(msg):
    #fuzzer logger :>
    print "[F] %s"%msg

old_char_t=char_t
class fuzz_char_t(old_char_t):
    def __init__(self,value=None,attributes=[],marshall=None):
        old_char_t.__init__(self,value,attributes,marshall)
        
    def marshall(self):
        #hit up the global dce fuzzer to see if we're a fuzz value
        useme,newvalue=g_dcefuzzer.getfuzzvalue(self)
        if useme:
            self.value=newvalue

        #print "char_t marshall: %s"%prettyprint("%s"%self.value)
        value=old_char_t.marshall(self)
        return value
#now everyone gets to be a fuzzer...        
char_t=fuzz_char_t
    
    
old_wchar_t=wchar_t
class fuzz_wchar_t(old_wchar_t):
    def __init__(self,value=None,attributes=[],marshall=None):
        #value=msunistring(value) # we assume you've done this...
        old_wchar_t.__init__(self,value,attributes,marshall)
        
    def marshall(self):
        #hit up the global dce fuzzer to see if we're a fuzz value
        useme,newvalue=g_dcefuzzer.getfuzzvalue(self)
        if useme:
            #set to unicode because we're a unicode string...
            self.value=msunistring(newvalue)

        #print "wchar_t marshall: %s"%prettyprint("%s"%self.value)
        value=old_wchar_t.marshall(self)
        return value
#now everyone gets to be a fuzzer...        
wchar_t=fuzz_wchar_t

old_dceint=dceint
class fuzz_dceint(old_dceint):
    def __init__(self,value=None,attributes=[],marshall=None):
        old_dceint.__init__(self,value,attributes,marshall)
        
    def marshall(self):
        #hit up the global fuzzer for a new value
        useme,newvalue=g_dcefuzzer.getfuzzvalue(self)
        if useme:
            self.value=newvalue
        #print "dceint marshall: %s"%prettyprint("%s"%self.value)
        value=old_dceint.marshall(self)
        return value
    
#now everyone gets to be a fuzzer...    
dceint=fuzz_dceint

old_dcearray=dcearray
class fuzz_dcearray(old_dcearray):
    def __init__(self,value=None,attributes=[],marshall=None):
        old_dcearray.__init__(self,value,attributes,marshall)
        
    def marshall(self):
        #hit up the global fuzzer for a new value
        useme,newvalue=g_dcefuzzer.getfuzzvalue(self)
        if useme:
            self.value=newvalue
        #print "dceint marshall: %s"%prettyprint("%s"%self.value)
        value=old_dcearray.marshall(self)
        return value
    
#now everyone gets to be a fuzzer...    
dcearray=fuzz_dcearray


global g_dcefuzzer
g_dcefuzzer=None

class fuzzermarshaller(dcemarshaller):
    """
    Our marshaller class
    This doesn't contain any sockets or other interesting objects
    because it needs to be deepcopied
    """
    def __init__(self):
        dcemarshaller.__init__(self)

    def unistring(self,value):
        #print "Unistring: %s"%value
        return msunistring(value)
    
    def longvalue(self,value):
        #print "Longvalue: %s"%value
        return intel_order(value)

        
class dcefuzzer:
    def __init__(self):
        self.marshaller=fuzzermarshaller()
        self.log("Fuzzing initalized")
        self.dceint=fuzz_dceint
        self.wchar_t=fuzz_wchar_t
        self.UUID=""
        self.opcode=-1
        self.create_pkt=None #function we use to create our data
        self.user=""
        self.password=""
        self.skip=0
        self.testing=0 #if we are testing, we don't fuzz...
        self.skipstring=0
        self.basestring=None
        self.context_handle=None #none by default
        #this is the function we call if we need to get a context handle
        self.get_context_handle=None
        self.response_check=None #if we need to look for memory leaks, here's how...
        
        
    def skipvars(self,vars):
        self.skip=vars
        
    def skipstring(self,skipval):
        """
        This is the value to skip - so a skipvars value of 1 and skipstring value of 1 means fuzz the second variable with the second string...
        """
        self.skipstring=skipval
        
    def getfuzzvalue(self,obj):
        """
        inputs an object to potentially change
        only changes one object per run
        """
        if self.testing:
            return 0, None
        myclass=obj.__class__        
        if self.myspike.fuzz_this_variable():
            print "Fuzzing this variable: %s"%myclass
            if myclass==dceint().__class__:
                return 1, self.myspike.get_int()
            #both wchar_t and char_t get the same 
            elif myclass in [wchar_t().__class__, char_t().__class__ ] :
                return 1, self.myspike.get_string()
            elif myclass in [dcearray().__class__]:
                if type(obj.value)==type(""):
                    return 1, self.myspike.get_string()
                elif obj.value.__myclass__ in [dceint().__myclass__]:
                    return 1, [dceint(0xff,[],self.marshaller)]*self.myspike.get_int()
            else:
                print "in getfuzzvalue: TYPE %s not recognized"%(type(obj))
        else:
            #don't fuzz - but if we have a basestring, let's 
            #use that for wchar_t, etc
            if myclass in [wchar_t().__class__, char_t().__class__ ]:
                if self.basestring!=None:
                    return 1, self.basestring
        return 0,None
            
    def log(self,msg):
        log(msg)
        
    def connect(self):
        """
        Using self.connectionList, this function tries to connect
        to the remote target UUID - this way we support any kind
        of connection CANVAS supports
        """
        self.myDCE = msrpc.DCE(self.UUID, self.version, self.connectionList)
        self.myDCE.setUsername(self.user)
        self.myDCE.setPassword(self.password)
        try:
            map=self.myDCE.connect()
            if not map:
                self.raiseError("Could not connect to remote server - service is not running or the host is firewalled.")
        except Exception, msg:
            self.log(msg)
            return 0
        return 1
    
    def disconnect(self):
        """
        We make the garbage collector do the hard work for us here by
        just setting myDCE to None
        """
        self.myDCE=None
        return
    
    def test(self):
        self.testing=1
        ret=self.connect()
        if not ret:
            self.log("Could not connect - returning 0")
            return 0
        #we store our create_pkt as a string to avoid deepcopy errors...
        if callable(self.create_pkt):
            #it's a function
            pkt=self.create_pkt(self.marshaller)
        else:
            #it's a string
            exec "pkt=%s(self.marshaller)"%self.create_pkt
        self.log("Pkt=\n%s"%prettyhexprint(pkt[:500]))
        log("Calling function %x with username and password of %s:%s"%(self.opcode,self.user,self.password))
        ret=None
        try:
            ret = self.myDCE.call(self.opcode, pkt, response=1)
        except Exception, msg:
            self.log(msg)
            return 0
        if hasattr(ret,"stub"):    
            if ret.stub!=None:
                self.log("Length of return data: %s"%len(ret.stub))
                self.log("Function returned %s"%prettyprint(ret.stub))
        self.testing=0
        #now we need to close that socket down
        self.disconnect()
        return 1
        
    def dobasestring(self,basestring):
        """
        Do fuzz for one basestring
        """
        self.log("Fuzzing with basestring: %s"%prettyprint(("%s"%basestring)[:100]))
        self.basestring=basestring
        myspike=self.myspike
        #skip to this variable...
        myspike.current_fuzz_variable=self.skip
        #skip both of these, although really we'll only use one
        myspike.current_string=self.skipstring
        myspike.current_int=self.skipstring
        
        while not self.myspike.done:
    
            ret=self.connect()
            if not ret:
                self.log("Could not connect to target - perhaps service died?")
                break
            if callable(self.create_pkt):
                #we stored it as a function pointer
                pkt=self.create_pkt(self.marshaller)
            else:
                #we store our create_pkt as a string to avoid deepcopy errors...
                exec "pkt=%s(self.marshaller)"%self.create_pkt
            self.log("Pkt=\n%s"%prettyhexprint(pkt[:500]))
            log("Calling function %x with username and password of %s:%s"%(self.opcode,self.user,self.password))
            self.log("Fuzzing: %s:%s:%s"%(myspike.current_fuzz_variable,myspike.current_int,myspike.current_string))
            self.log("Fuzzing with basestring: %s"%prettyprint(("%s"%basestring)[:100]))
            ret=None
            try:
                ret = self.myDCE.call(self.opcode, pkt, response=1)
            except Exception, msg:
                self.log(msg)
            if hasattr(ret,"stub"):    
                if ret.stub!=None:
                    self.log("Length of return data: %s"%len(ret.stub))
                    self.log("Function returned %s"%prettyprint(ret.stub))
            self.myspike.increment()
        self.log("Done with basestring: %s"%prettyprint(("%s"%basestring)[:100]))
        return 
        
    def run(self):
        if not self.test():
            self.log("Could not successfully test this interface...stopping now so you can fix it")
            return 0
        self.log("Testing endpoint of interface passed")

        self.myspike=spike() #initialize it
        for basestring in self.myspike.allbasestrings:
            self.myspike.clear()
            self.dobasestring(basestring)
            
#For testing
def createEnumPkt(marshaller):
    """Creates the MSRPC packet for enum"""

    data=""
    marshaller.define("""

typedef struct  {
   [string] [unique] wchar_t *wkui0_username;
} WKSTA_USER_INFO_0;

typedef struct {
  long num_entries;
  [size_is(num_entries)] [unique] WKSTA_USER_INFO_0 * u_i_0;  
} USER_INFO_0_CONTAINER;

typedef [switch_type(long)] union {  
  [case(0)] USER_INFO_0_CONTAINER * u_i_0_c;  
} USER_INFO;
        
typedef   struct {
  long info_level;
  [switch_is(info_level)] USER_INFO element_91;
} TYPE_5;

        """)
    type5=marshaller.getinstance("TYPE_5")
    ui0=marshaller.getinstance("WKSTA_USER_INFO_0")
    username=wchar_t()
    username.setvalue("A"*50+"\x00\x00")
    ui0.setmember("wkui0_username",username)
    #username.setvalue(None) #null pointer
    ui0c=marshaller.getinstance("USER_INFO_0_CONTAINER")
    ui0c.attributes=["unique"]
    ui0c.setmember("u_i_0",dcearray([],[],marshaller));
    ui0c.setmember("num_entries",dceint(0));
    user_info=marshaller.getinstance("USER_INFO")
    user_info.switchval=0
    user_info.setmember("u_i_0_c",ui0c)
    type5.setmember("info_level",dceint(0));
    type5.setmember("element_91",user_info); #null pointer
    
    """
    long  Function_02( 
    [in] [unique]  [string] wchar_t * server,
    [in,out] TYPE_5 * element_89,
    [in]  long  element_92, //preferred max length
    [out] long * element_93,
    [in,out] [unique] long * element_94 //enum handle
    );
    """
    data=""
    data+=wchar_t(None,["unique"],marshaller).marshall()
    data+=type5.marshall()
    #preferred max length
    data+=dceint(10000,[],marshaller).marshall() 
    #enum handle (zero)
    data+=dcepointer(dceint(0,[],marshaller),["unique"],marshaller).marshall()
    log("Returned data of length %d"%len(data))
    #print "data:\n%s"%prettyhexprint(data)

    return data

def runtest_userenum():
    """
    Run userenum test
    """
    mydcefuzzer=dcefuzzer()
    #mydcefuzzer.skipvars(3)
    mydcefuzzer.create_pkt="createEnumPkt"
    target="192.168.233.130"
    mydcefuzzer.target=target
    mydcefuzzer.connectionList=["ncacn_np:%s[\\browser]"% (target)]
    mydcefuzzer.UUID="6bffd098-a112-3610-9833-46c3f87e345a"
    mydcefuzzer.version="1.0"
    mydcefuzzer.opcode=2
    global g_dcefuzzer
    g_dcefuzzer=mydcefuzzer
    mydcefuzzer.run()
    return

def createWorkstationPkt(marshaller):
    NOTES=""" 
    XP - from unmidl.py
    
    long  Function_1b( [in] [unique]  [string] wchar_t * element_302,
    [in] [unique]  [string] wchar_t * element_303,
    [in] [unique]  [string] wchar_t * element_304,
    [in] [unique]  TYPE_18 ** element_305,
    [in]  long  element_306
    );
    """
    marshaller.define("""
    typedef   struct {
    [size_is(524)] char *element_274;
    } TYPE_18;
    """)
    data=""
    data+=dcepointer(wchar_t(msunistring("\\\\%s"%marshaller.target),["unique"],marshaller),["unique"],marshaller).marshall()
    data+=dcepointer(wchar_t(msunistring("Hello"),["unique"],marshaller),["unique"],marshaller).marshall()
    #null pointer
    data+=dceint(0,[],marshaller).marshall()
    #type_18
    type18=marshaller.getinstance("TYPE_18")
    type18.setmember("element_274",dceint(0,[],marshaller))
    #data+=dcepointer(dcepointer(type18,[],marshaller),[],marshaller).marshall()
    data+=dceint(0,[],marshaller).marshall()
    #element_306
    data+=dceint(0,[],marshaller).marshall()
    log("Returned data of length %d"%len(data))
    #print "data:\n%s"%prettyhexprint(data)
    return data
    

def runtest_workstation():
  
    mydcefuzzer=dcefuzzer()
    #mydcefuzzer.skipvars(1)
    mydcefuzzer.create_pkt="createWorkstationPkt"
    target="192.168.233.130"
    mydcefuzzer.target=target
    mydcefuzzer.connectionList=["ncacn_np:%s[\\wkssvc]"%(target)]
    mydcefuzzer.UUID="6bffd098-a112-3610-9833-46c3f87e345a"
    mydcefuzzer.version="1.0"
    mydcefuzzer.opcode=27
    global g_dcefuzzer
    g_dcefuzzer=mydcefuzzer
    mydcefuzzer.run()
    return

from win32MosdefShellServer import GENERIC_READ
def createOpenSCMPkt(marshaller,machinename="localhost",databasename="database",accessmask=GENERIC_READ):
    data=""
    data+=dcepointer(wchar_t(msunistring(machinename),["unique"],marshaller),["unique"],marshaller).marshall()
    data+=dcepointer(wchar_t(msunistring(databasename),["unique"],marshaller),["unique"],marshaller).marshall()
    data+=dceint(accessmask,[],marshaller).marshall() 
    return data

def runtest_openscm(target):
    connectionList = ["ncacn_np:%s[\\svcctl]"% (target)]
    UUID="367abb81-9844-35f1-ad32-98f038001003"
    version="2.0"
    mydcefuzzer=dcefuzzer()
    mydcefuzzer.user="Administrator"
    mydcefuzzer.password="jbone"
    #mydcefuzzer.skipvars(1)
    mydcefuzzer.create_pkt="createOpenSCMPkt"
    mydcefuzzer.target=target
    mydcefuzzer.connectionList=connectionList
    mydcefuzzer.UUID=UUID
    mydcefuzzer.version=version
    mydcefuzzer.opcode=15
    global g_dcefuzzer
    g_dcefuzzer=mydcefuzzer
    mydcefuzzer.run()
    return
    
def createlsasspkt(marshaller):
    """
long  Function_09( [in]  [string] wchar_t *  element_825,
[in] [unique]  [string] wchar_t * element_826,
[in]  [string] wchar_t *  element_827,
[in]  [string] wchar_t *  element_828,
[in]  [string] wchar_t *  element_829,
[in] [unique]  [string] wchar_t * element_830,
[in] [unique]  [string] wchar_t * element_831,
[in] [unique]  [string] wchar_t * element_832,
[in] [unique]  TYPE_6 ** element_833,
[in] [unique]  TYPE_6 ** element_834,
[in]  long  element_835,
[out] [context_handle]  void * element_836
 );
 
  typedef   struct {
  [size_is(524)] char *element_774;
 } TYPE_6;

    """

    data=""
    log("Getting instance")
    data+=wchar_t(msunistring("hello"),[],marshaller).marshall()
    data+=wchar_t(None,[],marshaller).marshall()
    data+=wchar_t(msunistring("hello"),[],marshaller).marshall()
    data+=wchar_t(msunistring("hello"),[],marshaller).marshall()
    data+=wchar_t(msunistring("hello"),[],marshaller).marshall()

    data+=dceint(0,[],marshaller).marshall() 
    data+=dceint(0,[],marshaller).marshall() 
    data+=dceint(0,[],marshaller).marshall() 
    #data+=wchar_t(msunistring("hello"),["pointer"],marshaller).marshall()
    #data+=wchar_t(msunistring("hello"),["pointer"],marshaller).marshall()
    #data+=wchar_t(msunistring("hello"),[],marshaller).marshall()

    data+=dceint(0,[],marshaller).marshall() 
    data+=dceint(0,[],marshaller).marshall() 
    data+=dceint(0,[],marshaller).marshall() 
    log("Returning data")
    return data

def runtest_lsass(target):
    log("Running lsass test")
    connectionList = ["ncacn_np:%s[\\lsarpc]"% (target)]
    UUID="3919286a-b10c-11d0-9ba8-00c04fd92ef5"
    version="0.0"
    mydcefuzzer=dcefuzzer()
    #mydcefuzzer.user="Administrator"
    #mydcefuzzer.password="jbone"
    #mydcefuzzer.skipvars(1)
    mydcefuzzer.create_pkt="createlsasspkt"
    mydcefuzzer.target=target
    mydcefuzzer.connectionList=connectionList
    mydcefuzzer.UUID=UUID
    mydcefuzzer.version=version
    mydcefuzzer.opcode=9
    global g_dcefuzzer
    g_dcefuzzer=mydcefuzzer
    log("Running fuzzer")
    mydcefuzzer.run()
    log("Fuzzer run done")
    return
    

def createex1pkt(marshaller):
    """
    long  Function_08( [in]  [string] char *  element_52,
    [size_is(16)] [out]  char * element_53
    );
    """
    data=""
    data+=char_t("hell",[""],marshaller).marshall()
    return data

def runtest_exchange1(target):
    log("Running exchange1 test")

    UUID="a4f1db00-ca47-1067-b31f-00dd010662da"
    port=get_tcp_port(UUID,target)
    if not port:
        log("Could not get port for UUID %s"%UUID)
        return 0
    log("Found UUID on port %d"%port)
    connectionList = ["ncacn_ip_tcp:%s[%d]"% (target,port)]
    version="0.81"
    opcode=8
    mydcefuzzer=dcefuzzer()
    #mydcefuzzer.user="Administrator"
    #mydcefuzzer.password="jbone"
    #mydcefuzzer.skipvars(1)
    mydcefuzzer.create_pkt="createex1pkt"
    mydcefuzzer.target=target
    mydcefuzzer.connectionList=connectionList
    mydcefuzzer.UUID=UUID
    mydcefuzzer.version=version
    mydcefuzzer.opcode=opcode
    global g_dcefuzzer
    g_dcefuzzer=mydcefuzzer
    log("Running fuzzer")
    mydcefuzzer.run()
    log("Fuzzer run done")
    return

def runafuzz(target,UUID,version,opnum,pktname,protocol,pipe=None,skip=0):
    log("Running test")

    if protocol=="tcp":
        port=get_tcp_port(UUID,target)
        if not port:
            log("Could not get port for UUID %s"%UUID)
            return 0
        log("Found UUID on port %d"%port)
        connectionList = ["ncacn_ip_tcp:%s[%d]"% (target,port)]
    elif protocol=="namedpipe":
        connectionList = ["ncacn_np:%s[\\%s]"% (target,pipe)]

    mydcefuzzer=dcefuzzer()
    #mydcefuzzer.user="Administrator"
    #mydcefuzzer.password="jbone"
    mydcefuzzer.skipvars(skip)
    mydcefuzzer.create_pkt=pktname
    mydcefuzzer.target=target
    mydcefuzzer.connectionList=connectionList
    mydcefuzzer.UUID=UUID
    mydcefuzzer.version=version
    mydcefuzzer.opcode=opnum
    global g_dcefuzzer
    g_dcefuzzer=mydcefuzzer
    log("Running fuzzer")
    mydcefuzzer.run()
    log("Fuzzer run done")
    return

def ex2(marshaller):
    """
    long  Function_00( [in]  [string] char *  element_55,
    [in]  long  element_56
    );
    """
    data=""
    data+=char_t("hell",[""],marshaller).marshall()
    data+=dceint(0,[],marshaller).marshall()
    return data
    
def runtest_ex2(target):
    runafuzz(target,"a4f1db00-ca47-1067-b31e-00dd010662da","1.0",0,"ex2","tcp")

def create_umpnp1(marshaller):
    """
    long  Function_36( [in]  [string] wchar_t *  element_288,
    [in]  long  element_289,
    [size_is(element_291)] [in]  char  element_290,
    [in]  long  element_291,
    [size_is(element_293)] [out]  char  element_292,
    [in]  long  element_293,
    [in]  long  element_294
    );
    """
    myspike_data=spike_data()
    #element_288
    myspike_data.append(wchar_t(msunistring("T\\R\\Q"),[],marshaller).marshall())
    #element_289
    myspike_data.append(dceint(0xffff,[],marshaller).marshall())
    #fake pointer
    #myspike_data.append(dceint(1111,[],marshaller).marshall())
    myspike_data.start_block("element_290")
    #element_290 - an array of characters
    myarray=dcearray("HELLO",[],marshaller)
    myspike_data.append(myarray.marshall())
    myspike_data.end_block("element_290")
    #element_291
    myspike_data.insert_size("sizeis_char_t","element_290")
    #element_292
    myspike_data.append(dceint(5,[],marshaller).marshall())
    #element_293
    myspike_data.append(dceint(3,[],marshaller).marshall())
    return myspike_data.value

def runtest_umpnpmgr1(target):
    runafuzz(target,"8d9f4e40-a03d-11ce-8f69-08003e30051b","1.0",0x36,create_umpnp1,"namedpipe",pipe="\\ntsvcs",skip=2)

def ex3(marshaller):
    """
    long  Function_01( [in]  [string] char *  element_58,
    [in]  long  element_59
    );
    """
    data=""
    data+=char_t("hell",[""],marshaller).marshall()
    data+=dceint(0,[],marshaller).marshall()
    return data

def ex4(marshaller):
    """
    long  Function_02( 
    [size_is(element_64)] [in]  long  element_62,
    [size_is(element_64)] [in] [unique]  long * element_63,
    [in]  long  element_64
    );
    """
    #who knows how to marshall THIS?
    return 

def ex5(marshaller):
    """
    long  Function_03( [in]  long  element_66,
    [size_is(element_66)] [in]  char  element_67,
    [size_is(element_69)] [out]  char  element_68,
    [in]  long  element_69,
    [size_is(element_71)] [in]  long  element_70,
    [in]  long  element_71,
    [out]  long * element_72
    );
    """
    myspike_data=spike_data()
    #element_66
    myspike_data.append(dceint(0,[],marshaller).marshall())
    #element_67
    myspike_data.start_block("element_67")
    #element_67 - an array of characters
    myarray=dcearray("HELLO",[],marshaller)
    myspike_data.append(myarray.marshall())
    myspike_data.end_block("element_67")
    #element_69
    myspike_data.insert_size("sizeis_char_t","element_67")
    #element_70 - array of ints
    myspike_data.start_block("element_70")
    alist=[]
    for i in range(0,5):
        alist+=[dceint(0,[],marshaller)]
    myarray=dcearray(alist,[],marshaller)
    myspike_data.append(myarray.marshall())
    myspike_data.end_block("element_70")
    #element_71
    myspike_data.insert_size("sizeis_dceint","element_70")


    myspike_data.append(dceint(0xffff,[],marshaller).marshall())
    #fake pointer
    #myspike_data.append(dceint(1111,[],marshaller).marshall())
    #element_291

    #element_292
    myspike_data.append(dceint(5,[],marshaller).marshall())
    #element_293
    myspike_data.append(dceint(3,[],marshaller).marshall())
    return myspike_data.value

def ex_05(marshaller):
    """
    Obvious memory exhaustion bug...
    long  Function_05( [in]  [string] char *  element_78,
    [size_is(element_80)] [out]  char  element_79,
    [in]  long  element_80
    );
    """
    myspike_data=spike_data()
    #element_78
    myspike_data.append(char_t("Hello",[],marshaller).marshall())
    #element_80
    myspike_data.append(dceint(0,[],marshaller).marshall())
    return myspike_data.value
    
def ex_0c(marshaller):
    """
    long  Function_0c( [in]  [string] char *  element_138,
    [in]  long  element_139,
    [in]  long  element_140
    );
    """
    myspike_data=spike_data()
    myspike_data.append(char_t("Hello",[],marshaller).marshall())
    myspike_data.append(dceint(0,[],marshaller).marshall())
    myspike_data.append(dceint(-1,[],marshaller).marshall())
    return myspike_data.value

def ex_0d(marshaller):
    """
    Appears to be a simple memory exhaustion bug as well...
    long  Function_0d( 
    [size_is(element_143)] [in,out]  char  element_142,
    [in]  short  element_143,
    [size_is(element_145)] [out]  short  element_144,
    [in]  long  element_145,
    [in]  long  element_146,
    [in]  long  element_147
    );
    """
    myspike_data=spike_data()
    #pointer if needed
    #myspike_data.append(dceint(0x31313131,[],marshaller).marshall())
    myspike_data.start_block("element_142")
    myarray=dcearray("HELLO",[],marshaller)
    myspike_data.append(myarray.marshall())
    myspike_data.end_block("element_142")
    myspike_data.insert_size("sizeis_char_t","element_142")
    #myspike_data.append("\x05\x00")
    myspike_data.append(dceint(0,[],marshaller).marshall())
    myspike_data.append(dceint(0,[],marshaller).marshall())
    myspike_data.append(dceint(0,[],marshaller).marshall())
    return myspike_data.value
    
def ex_0e(marshaller):
    """
    long  Function_0e(
    [in]  [string] char *  element_149,
    [in]  long  element_150,
    [in]  long  element_151
    );
    """
    myspike_data=spike_data()
    myspike_data.append(char_t("Hello",[],marshaller).marshall())
    myspike_data.append(dceint(0,[],marshaller).marshall())
    myspike_data.append(dceint(0,[],marshaller).marshall())
    return myspike_data.value
    
def ex_11(marshaller):
    """
    long  Function_11( [in] [unique]  [string] char * element_164,
    [in] [unique]  [string] char * element_165
    );
    """
    myspike_data=spike_data()
    myspike_data.append(char_t("Hello",["pointer"],marshaller).marshall())
    myspike_data.append(char_t("Hello2",["pointer"],marshaller).marshall())
    return myspike_data.value
    

  
def ex2_00(marshaller):
    """
    short * Function_00( [in]  long  element_259,
    [out]  short * element_260
    );
    """
    myspike_data=spike_data()
    myspike_data.append(dceint(0,[],marshaller).marshall())
    return myspike_data.value
    
def ex2_03(marshaller):
    """
    long  Function_03( 
    [in]  long  element_278,
    [size_is(*element_280)] [out] [ref] [unique]  char ** element_279,
    [out]  long * element_280,
    [size_is(element_282)] [in]  long  element_281,
    [in]  long  element_282,
    [in]  long  element_283,
    [out]  long * element_284
    );
    """
    myspike_data=spike_data()
    myspike_data.append(dceint(1,[],marshaller).marshall())

    alist=[]
    for i in range(0,5):
        alist+=[dceint(i,[],marshaller)]
    myarray=dcearray(alist,[],marshaller)
    
    myspike_data.start_block("element_70")
    myspike_data.append(myarray.marshall())
    myspike_data.end_block("element_70")
    #element_71
    myspike_data.insert_size("sizeis_dceint","element_70")

    myspike_data.append(dceint(1,[],marshaller).marshall())
    return myspike_data.value

def spool1(marshaller):
    function="""
    long  Function_46( [in] [unique]  [string] wchar_t * element_541,
    [in]  TYPE_8 * element_542,
    [in]  TYPE_1 * element_543,
    [in]  TYPE_20 * element_544,
    [in]  TYPE_35 * element_545,
    [out] [context_handle]  void * element_546
    );
    """
    oldtypes="""
    #for reference
     typedef   [switch_type(long)] union {
  [case(0)] [unique] TYPE_10 *element_95;
  [case(1)] [unique] TYPE_11 *element_125;
  [case(2)] [unique] TYPE_12 *element_130;
  [case(3)] [unique] TYPE_13 *element_152;
  [case(4)] [unique] TYPE_14 *element_154;
  [case(5)] [unique] TYPE_15 *element_158;
  [case(6)] [unique] TYPE_16 *element_164;
  [case(7)] [unique] TYPE_17 *element_166;
  [case(8)] [unique] TYPE_18 *element_169;
  [case(9)] [unique] TYPE_19 *element_171;
 } TYPE_9;
 typedef   [switch_type(long)] union {
  [case(1)] [unique] TYPE_4 *element_22;
  [case(2)] [unique] TYPE_6 *element_44;
  [case(3)] [unique] TYPE_7 *element_68;
 } TYPE_3;

    """
    types="""
  typedef   struct {
  long element_14;
  [size_is(element_14)] [unique] char *element_13;
 } TYPE_1;

 typedef   struct {
  long element_153;
 } TYPE_13;


 typedef   [switch_type(long)] union {
  [case(3)] [unique] TYPE_13 *element_152;
 } TYPE_9;
 
 typedef   struct {
  long element_93;
  TYPE_9 element_94;
 } TYPE_8;

 
 typedef   struct {
  long element_177;
  [size_is(element_177)] [unique] char *element_176;
 } TYPE_20;

  typedef   struct {
  long element_69;
  long element_70;
  long element_71;
 } TYPE_7;

 typedef   [switch_type(long)] union {
  [case(3)] [unique] TYPE_7 *element_68;
 } TYPE_3;
 
  typedef   struct {
  long element_538;
  TYPE_3 element_539;
 } TYPE_35;
 """
    #first , define the types in the marshaller
    marshaller.define(types)
    
    myspike_data=spike_data()
    #element_541
    myspike_data.append(wchar_t(msunistring("T\\R\\Q"),["pointer"],marshaller).marshall())
    #element_542 - let's try to have a null pointer here and see what happens
    myspike_data.append(dcepointer(None,[],marshaller).marshall())
    #element_543 - let's try to have a null pointer here and see what happens
    myspike_data.append(dcepointer(None,[],marshaller).marshall())
    #element_544 - let's try to have a null pointer here and see what happens
    myspike_data.append(dcepointer(None,[],marshaller).marshall())
    #element_545 - let's try to have a null pointer here and see what happens    
    myspike_data.append(dcepointer(None,[],marshaller).marshall())
    #element 546 is only an [out]
    return myspike_data.value
    
    
def runtest_ex2(target):
    """
    Runs a bunch of tests on Exchange Server 2000
    """
    done=[(1, ex3),(3,ex5), (0xc,ex_0c), (0x11, ex_11),(0x00,ex2_00)]
    crashy=[(5,ex_05)] #things that crashed it
    marshall_problems=[(0xd,ex_0d)] #d is boring though
    notdone=[(0x03,ex2_03)]
    for opnum,func in notdone:
        #for the first interface
        #runafuzz(target,"a4f1db00-ca47-1067-b31e-00dd010662da","1.0",opnum,func,"tcp",skip=0)
        runafuzz(target,"89742ace-a9ed-11cf-9c0c-08002be7ae86","2.0",opnum,func,"tcp",skip=0)

def runtest_spooler(target):
    UUID="12345678-1234-abcd-ef00-0123456789ab"
    version="1.0"
    opnum=0x46
    protocol="namedpipe"
    pipe="\\spoolss"
    func=spool1
    runafuzz(target,UUID,version,opnum,func,protocol,pipe=pipe,skip=0)

def svrsvc_1f(marshaller):
    """
    
On win2k attach to services.exe
  
long  Function_1f( [in] [unique]  [string] wchar_t * element_503,
[in]  [string] wchar_t *  element_504,
[size_is(element_507)] [out]  char  element_505,
[in]  [range(0,64000)] long  element_507,
[in]  [string] wchar_t *  element_508,
[in,out]  long * element_509,
[in]  long  element_510
 );
    """
    myspike_data=spike_data()
    #data+=dcepointer(wchar_t(msunistring("\\\\?\\c:\\Bob\\sam.txt\\"),["unique"],marshaller),["unique"],marshaller).marshall()
    myspike_data.append(dceint(0,[],marshaller).marshall())
    #data+=wchar_t(msunistring("Bob"),["unique"],marshaller).marshall()
    myspike_data.append(wchar_t(msunistring("/"+"H"*255),["unique"],marshaller).marshall())
    myspike_data.append(dceint(1,[],marshaller).marshall())
    myspike_data.append(wchar_t(msunistring(""),["unique"],marshaller).marshall())
    #pointer to array of longs
    myspike_data.append(dceint(0,[],marshaller).marshall())
    myspike_data.append(dceint(1,[],marshaller).marshall())
    return myspike_data.value
    
def runtest_svrsvc(target):
    UUID="4b324fc8-1670-01d3-1278-5a47bf6ee188"
    version="3.0"
    opnum=0x1f
    protocol="namedpipe"
    pipe="\\srvsvc"
    func=svrsvc_1f
    runafuzz(target,UUID,version,opnum,func,protocol,pipe=pipe,skip=0)

def runtest():
    target=sys.argv[1]
    #runtest_workstation() #found it
    #runtest_userenum() #nothing
    #runtest_openscm("192.168.16.128") #nothing
    #runtest_lsass(target) #found it
    #runtest_umpnpmgr1(target) # requires sizeof! (found it, sorta)
    #runtest_umpnpmgr2(target) # not done
    #runtest_exchange1(target)
    #runtest_ex2(target)
    #runtest_spooler(target)
    runtest_svrsvc(target)
    
if __name__=="__main__":
    if len(sys.argv)<2:
        print "Usage: dcefuzz.py <host>"
        sys.exit(1)
    runtest()
