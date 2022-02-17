from exploitutils import devlog
from WindowsConstants import keyDict
from WindowsConstants import accessDict

SEND_RETURN = {64: "sendlonglong",
                  32: "sendint"
}

HANDLE_TYPE = {64: "long long",
               32: "int"
}

POINTER_TYPE = {64: "long long",
                 32: "int"
}
REMOTE_IMPORT_TYPE = {64: "local",
                      32: "remote"
}


class WindowsMosdefShellServer(object):
    def __init__(self, arch):
        global SEND_FUNCTIONS
        global POINTER_TYPE
        global REMOTE_IMPORT_TYPE
        
        self.bit_width = 64
        
        if arch.endswith("64"):
            self.bit_width = 64
        elif arch.endswith("32"):
            self.bit_width = 32
        else:
            self.bit_width = None

        self.send_return = SEND_RETURN[self.bit_width]
        self.read_return = self.readlonglong if self.bit_width == 64 else self.readint
        self.pointer_type = POINTER_TYPE[self.bit_width]
        self.return_type = POINTER_TYPE[self.bit_width]
        self.handle_type = HANDLE_TYPE[self.bit_width]
        self.import_type = REMOTE_IMPORT_TYPE[self.bit_width]

    def os_version_info(self, major=6):
        code = """
        #import "IMPORT_TYPE", "ntdll.dll|RtlGetVersion" as "RtlGetVersion"

        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"
        #import "local", "sendblock" as "sendblock"
        #import "debug", "debug" as "debug"

        struct RTL_OSVERSIONINFOW {
            int dwOSVersionInfoSize;
            int dwMajorVersion;
            int dwMinorVersion;
            int dwBuildNumber;
            int dwPlatformId;
            short szCSDVersion[128];
            short wServicePackMajor;
            short wServicePackMinor;
            short wSuiteMask;
            // it's possible there's 2 characters here, for padding? I hope not.
            char wProductType;
            char wReserved;
            int pad; //dunno why this is here. But it is.
        };

        int main(){
           int ret;
           int size;
           struct RTL_OSVERSIONINFOW osvi;

           size = 288; // sizeof(RTL_OSVERSIONINFOW) + 4 (for whatever reason)

           // debug();

           memset(&osvi, 0, size);
           osvi.dwOSVersionInfoSize = size;

           RtlGetVersion(&osvi);
           sendint(osvi.dwMajorVersion);
           sendint(osvi.dwMinorVersion);
           sendint(osvi.dwBuildNumber);
           sendint(osvi.dwPlatformId);
           sendblock(&osvi.szCSDVersion, 256);
        }
        """.replace("IMPORT_TYPE", self.import_type)

        self.clearfunctioncache()
        request=self.compile(code,{})
        self.sendrequest(request)
        version_info = {}
        version_info["major"] = self.readint()
        version_info["minor"] = self.readint()
        version_info["build"] = self.readint()
        version_info["platform"] = self.readint()

        sp_name = None
        sp_name_enc = self.readblock()
        self.leave()
        
        if all([byte == "\x00" for byte in sp_name_enc]):
            sp_name = None
        else:
            sp_name = sp_name_enc.decode("utf-16-le")
        
        version_info["service_pack"] = sp_name
        
        return version_info



    def get_integrity_level(self):
        vars = {}
        code = ("""
        #import "IMPORT_TYPE","kernel32.dll|GetCurrentProcess" as "GetCurrentProcess"
        #import "IMPORT_TYPE","kernel32.dll|GetLastError" as "GetLastError"
        #import "IMPORT_TYPE","kernel32.dll|OpenProcess" as "OpenProcess"
        #import "IMPORT_TYPE","advapi32.dll|OpenProcessToken" as "OpenProcessToken"
        #import "IMPORT_TYPE","advapi32.dll|GetSidSubAuthorityCount" as "GetSidSubAuthorityCount"
        #import "IMPORT_TYPE","advapi32.dll|GetSidSubAuthority" as "GetSidSubAuthority"
        #import "IMPORT_TYPE","advapi32.dll|GetTokenInformation" as "GetTokenInformation"
        #import "IMPORT_TYPE","advapi32.dll|IsValidSid" as "IsValidSid"
        
        #import "local", "SEND_RETURN" as "SEND_RETURN"
        #import "local", "free" as "free"
        #import "local", "malloc" as "malloc"

        struct SID_AND_ATTRIBUTES {
          void * sid;
          int attributes;
        };

        void main()
        {
        HANDLE proc_handle;
        HANDLE token_handle;
        int length_needed;
        char * psub_auth_count;
        int * pintegrity_level;
        int ret;
        int last_error;
        struct SID_AND_ATTRIBUTES * ppsid;
        
        proc_handle = GetCurrentProcess();


        // TOKEN_QUERY = 8
        ret = OpenProcessToken(proc_handle, 8, &token_handle);
        if (ret == 0){
           SEND_RETURN(0xffffff0);
           return;
        }



        // TOKEN_INTEGRITY_LEVEL = 25
        ret = GetTokenInformation(token_handle, 25, 0, 0, &length_needed);
        if (ret == 0){
           ppsid = malloc(length_needed);
        }


        if (ppsid == 0){
          SEND_RETURN(0xffffff1);
          return;
        }

        ret = GetTokenInformation(token_handle, 25, ppsid, length_needed, &length_needed);
        if (ret == 0){
           free(ppsid);
           SEND_RETURN(0xffffff2);
           return;
        }

        ret = IsValidSid(ppsid->sid);
        if (ret == 0){
           SEND_RETURN(999);
           return;
        }

        psub_auth_count = GetSidSubAuthorityCount(ppsid->sid);

        pintegrity_level = GetSidSubAuthority(ppsid->sid, *psub_auth_count-1);
        SEND_RETURN(*pintegrity_level);

        free(ppsid);
        return;
        }
        """).replace("SEND_RETURN", self.send_return).replace("IMPORT_TYPE", self.import_type).replace("HANDLE", self.handle_type)

        self.clearfunctioncache()
        request = self.compile(code,vars)

        self.sendrequest(request)
        il = self.read_return()
        self.leave()

        level = None

        if (il >= 0x1000 and il < 0x2000):
            level = "low"
        elif (il >= 0x2000 and il < 0x3000):
            level = "medium"
        elif (il >= 0x3000 and il < 0x4000):
            level = "high"
        elif (il >= 0x4000 and il < 0x5000):
            level = "system"
        elif (il >= 0x5000 and il < 0x6000):
            level = "protected"
        elif (0xffffff0 >= il and il < 0xfffffff):
            self.log("get_process_il failed with return value: %x" % il)
        else:
            self.log("get_process_il obtained unknown integrity level! %x" % il)
            level = il

        return level

    def create_reg_key(self, hkey, key_path, access):
        return_handle = None
        handle = self.RegOpenKeyEx(hkey, key_path, access)
            
        if not handle:
            devlog("winmosdefshellserver", "could not open %s, creating it" % key_path)
            new_handle = self.RegCreateKeyEx(hkey, key_path, access)

            if not new_handle:
                devlog("winmosdefshellserver", "failed to create %s! failing." % (key_path))
                return_handle = None
            else:
                devlog("winmosdefshellserver", "successfully created %s!" % key_path)
                return_handle = handle

        else:
            return_handle = handle
            devlog("winmosdefshellserver", "successfully opened %s" % key_path)

        devlog("winmosdefshellserver", "return_handle is %s!" % str(return_handle))

        return return_handle

    #Registry functions
    def get_reg_key_handle(self, hkey, key_path, access):
        dir_stack = []
        return_handle = None

        key_dirs = key_path.split("\\")
        
        if len(key_dirs) == 0:
            return None
        
        for key_entry in key_dirs[:-1]:
            dir_stack.append(key_entry)

            path = "\\".join(dir_stack)

            handle = self.create_reg_key(hkey, path, access)
            
            if handle == None:
                devlog("winmosdefshellserver", "unable to create reg key: %s" % path)
                break
            else:
                self.RegCloseKey(handle)

        devlog("winmosdefshellserver", "creating final registry key %s" % key_path)
        return_handle = self.create_reg_key(hkey, key_path, access)
        
        return return_handle

    def RegDeleteKeyEx(self, hKey, keyname):
        """
        Delete a subkey of a registry key
        """

        hKey=keyDict.get(hKey,hKey)
        vars={}

        code="""
        #import "%s","advapi32.dll|RegDeleteKeyExA" as "RegDeleteKeyExA"

        #import "local", "%s" as "%s"

        #import "%s", "hKey" as "hKey"
        #import "string", "keyname" as "keyname"



        void main()
        {
        %s ret;
        
        ret=RegDeleteKeyExA(hKey,keyname,0,0);
        %s(ret);
        }
        """ % (self.import_type, self.send_return, self.send_return,
               self.pointer_type,
               self.return_type,
               self.send_return)
        
        vars["keyname"]=keyname
        vars["hKey"]=hKey

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.read_return()
        self.leave()
        return fd


    def RegCreateKeyEx(self,hKey,keyname,access):
        """
        Create a registry key for later use
        """

        hKey=keyDict.get(hKey,hKey)
        access=accessDict.get(access,access)
        vars={}

        # Note: in order for library imports to work, they must be the *exact* same
        # name as they are in the library itself.
        
        code="""
        #import "%s","advapi32.dll|RegCreateKeyExA" as "RegCreateKeyExA"

        #import "local", "%s" as "%s"

        #import "%s", "hKey" as "hKey"
        #import "string", "keyname" as "keyname"
        #import "long", "reserved" as "reserved"
        #import "long", "options" as "options"
        #import "int", "access" as "access"



        void main()
        {
        %s ret;
        %s hKey2;
        %s securityAttributes;
        %s class;
        long options;
        
        securityAttributes = 0;
        class = 0;
        options = 0;
        
        ret=RegCreateKeyExA(hKey,keyname,0,class,options,access,0,&hKey2,0);
        if (ret==0) {
           %s(hKey2); //0 on sucess
           }
        else {
          %s(0);
         }
        }
        """ % (self.import_type, self.send_return, self.send_return, self.pointer_type,
               self.return_type,
               self.pointer_type, self.pointer_type, self.pointer_type,
               self.send_return, self.send_return)
        
        vars["keyname"]=keyname
        vars["hKey"]=hKey
        vars["access"]=access

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.read_return()
        self.leave()
        return fd

    def exit(self, exitcode):
        """
        Calls ExitProcess - MSDN says never to do this from a DLL, which is
        essentially what we do.

        Kostya says that we end up sending XX00XX00 as our exit code, instead of what
        you specify in exitcode. Haven't tracked down this bug yet. Possibly due to DLL's
        trying to clean themselves up in weird states.

        You'll most likely want to call TerminateProcess instead which does not
        let each DLL try to clean up.
        """
        vars={}
        vars["exitcode"]=exitcode


        code="""
        //start of code
        #import "%s","kernel32.dll|ExitProcess" as "ExitProcess"
        #import "int","exitcode" as "exitcode"

        void main()
        {
            int i;
            i=ExitProcess(exitcode);
        }
        """ % (self.import_type)
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()
        return
