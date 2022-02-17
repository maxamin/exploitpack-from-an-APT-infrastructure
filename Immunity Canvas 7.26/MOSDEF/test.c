#import "remote", "kernel32.dll|CloseHandle" as "CloseHandle"
        #import "remote", "advapi32.dll|GetTokenInformation" as "GetTokenInformation"
        #import "remote", "advapi32.dll|OpenProcessToken" as "openprocesstoken"
        #import "remote", "advapi32.dll|LookupAccountSidA" as "LookupAccountSid"
        
        #import "int", "accessrights" as "accessrights"
        #import "int", "pid" as "pid"
        
        #import "local","sendint" as "sendint"
        #import "local","sendstring" as "sendstring"
        
        struct SID_AND_ATTRIBUTES {        
        char *Sid;
        int Attributes;
        };
        
        struct TOKEN_USER {
        struct SID_AND_ATTRIBUTES User;
        }; 

