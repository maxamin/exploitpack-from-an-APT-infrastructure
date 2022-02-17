#! /usr/bin/env python

from subC import subC
from ANSI import ANSI

from internal.debug import devlog

NOTES = """
We will generate API call wrappers, to translate between our
IL calling convention and Win64 API calling convention. This
allows us to remain platform agnostic in our IL layer.

The downside is we have to prototype API calls to generate
the appropriate wrappers for them. We will define any and
all commonly used CANVAS Win API calls here, and also give
the option to define your own prototypes in custom MOSDEF-C
code. (re: 3rd parties)

E.g. node.shell.runCode(code, vars, prototypes), as opposed
to node.shell.runCode(code, vars)

Prototyping does not have to complex, can be a simple
dll based 2dimensional-dictionary.

e.g. for function something.dll|FunctionNameA(int arg1);
you would prototype something like:

prototypes['something.dll']['FunctionNameA'] = 1, which would
wrap out to something like

int
FunctionNameA(int arg1)
{
    int ret;
    ret = Win64Call_1(RESOLVED_FunctionNameA, arg1);
    return ret;
}

Where Win64Call_1 is auto-generated, and FunctionNameA wrapper is
also auto-generated from the prototypes.

NOTE:

remote imports happen through 'remote64' on Win64, e.g:

#import "remote64", "ws2_32.dll|recv" as "RESOLVED_recv"

long long imports happen through 'long long', e.g.:

#import "long long" ...

"""

class Win64(ANSI, subC):

    def __init__(self):

        self.debug = False

        ANSI.__init__(self)
        subC.__init__(self)
        # prototypes for wrapper generation
        self.prototypes = {}
        # kernel32.dll
        # remember, you're going to have to translate msdn prototypes to their most basic MOSDEF-C counterpart
        self.prototypes['kernel32.dll'] = {
            # XXX: remember to , single arg tuples, or they get turned into str
            'LoadLibraryA'               : ['long long', ('char * lpFileName',)],
            'GetProcAddress'             : ['long long', ('long long hModule', 'char * lpProcName')],
            'FreeLibrary'                : ['int', ('long long hModule', )],
            # we never set GMEM_MOVABLE so handles are actually 64b pointers
            'GlobalFree'                 : ['long long', ('long long hMem',)],
            'GlobalAlloc'                : ['long long', ('int uFlags', 'int dwBytes')],
            'DuplicateHandle'            : ['int', ('long long hSourceProcess', 'long long hSourceHandle', 'long long hTargetProcess', 'int * lpTargetHandle', 'int dwDesiredAccess','int bInheritHandles', 'int dwOptions')],
            'CreateFileA'                : ['long long', ('char* lpFileName', 'int dwAccess','int dwSharedMode','int lpSecAttr',
                                                      'int dwCreationDisposition','int dwFlags','long long hTemplateFile')],
            'WriteFile'                  : ['int', ('long long hFile', 'char *lpBuffer', 'int dwBytes', 'int *lpNumberOfBytesWritten', 'char *lpOverlapped')],
            'ReadFile'                   : ['int', ('long long hFile', 'char* lpBuffer', 'int dwBytes', 'int *lpNumberOfBytesRead', 'char *lpOverlapped')],
            'CreatePipe'                 : ['int', ('long long *hReadPipe', 'long long *hWritePipe', 'char *lpPipeAttributes', 'int nSize')],
            'GetFileInformationByHandle' : ['int', ('long long hFile', 'char* lpFileInformation')],
            'GetEnvironmentVariableA'    : ['int', ('char* lpName', 'char* lpBuffer', 'int nSize')],
            'CreateThread'               : ['long long', ('long long lpThreadAttributes', 'long long dwStackSize', 'long long lpStartAddress', 'long long lpParameter', 'int dwCreationFlags', 'long long lpThreadId')],
            'CloseHandle'                : ['int', ('long long hFile',)],
            'DeviceIoControl'            : ['int', ('long long hDevice', 'int dwIoControlCode', 'long long lpInBuffer', 'int nInBufferSize',
                                                    'long long lpOutBuffer', 'int nOutBufferSize', 'long long lpBytesReturned',
                                                    'long long lpOverlapped')],
            'GetCurrentProcess'          : ['long long',() ],
            'GetModuleHandleA'           : ['long long',('char *lpModuleName',) ],
            'GetModuleHandleExA'         : ['int',('int dwFlags', 'char *lpModuleName', 'long long phModule')],
            'GetStartupInfoA'            : ['void',('int * lpStartupInfo',) ],
            'GetComputerNameA'           : ['int', ('char *lpbuffer','int *lpnsize')],
            'CreateProcessA'             : ['int',('char * lpApplicationName', 'char* lpCommandLine', 'char *lpProcessAttributes', 'char *lpThreadAttributes', 'int bInheritHandles', 'int dwCreationFlags', 'char *lpEnvironment', 'char *lpCurrentDirectory', 'char *lpStartupInfo', 'char *lpProcessInformation') ],
            'FindFirstFileA'             : ['long long', ('char* lpFileName', 'int* lpFindFileData')],
            'FindFirstFileW'             : ['long long', ('short* lpFileName', 'int* lpFindFileData')],
            'FindNextFileA'              : ['long long', ('char* lpFileName', 'int* lpFindFileData')],
            'FindNextFileW'              : ['long long', ('short* lpFileName', 'int* lpFindFileData')],
            'FindClose'                  : ['int', ('long long handle',)],
            'GetLastError'               : ['int',()],
            'GetTickCount'               : ['int', ()],
            'RemoveDirectoryA'           : ['int', ('char *filename',)],
            'GetCurrentThreadId'         : ['int',()],
            'GetCurrentThread'           : ['long long', ()],
            'ExitThread'                 : ['void',('int dwExitCode',)],
            'ExitProcess'                : ['void',('int dwExitCode',)],
            'CreateToolhelp32Snapshot'   : ['int',('int dwFlags','int th32ProcessID')],
            'Process32First'             : ['int',('int hSnapshot', 'char *lppe')],
            'Process32Next'              : ['int',('int hSnapshot', 'char *lppe')],
            'CloseHandle'                : ['int',('long long hObject',)],
            'PeekNamedPipe'              : ['int',('long long hNamedPipe', 'char* lpBuffer', 'int nBufferSize', 'int *nBufferSize', 'int *lpTotalBytesAvail', 'int *lpTotalBytesAvail')],
            'GetExitCodeThread'          : ['int',('long long hThread', 'char* lpExitCode')],
            'Sleep'                      : ['void',('int dwMilliseconds',)],
            'VirtualFree'                : ['int',('int* lpAddress', 'int dwSize', 'int dwFreeType')],
            'VirtualAlloc'               : ['long long',('int* lpAddress', 'int dwSize', 'int flAllocationType','int flProtect')],
            'VirtualAllocEx'             : ['long long',('long long hProcess', 'int * lpAddress', 'int dwSize','int flAllocationType','int flProtect')],
            'GetVersionExA'              : ['int',('char *lpVersionInfo',)],
            'GetCurrentProcessId'        : ['int',()],
            'OpenProcess'                : ['long long',('int dwDesiredAccess', 'int bInheritHandle', 'int dwProcessId')],
            'TerminateProcess'           : ['int',('long long hProcess', 'int uExitCode')],
            'TerminateThread'            : ['int', ('long long hThread', 'int dwExitCode')],
            'GetFileTime'                : ['int',('long long hFile','int lpCreationTime','int lpCreationTime','int lpLastAcessTime','int lpLastWriteTime')],
            'SetFileTime'                : ['int',('long long hFile','int lpCreationTime', 'int lpLastAcessTime','int lpLastWriteTime')],
            'ProcessIdToSessionId'       : ['int',('int dwProcessId', 'int * pSessionId')],
            'WriteProcessMemory'         : ['int',('long long hProcess','int* lpBaseAdress','int* lpBuffer','int nSize','int * lpNumberOfBytesWritten')],
            'CreateRemoteThread'         : ['long long',('long long hProcess','int * lpThreadAttributes','int dwStackSize', ' int * lpStartAddress',' int * lpParameter','int dwCreationFlags','int * lpThreadId')],
            'GetLocaleInfoA'             : ['int' , ('int Locale', 'int LCType', 'char * lpLCData', 'int cchData')],
            'SetCurrentDirectoryW'       : ['int' , ('short * lpPathName',)],
            'GetCurrentDirectoryW'       : ['int' , ('int BufferLength' , 'short * lptstring')],
            'GetLogicalDriveStringsW'    : ['int' , ('int BufferLength' , 'short * lptstring')],
            'GetDriveTypeW'              : ['int' , ('short * lpRootPathName',)],
            'GetTempPathA'               : ['int' , ('int BufferLength', 'char * lpBuffer')],
            'GetTempPathW'               : ['int' , ('int BufferLength', 'short * lpBuffer')],
            'IsWow64Process'             : ['int' , ('long long hProcess', 'long long Wow64Process')],
            'LocalAlloc'                 : ['long long', ('int uFlags', 'long long uBytes')],
            'LocalFree'                  : ['long long', ('long long Hmem',)],
            'VirtualQuery'               : ['long long', ('long long lpAddress', 'long long lpBuffer', 'long long dwLength')],
            'VirtualProtect'             : ['int', ('long long lpAddress', 'long long dwSize', 'int flNewProtect', 'long long lpflOldProtect')],
            'FlushInstructionCache'      : ['int', ('long long hProcess', 'long long lpBaseAddress', 'long long dwSize')],
            'MoveFileExA'                : ['int', ('long long lpExistingFileName', 'long long lpNewFileName', 'long dwFlags')],
            'WaitForSingleObject'        : ['int', ('long long hHandle', 'int dwMilliseconds')],
            'VerifyVersionInfoA'         : ['int', ('char *lpVersionInfo', 'int dwTypeMask', 'long long dwlConditionMask')],
            'VerSetConditionMask'        : ['long long', ('long long dwlConditionMask', 'int dwTypeBitMask', 'char dwConditionMask')],
            'CreateMutexA'               : ['long long', ('void *lpMutexAttributes', 'int bInitialOwner', 'char *lpName')],
            'OpenMutexA'                 : ['long long', ('unsigned int dwDesiredAccess', 'unsigned char bInheritHandle', 'char *lpName')],
            'ReleaseMutex'               : ['unsigned char', ('long long hMutex',)],
            "ReadProcessMemory"          : ['int', ('long long hProcess', 'void *lpBaseAddress', 'void *lpBuffer', 'unsigned long long nSize', 'unsigned long long *lpNumberOfBytesRead')]
        }

        self.prototypes['ws2_32.dll'] = {
            'socket'          : ['long long', ('int af','int type','int protocol')],
            'send'            : ['int', ('long long s', 'char *buf', 'int len', 'int flags')],
            'bind'            : ['int', ('long long s', 'char *name', 'int namelen')],
            'listen'          : ['int', ('long long s', 'int backlog')],
            'recv'            : ['int', ('long long s', 'char *buf', 'int len', 'int flags')],
            'accept'          : ['long long', ('long long s', 'char *addr', 'int *addrlen')],
            'connect'         : ['int', ('long long s', 'char *addr', 'int *namelen')],
            'closesocket'     : ['int', ('long long socket',)],
            'select'          : ['int', ('int nfds','int *readfds','int *writefds','int *exceptfds','char *timeout')],
            'ioctlsocket'     : ['int',('long long s','int cmd','char *argp')],
            'setsockopt'      : ['int', ('long long s','int level','int optname','char *optval','int optlen')],
            'WSAGetLastError' : ['int',()],
            'gethostname'     : ['int', ('char *name', 'int namelen')],
            'gethostbyname'   : ['long long', ('char *name',)],
            'WSAIoctl'        : ['int', ('long long s', 'int dwIoControlCode', 'long long lpvInBuffer', 'int cbInBuffer',
                                         'long long lpvOutBuffer', 'int cbOutBuffer', 'long long lpcbBytesReturned',
                                         'long long lpOverlapped', 'long long lpCompletionRoutine')],
            'WSARecv'         : ['int', ('long long s', 'long long lpBuffers', 'int dwBufferCount',
                                         'long long lpNumberOfBytesRecvd', 'long long lpFlags',
                                         'long long lpOverlapped', 'long long lpCompletionRoutine')],
            'WSASocketA'      : ['long long', ('int af', 'int type', 'int protocol', 'long long lpProtocolInfo',
                                               'int g', 'int dwFlags')],
            'getpeername'     : ['int', ('long long s', 'long long name', 'int *namelen')],
        }

        self.prototypes['msvcrt.dll'] = {
            '_getdrive' : ['int', ()],
            '_getcwd' : ['char*', ('char *buf', 'int maxlen')],
            '_chdir' : ['int', ('char *dirname',)],
            'remove' : ['int', ('char *filename',)],
            '_utime64' : ['int', ('char *filename','char *times')],
            'wcslen' :  [' long long', ('short * str',)],
            '_mkdir' : ['int', ('char *dirname',)],

        }

        self.prototypes['secur32.dll'] = {
            'GetUserNameExA'                 : ['int',('int NameFormat', 'char *outbuf', 'int *len')],
            'LsaEnumerateLogonSessions'      : ['int',('long long LogonSessionCount', 'long long LogonSessionList')],
            'LsaConnectUntrusted'            : ['long',('long long *LsaHandle',)],
            'LsaLookupAuthenticationPackage' : ['long',('long long LsaHandle', 'void *PackageName', 'unsigned long long *AuthenticationPackage')],
            'LsaCallAuthenticationPackage'   : ['long',('long long LsaHandle', 'unsigned long long AuthenticationPackage', 'void *ProtocolSubmitBuffer', 'unsigned long long SubmitBufferLength', 'void **ProtocolReturnBuffer', 'unsigned long long *ReturnBufferLength', 'long long *ProtocolStatus')],
            'LsaFreeReturnBuffer'            : ['long',('void *Buffer',)],
            'LsaDeregisterLogonProcess'      : ['int',('long long LsaHandle',)],
            'LsaGetLogonSessionData'         : ['int',('long long LogonId', 'char *ppLogonSessionData',)],
        }
        self.prototypes['user32.dll'] = {
            'OpenClipboard'            : ['int',('int hWndNewOwner',)],
            'EmptyClipboard'           : ['int',()],
            'SetClipboardData'         : ['int',('int uformat', 'int hmem')],
            'CloseClipboard'           : ['int',()],
            'GetDC'                    : ['int',('int hwnd',)],
            'GetDesktopWindow'         : ['int',()],
            'OpenWindowStationA'       : ['int',('char *winsta','int finherit','int desiredaccess')],
            'CloseWindowStation'       : ['int',('int winsta',)],
            'GetProcessWindowStation'  : ['int',()],
            'SetProcessWindowStation'  : ['int',()],
            'OpenInputDesktop'         : ['int',('int flags','int inherit','int desiredaccess')],
            'CloseDesktop'             : ['int',('int hdesktop',)],
            'GetThreadDesktop'         : ['int',('int threadid',)],
            'SetThreadDesktop'         : ['int',('int hdesktop',)],
            'FindWindowA'              : ['int',('char *lpClassName','char *lpWindowName')],
            'SendMessageA'             : ['int',('int hWnd','int Msg','int wParam','int lParam')],
            'ExitWindowsEx'            : ['int',('int uFlags','int Reason')],
            'GetLastInputInfo'         : ['int',('long long plii',)],
            'keybd_event'              : ['void',('unsigned char bVk','unsigned char bScan','unsigned int dwFlags','unsigned long *dwExtraInfo')],
            'SetWindowsHookExA'        : ['int',('int idHook','void *lpfn','void *hmod','unsigned int dwThreadId')],
            'UnhookWindowsHookEx'      : ['int',('void *hhk',)],
            'GetMessageA'              : ['int',('unsigned char *lpMsg','void *hWnd','unsigned int wMsgFilterMin','unsigned int wMsgFilterMax')],
            'TranslateMessage'         : ['int',('void *lpMsg',)],
            'DispatchMessageA'         : ['int',('void *lpMsg',)],
            'RegisterHotKey'           : ['int',('void *hWnd','int id','unsigned int fsModifiers','unsigned int vk')]
        }
        self.prototypes['gdi32.dll'] = {
            'CreateDCA'                : ['int', ('char *driver', 'char *device','char *output')],
            'CreateCompatibleDC'       : ['int', ('int hdc',)],
            'GetDeviceCaps'            : ['int', ('int hdc','int index')],
            'CreateCompatibleBitmap'   : ['int', ('int hdc','int width','int height')],
            'SelectObject'             : ['int', ('int hdc','int hgdiobj')],
            'BitBlt'                   : ['int', ('int hdcDest','int nXDest','int nYDest','int nWidth','int nHeight','int hdcSrc','int nXSrc','int nYSrc','int dwRop')],
            'CreateDIBSection'         : ['int', ('int hdc','char *pbmi','int usage','char **ppvBits','int hSection','int dwOffset')],
            'DeleteObject'             : ['int', ('int hObject',)],
            'DeleteDC'                 : ['int', ('int hdc',)]
        }
        self.prototypes['avicap32.dll'] = {
            'capCreateCaptureWindowA'  : ['int',('char * lpszWindowName','int dwStyle','int x','int y','int nWidth', 'int nHeight','int Hwnd','int nID')]
        }

        self.prototypes['iphlpapi.dll'] = {
            'GetIpAddrTable' : ['int',('int* pIpAddrTable', 'int* pdwSize', 'int bOrder')],
            'SendARP'        : ['unsigned int', ('int *DestIP', 'int *SrcIP', 'void *pMacAddr', 'unsigned int *PhyAddrLen')]
        }
        self.prototypes['netapi32.dll'] = {
            'NetShareAdd'                       : ['int',('char *servername', 'int level', 'char *buf', 'int *parm_err')],
            'NetShareEnum'                      : ['int',('char *servername','int level','char *bufptr','int prefmaxlen','int *entriesread','int *totalentries','int *resume_handle')],
            'NetApiBufferFree'                  : ['int',('char *Buffer',)],
            'NetUserEnum'                       : ['int',('char * servername','int level','int filter','char * bufptr','int prefmaxlen','int * entriesread','int * totalentries','int * resumehandle')],
            'DsRoleGetPrimaryDomainInformation' : ['int',('char *servername','int level','char ** bufptr')]
        }

        self.prototypes['dsrole.dll'] = {
            'DsRoleGetPrimaryDomainInformation' : ['int',('char *servername','int level','char ** bufptr')]
        }

        self.prototypes['psapi.dll'] = {
            'GetModuleInformation'       : ['int',('long long hProcess', 'long long hModule', 'long long lpmodinfo', 'int cb',) ],
        }


        self.prototypes['advapi32.dll'] = {
            'CreateProcessWithTokenW'  : ['int', ('long long hToken', 'int dwLogonFlags', 'char *lpApplicationName', 'char *lpCommandLine', 'int dwCreationFlags', 'char *lpEnvironment', 'char *lpCurrentDirectory', 'char *lpStartupInfo', 'char *lpProcessInformation') ],
            'CheckTokenMembership': ['int', ('long long TokenHandle', 'char * pSid', 'int * IsMember')],
            'CreateWellKnownSid': ['int', ('int WellKnownSidType', 'char * DomainSid', 'char * pSid', 'long * cbSid')],
            'DuplicateToken': ['int', ('long long ExistingTokenHandle', 'int ImpersonationLevel', 'long long * DuplicateTokenHandle')],
            'IsValidSid': ['int', ('char *pSid',)],
            'GetSidSubAuthorityCount': ['char *', ('char *pSid',)],
            'GetSidSubAuthority' : ['int *', ('char * pSid', 'int nSubAuthority')],
            'GetTokenInformation' : ['int', ('long long TokenHandle', 'int TokenInformationClass', 'char * TokenInformation', 'int TokenInformationLength', 'int * ReturnLength')],
            'OpenProcessToken' : ['int',('long long ProcessHandle','int DesiredAccess', 'char *TokenHandle')],
            'OpenThreadToken'  : ['int',('long long ThreadHandle', 'int DesiredAccess', 'int OpenAsSelf', 'char * TokenHandle')],
            'LookupPrivilegeValueA' : ['int',('char *lpSystemName','char *lpName', 'char *lpLuid')],
            'LookupPrivilegeNameA': ['int', ('char *lpSystemName', 'char * lpLuid', 'char * lpName', 'int * cchName')],
            'AdjustTokenPrivileges' : ['int',('long long TokenHandle','int DisableAllPrivileges', 'char *NewState','int BufferLength','char *PreviousState','int *ReturnLength')],
            'OpenSCManagerA'        : ['long long',('char * lpMachineName','char * lpDatabaseName','int dwDesiredAccess')],
            'EnumServicesStatusExA' : ['int',('long long hManager','int InfoLevel','int dwServiceType','int dwServiceState','char * lpServices','int cbBufSize','int BytesNeeded','int ServicesReturned','int lpResumeHandle','int pszGroupName')],
            'CloseServiceHandle'    : ['int',('long long hSCObject',)],
            'OpenServiceA'          : ['long long',('long long hSCManager','char * lpServiceName','int dwDesiredAccess')],
            'CreateServiceA'        : ['long long',('long long hSCManger', 'char * lpServiceName','char * lpDisplayName','int dwDesiredAcess','int dwServiceType','int dwStartType','int dwErrorControl','char * lpBinaryPathName','char * lpLoadOrderGroup','int * lpswTagId','char * lpDependencies','char * lpServiceStartName','char * lpPassword')],
            'StartServiceA'         : ['int',('long long hService','int swNumServiceArgs','char * lpServiceArgVectors')],
            'QueryServiceStatus'    : ['int',('long long hService', 'char * lpServiceStatus')],
            'DeleteService'         : ['int',('long long hService',)],
            'ControlService'        : ['int',('long long hService','int dwControl','char * lpServiceStatus')],
            'SetThreadToken'        : ['int',('long long hThread', 'long long hToken')],
            'RegOpenKeyExA'         : ['int' , ('long long hKey', 'char *lpSubKey', 'int ulOptions','int samDesired','char *phkResult')],
            'RegCreateKeyExA'       : ['int' , ('long long hKey', 'char *lpSubKey', 'int reserved','char *lpClass', 'int dwOptions', 'int samDesired', 'long long lpSecurityAttributes', 'char *phkResult', 'long long lpdwDisposition')],
            'RegDeleteKeyExA'       : ['int' , ('long long hKey', 'char *lpSubKey', 'int samDesired', 'int reserved')],
            'RegQueryValueExA'      : ['int' , ('long long hKey', 'char *lpValueName', 'int *lpReserved','int *lpType','char *lpData', 'int *lpcbData')],
            'RegSetValueExA'        : ['int' , ('long long hKey', 'char *lpValueName', 'int Reserved','int dwType','char *lpData','int cbData')],
            'RegEnumKeyExA'         : ['int' , ('long long hKey', 'int dwIndex', 'char *lpName','int *lpcName','int *lpReserved','char *lpClass','int *lpcClass','char *lpftLastWriteTime')],
            'RegCloseKey'           : ['int' , ('long long hKey',)],
            'LsaOpenPolicy'         : ['int' , ('long long SystemName', 'long long ObjectAttributes', 'int DesiredAccess', 'long long PolicyHandle')],
            'LsaQueryInformationPolicy' : ['int' , ('long long PolicyHandle', 'int InformationClass', 'long long Buffer')],
            'LsaClose'              : ['int' , ('long long ObjectHandle',)],
            'LookupAccountSidA'     : ['int', ('char *lpSystemName', 'char *Sid', 'char *Name', 'unsigned int *cchName', 'char *ReferencedDomainName', 'unsigned int *cchReferencedDomainName', 'char *peUse')],
            'LogonUserA'            : ['int', ('char *lpszUsername', 'char *lpszDomain', 'char *lpszPassword', 'unsigned int dwLogonType', 'unsigned int dwLogonProvider', 'void *phToken')],
            'GetUserNameA'          : ['int', ('char *lpBuffer', 'unsigned int *pcbBuffer')],
            'LookupAccountNameA'    : ['int', ('char *lpSystemName', 'char *lpAccountName', 'void *Sid', 'unsigned int *cbSid', 'char *ReferencedDomainName', 'unsigned int *cchReferencedDomainName', 'void *peUse')],
            'OpenEventLogA'         : ['unsigned long long', ('char *lpUNCServerName', 'char *lpSourceName')],
            'ClearEventLogA'        : ['int', ('long long *hEventLog', 'char *lpBackupFileName')],
            'CloseEventLog'         : ['int', ('long long hEventLog',)]
        }

        self.prototypes['Version.dll'] = {
            'VerQueryValueA'            : ['int',('char *pBlock', 'char *lpSubBlock', 'char *lplpBuffer','int *puLen')],
            'GetFileVersionInfoSizeA'   : ['int',('char *lpstrFileName', 'int *lpdwHandle')],
            'GetFileVersionInfoA'       : ['int',('char *lpstrFileName', 'int dwHandle', 'int dwLen','char *lpData')],
        }

        self.prototypes['ntdll.dll'] = {
            'NtCreateThreadEx'                  : ['int', ('long long hThread', 'int DesiredAccess', 'long long ObjectAttributes', 'long long ProcessHandle',
                                                           'long long lpStartAddress', 'long long lpParameter', 'int CreateSuspended', 'long StackZeroBits',
                                                           'long SizeOfStackCommit', 'long SizeOfStackReserve', 'long long lpBytesBuffer')],
            'NtSetInformationThread'            : ['int', ('long long ThreadHandle', 'int ThreadInformationClass', 'long long ThreadInformation',
                                                           'int ThreadInformationLength')],
            'NtQueryInformationThread'          : ['int', ('long long ThreadHandle', 'int ThreadInformationClass', 'long long ThreadInformation',
                                                           'int ThreadInformationLength', 'long long ReturnLength')],
            'NtQuerySystemInformation'          : ['int', ('int SystemInformationClass', 'long long SystemInformation',
                                                           'int SystemInformationLength', 'long long ReturnLength')],
            'NtAllocateVirtualMemory'           : ['int', ('long long ProcessHandle','long long BaseAddress',
                                                           'long long ZeroBits', 'long long RegionSize', 'long AllocationType', 'long Protect')],
            'NtQueryObject'                     : ['int', ('long long ObjectHandle',
                                                           'int ObjectInformationClass',
                                                           'long long ObjectInformation',
                                                           'long Length',
                                                           'long long ResultLength')],
            'RtlAddVectoredExceptionHandler'    : ['long long', ('long FirstHandler', 'long long VectoredHandler')],
            'RtlRemoveVectoredExceptionHandler' : ['long', ('long long Handler',)],
            'RtlGetVersion'                     : ['long', ('long long lpVersionInformation',)],
        }

        # Used in getpasswordhashes module
        # NOTE: There are no official docs about these functions
        #       I divined the prototypes from looking at code available online
        self.prototypes['samsrv.dll'] = {
            'SamIConnect' : ['int', ('int Unknown1', 'long long pSamHandle', 'int AccessMask', 'int Unknown2')],
            'SamrOpenDomain' : ['int', ('long long SamHandle', 'int AccessMask', 'long long DomainSid', 'long long pDomainHandle')],
            'SamrEnumerateUsersInDomain' : ['int', ('long long DomainHandle', 'long long pEnumerationHandle', 'int AccessMask',
                                                    'long long pDomainUserEnumeration', 'int PrefMaxSize', 'long long pUserCount')],
            'SamrOpenUser' : ['int', ('long long DomainHandle', 'int AccessMask', 'int Rid', 'long long pUserHandle')],
            'SamIFree_SAMPR_USER_INFO_BUFFER' : ['void', ('long long UserInfo', 'int InfoClass')],
            'SamIFree_SAMPR_ENUMERATION_BUFFER' : ['void', ('long long EnumerationBuf',)],
            'SamrQueryInformationUser' : ['int', ('long long UserHandle', 'int InfoClass', 'long long UserInfo')],
            'SamrCloseHandle' : ['int', ('long long SamHandle',)],
        }

        # Used in wlanlist module
        self.prototypes['wlanapi.dll'] = {
            'WlanOpenHandle'              : ['unsigned int', ('unsigned int dwClientVersion', 'void *pReserved', 'unsigned int *pdwNegotiatedVersion', 'long long *phClientHandle')],
            'WlanEnumInterfaces'          : ['unsigned int', ('long long hClientHandle', 'void *pReserved', 'void *ppInterfaceList')],
            'WlanGetAvailableNetworkList' : ['unsigned int', ('long long hClientHandle', 'void *pInterfaceGuid', 'unsigned int *dwFlags', 'void *pReserved', 'void *ppAvailableNetworkList')],
        }

        # Used in Speak module
        self.prototypes['ole32.dll'] = {
            'CoUninitialize'   : ['void', ()],
            'CoInitialize'     : ['long', ('void *pvReserved', )],
            'CoCreateInstance' : ['long', ('void *rclsid', 'void *pUnkOuter', 'unsigned int dwClsContext', 'void *riid', 'void **ppv')]
        }

         # Used in recordaudio module
        self.prototypes['winmm.dll'] = {
            'waveInGetDevCapsA'     : ['unsigned int', ('unsigned int uDeviceID', 'void *pwic', 'unsigned int cbwic')],
            'waveInPrepareHeader'   : ['unsigned long long', ('unsigned long long hwi', 'void *pwh', 'unsigned int cbwh')],
            'waveInOpen'            : ['unsigned long long', ('void *phwi', 'unsigned int uDeviceID', 'void *pwfx', 'unsigned int *dwCallback', 'unsigned int *dwInstance', 'unsigned int fdwOpen')],
            'waveInClose'           : ['unsigned long long', ('unsigned long long hwi',)],
            'waveInAddBuffer'       : ['unsigned long long', ('unsigned long long hwi', 'void *pwh', 'unsigned int cbwh')],
            'waveInStart'           : ['unsigned long long', ('unsigned long long hwi',)],
            'waveInStop'            : ['unsigned long long', ('unsigned long long hwi',)],
            'waveInUnprepareHeader' : ['unsigned long long', ('unsigned long long hwi', 'void *pwh', 'unsigned int cbwh')],
            'waveInGetNumDevs'      : ['unsigned int', ()]
        }

        # Used in hw_enum module
        self.prototypes['setupapi.dll'] = {
           'SetupDiEnumDeviceInfo'             : ['int', ('unsigned long long DeviceInfoSet', 'unsigned int MemberIndex', 'void *DeviceInfoData')],
           'SetupDiGetClassDevsExW'            : ['unsigned long long', ('void *ClassGuid', 'char *Enumerator', 'unsigned long long hwndParent', 'int flags', 'unsigned long long DeviceInfoSet', 'char *MachineName', 'void *Reserved')],
           'SetupDiGetDeviceRegistryPropertyW' : ['int', ('unsigned long long DeviceInfoSet', 'void *DeviceInfoData', 'unsigned int Property', 'unsigned int *PropertyRegDataType', 'unsigned char *PropertyBuffer', 'unsigned int PropertyBufferSize', 'unsigned int *RequiredSize')]
        }

        # etc. for *
        for dll in self.prototypes.keys():
            for function in self.prototypes[dll].keys():
                devlog("shellserver", self.prototypes[dll][function][1])
                self.add_generic_win64call(dll,
                                           function,
                                           self.prototypes[dll][function][0],
                                           *self.prototypes[dll][function][1])
        self.create_API_wrappers()

        self.localfunctions["_cpuid_proc"] = ("asm", """
        _cpuid_proc:
            pushq %rbp
            movq %rsp, %rbp
            jmp _is_cpuid_proc_avail

        _is_cpuid_proc_avail:
            pushfd
            pushfd
            xor $0x00200000, (%rsp)
            popfd
            pushfd
            pop %rax
            popfd
            and $0x00200000, %rax
            jnz _cpuid_proc_present
            jmp _cpuid_proc_fail

        _cpuid_proc_present:
            movl $0x80000001, %eax
            cpuid
            mov %rdx, %r13

        _cpuid_proc_exit:
            movq %rbp, %rsp
            popq %rbp
            ret

        _cpuid_proc_fail:
            mov $0, %r13
            jmp _cpuid_proc_exit
        """)

        self.localfunctions["_cpuid_features"] = ("asm", """
        _cpuid_features:
            pushq %rbp
            movq %rsp, %rbp
            jmp _is_cpuid_features_avail

        _is_cpuid_features_avail:
            pushfd
            pushfd
            xor $0x00200000, (%rsp)
            popfd
            pushfd
            pop %rax
            popfd
            and $0x00200000, %rax
            jnz _cpuid_features_present
            jmp _cpuid_features_fail

        _cpuid_features_present:
            xorl %ecx, %ecx                     // sub-leaf 0
            movl $0x7, %eax
            cpuid
            mov %rbx, %r13

        _cpuid_features_exit:
            movq %rbp, %rsp
            popq %rbp
            ret

        _cpuid_features_fail:
            mov $0, %r13
            jmp _cpuid_features_exit
        """)

    def add_prototype(self, dll, name, ret_type, *args):
        """ add a prototype to the libc """
        if dll not in self.prototypes:
            self.prototypes[dll] = {}
        if name in self.prototypes[dll]:
            print "[!] Warning, re-defining prototype for %s!%s" % (dll, name)
        self.prototypes[dll][name] = [ret_type, args]

    def create_API_wrappers(self):
        nonvolatile = ['rbx',
                       'rbp',
                       'rdi',
                       'rsi',
                       'r12',
                       'r13',
                       'r14',
                       'r15']
        volatile    = ['rax',
                       'rcx',
                       'rdx',
                       'r8',
                       'r9',
                       'r10',
                       'r11']
        # 4 reg fast call + stack backing

        arg_map = { 1 : 'mov 24(%rbp),%rcx',
                    2 : 'mov 32(%rbp),%rdx',
                    3 : 'mov 40(%rbp),%r8',
                    4 : 'mov 48(%rbp),%r9' }

        # max 32 args, increase if need be :>
        for arg_n in range(0,33):
            code = """
Win64Call_%d:

    push %%rbp
    mov %%rsp,%%rbp

    // Ensure 16 byte frame alignment (this will extend don't worry)
    // everything is referenced relative to rbp, so this should be okay ...

    and $0xfffffff0,%%rsp

""" % arg_n

            stack_args  = []
            reg_args    = []
            i           = 1


            while i <= arg_n:
                if i in arg_map.keys():
                    reg_args.append('    '
                                    + arg_map[i]
                                    + ' // arg%d' % i
                                    + '\n')
                else:
                    stack_args.append('    '
                                      + 'push %d(%%rbp)' % (16+(8*i))
                                      + ' // arg%d' % i
                                      + '\n')
                i = i + 1


            if len(stack_args) % 2:
                # keep frame 16 aligned on call entry
                stack_args.append('    '
                                  + 'push %rax // frame align dummy\n')

            # order the arg ops in reverse for readability ...
            if len(stack_args):
                stack_args.reverse()
                code += ''.join(stack_args)
            if len(reg_args):
                reg_args.reverse()
                code += ''.join(reg_args)

            # load target func from arg1
            code += """
    mov 16(%%rbp),%%rax

    // stackback for fastcall ...
    push %%r9
    push %%r8
    push %%rdx
    push %%rcx
    call *%%rax // call RESOLVED_func
    pop %%rcx
    pop %%rdx
    pop %%r8
    pop %%r9
    // move retval to accum
    mov %%rax,%%r13

    mov %%rbp,%%rsp
    pop %%rbp
    ret $%d
""" % ((arg_n + 1) * 8)

            self.localfunctions['Win64Call_%d' % arg_n] = ('asm', code)
            devlog("shellserver", '+' * 80)
            devlog("shellserver", code)
        return

    def add_generic_win64call(self, dll, name, ret_type, *args):
        """ add a generic win64 call wrapper """
        code    =  ''
        sargs   = 'void'
        fargs   = ''
        nargs   = len(args)
        if len(args):
            sargs = ', '.join(args)
            fargs = list(args)
            ### This is where we parse the import tables you manually added above
            for n in range(0, nargs):
                try:
                    fargs[n] = args[n].split('*')[-1].split()[-1]
                except IndexError:
                    print "*******"
                    print "******* You've probably forgotten to create a tuple in function: %s|%s"%(dll,name)
                    print "*******"
                    raise
            fargs = ', '.join(fargs)
        if sargs == 'void':
            sargs = ''

        # So import remote function name should populate the libc defines
        # so as soon as a remote import is resolved, we put it in the
        # win64 libc define as RESOLVED_function : 0xdeadcafebabebeef

        # flow:
        #   - coder goes: #import "remote", "kernel32.dll!blah" as "blah"
        #   - MOSDEF engine takes care of all this stuff, resolves the function
        #   - RESOLVED_blah is placed into libc defines by engine
        #   - correct local-C code is appended by engine
        #
        # So nothing will change coding wise from a 3rd party developer view

        code += """
#import "remote64", "%s|%s" as "RESOLVED_%s"
#import "local", "Win64Call_%d" as "Win64Call_%d"
#import "local", "debug" as "debug"

%s %s(%s)
{
"""         % (dll,
               name,
               name,
               nargs,
               nargs,
               ret_type,
               name,
               sargs)
        if ret_type != 'void':
            code += '    %s retval;\n\n' % ret_type
            if self.debug == True:
                code += '    debug();\n'
            code += '    retval = '
        else:
            code += '    '
            if self.debug == True:
                code += '    debug();\n'
        # RESOLVED_FunctionName should resolve to function address ... remote64 handles this
        code += 'Win64Call_%d(RESOLVED_%s, %s);\n' % (nargs, name, fargs)
        if ret_type != 'void':
            code += '    \n    return retval;\n'
        code += '}\n'
        if not self.localfunctions.has_key(name):
            #print 'Adding API wrapper for %s' % name
            self.localfunctions['%s|%s' % (dll, name)] = ('c', code)
        devlog("shellserver", "[!] Checkme: %s:\n%s" % ('%s|%s' % (dll, name), code))

class Win64_intel(Win64):

    Endianness = 'little'

    def __init__(self, version = None):
        self.version = version
        Win64.__init__(self)

Win64_x64 = Win64_intel

if __name__ == '__main__':
    test = Win64_intel()
