@ECHO OFF
echo This is a little CANVAS VisualSploit loader. It tries Python 2.4, 2.5, 2.6
echo Copyright Immunity, Inc.

PATH=c:\GTK\bin;c:\Python24\DLLs;c:\Program Files\Common Files\GTK\2.0\lib;c:\Python24\;c:\Python25\;c:\Python25\DLLs;c:\Python26\;c:\Python26\DLLs; %PATH%

@IF not exist VisualSploit\main.py GOTO PRINT
python.exe -W ignore VisualSploit\main.py
@exit


:PRINT
echo *************************************************************************
echo *************************************************************************
echo You dont seem to have VisualSploit installed, please check 
echo http://www.immunityinc.com/products-visualsploit.shtml
echo *************************************************************************
echo *************************************************************************
@pause


