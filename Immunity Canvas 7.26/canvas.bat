@echo off
setlocal enableextensions enabledelayedexpansion
rem This is a little CANVAS loader.
rem Copyright Immunity, Inc.

rem YOU CANNOT USE -OO because that strips doc strings, and
rem we need docstrings to do our MOSDEF compile!

rem This weird command cd's to the current directory of the batch script
pushd %~dp0

rem Find what version of python is available, we use the highest available. 
IF exist c:\Python27x\python.exe (
    echo "Using Python 2.7 .bat setup...."
    PATH=c:\Python27x\DLLs;C:\python27x\;!PATH!
    python.exe -W ignore C:\ProgramData\0Day\Tools\CANVAS\runcanvas.py
) ELSE (
    echo "Python 2.7 could not be found and it is required for CANVAS. Please update to Python 2.7."
    echo "You can find an archive with all Windows dependencies at: https://www.immunityinc.com/canvas-dependencies.shtml"
)


                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      