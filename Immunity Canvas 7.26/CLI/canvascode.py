#!/usr/bin/env python

# CanvasConsole, follows the native python model
import sys

# translate commandline commands into engine script
class ScriptEngine:
    def __init__(self):
        return
    
    def build_script(self, source):
        return 'listen 0 9090'
    
from xmlrpc import XMLRPCRequest

# interact with the engine over XML-RPC
class EngineInteract:
    def __init__(self):
        return
    
    def run_script(self, code):
        return

class CanvasInteractiveInterpreter:
    def __init__(self):
        self.canvascompile  = ScriptEngine().build_script
        self.runcanvascode  = EngineInteract().run_script
        return

    def runscript(self, source):
        # From actual python interpreter
        """Compile and run some source in the interpreter.

        Arguments are as for compile_command().

        One several things can happen:

        1) The input is incorrect; compile_command() raised an
        exception (SyntaxError or OverflowError).  A syntax traceback
        will be printed by calling the showsyntaxerror() method.

        2) The input is incomplete, and more input is required;
        compile_command() returned None.  Nothing happens.

        3) The input is complete; compile_command() returned a code
        object.  The code is executed by calling self.runcode() (which
        also handles run-time exceptions, except for SystemExit).

        The return value is True in case 2, False in the other cases (unless
        an exception is raised).  The return value can be used to
        decide whether to use sys.ps1 or sys.ps2 to prompt the next
        line.

        """
        try:
            code = self.canvascompile(source)
        except (OverflowError, SyntaxError, ValueError):
            # Case 1
            return False

        if code is None:
            # Case 2
            return True

        # Case 3
        self.runcanvascode(code)
        return False

