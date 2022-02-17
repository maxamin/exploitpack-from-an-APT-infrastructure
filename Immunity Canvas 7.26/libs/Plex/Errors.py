#=======================================================================
#
#   Python Lexical Analyser
#
#   Exception classes
#
#=======================================================================

import exceptions

class PlexError(exceptions.Exception):
  message = ""

class PlexTypeError(PlexError, TypeError):
  pass

class PlexValueError(PlexError, ValueError):
  pass

class InvalidRegex(PlexError):
  pass

class InvalidToken(PlexError):

  def __init__(self, token_number, message):
    PlexError.__init__(self, "Token number %d: %s" % (token_number, message))

class InvalidScanner(PlexError):
  pass

class AmbiguousAction(PlexError):
  message = "Two tokens with different actions can match the same string"

  def __init__(self):
    pass

class UnrecognizedInput(PlexError):
  scanner = None
  position = None
  state_name = None

  def __init__(self, scanner, state_name, token="Unknown"):
    self.scanner = scanner
    self.position = scanner.position()
    self.state_name = state_name
    self.token=token
    
  def __str__(self):
    filename = self.position[0]
    line = self.position[1]
    character = self.position[2]
    ret="'%s', line %d, char %d: Token (%s) not recognised in state %s"% (filename,line, character, repr(self.token), repr(self.state_name))
    print ret 
    return ret 


