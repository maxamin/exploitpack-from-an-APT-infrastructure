"""
targetrm.py

Target Relational Map

"""

DESIGN="""

This code provides two main objects:
cEntity - An email address/person/computer/email/file/note/ or other data object
cLink - A link between two entities with an associated time , type ("knows" or "sent email to" or "has") and a description of how we know that (as an object). 

I.E cEntity(person:"Bob Smith") -> cLink("has",via:"mail spool parse at X time") -> cEntity(email:"bob.smith@example.com")

This information can be filled out many many ways:
o Web spiders
o Facebook API's
o Manual Entry
o DNS Requests: Dig/host/nslookup/etc
o Hacking modules

One of the main goals is storing information for use in client-side attacks (i.e. hasEmail and hasBrowser).

This file is the main objects, but not the datastorage routines or the visualization.

"""

class cEntity:
    pass

class cLink:
    pass

