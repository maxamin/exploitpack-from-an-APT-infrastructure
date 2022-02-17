#!/usr/bin/env python
"""
MCNBFX.py - a partial parser for NBFX, the .Net binary remoting protocol as used by
application/soap+msbin1 web services

(C) Immunity, 2008
Immunity CANVAS Licensed
"""

CHARS16TEXT="\x9a" #+ intel_short(length) + string
CHARS8WITHENDELEMENT="\x99" #+ ord(len(string))+string
CHAR8TEXT="\x98"
EMPTYTEXTRECORD="\xa8" #good for padding
ENDELEMENT="\x01"


def chars8ee(astring):
    return CHARS8WITHENDELEMENT+chr(len(astring))+astring

def count_end_elements(data, getdata=False ):
    """
    Parses the packet starting at the first data string
    either returns the number of end elements or the 
    original data string (still base64 and gziped)
    """
    end_elements=0
    retdata=[]
    #print "NBFX parsing: %s"%repr(data)
    while data!="":
        if data[0]==CHARS16TEXT:
            length=istr2halfword(data[1:3])
            newdata=data[3:3+length]
            data=data[3+length:]
            retdata+=[newdata]
        elif data[0] in [CHAR8TEXT, CHARS8WITHENDELEMENT]:
            if data[0]==CHARS8WITHENDELEMENT:
                end_elements+=1
            length=ord(data[1])
            newdata=data[2:2+length]
            data=data[2+length:]
            retdata+=[newdata]
        elif data[0]==ENDELEMENT:
            data=data[1:]
            end_elements+=1
        elif ord(data[0]) in range(0x44,0x5d):
            #prefix dictionary element - wrong?
            data=data[1:]
        else:
            print "end_elements not able to parse %2.2x: %s"%(ord(data[0]), repr(data))
            break
    if getdata:
        return "".join(retdata)
    return end_elements

def parse_NBFS(payload):
    """
    Parse (badly) NBFS/X to get the gziped data out
    """
    #print "Parsing NBFS of %d length"%len(payload)

    start=payload.find("Compression\x9a")
    if start=="-1":
        return "" #failed
    
    start=start+len("Compression")
    #copy all the new data in there
    base64edzipeddata=count_end_elements(payload[start:], getdata=True)
    #print "base64 bziped data: %s"%repr(base64edzipeddata)
    base64data=""
    try:
        base64data=base64.decodestring(base64edzipeddata)
    except:
        pass 

    if base64data=="":
        print "Nothing to decode in gzip"
        return ""#nothing to decode 

    gzip_decoded=""
    try: 
        gzip_decoded=gunzipstring(base64data)
        #print "GZip decoded"
    except:
        traceback.print_exc(file=sys.stdout)
        pass 

    if gzip_decoded!="":
        print "Gzip Data found: %s"%repr(gzip_decoded)
        return gzip_decoded
    return ""
