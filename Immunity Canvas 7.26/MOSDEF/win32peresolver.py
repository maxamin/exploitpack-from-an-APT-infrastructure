#! /usr/bin/env python

from win32remoteresolver import win32remoteresolver

class win32peresolver(win32remoteresolver):
  def __init__(self, plt_addr):
    win32remoteresolver.__init__(self)
    #self.compilelock.acquire() XXX KLUDGED, fix once win32remoteresolver::compilelock fixed.
    self.addr = plt_addr
    self.pltentrysize = 0
    del self.remotefunctioncache["kernel32.dll|getprocaddress"]
    del self.remotefunctioncache["ws2_32.dll|send"]

  def setPLTEntrySize(self, num):
    self.pltentrysize= num
    
  def getremote(self, func):
    print "Function: %s %x " % (func, self.addr)
    self.remotefunctioncache[func]=self.addr
    self.addr += self.pltentrysize
    return self.remotefunctioncache[func]
  
if __name__ == '__main__':
  code="""      #import "remote", "kernel32.dll|getprocaddress" as "getprocaddress"
                //#import "int", "libaddr" as "libaddr"
                //#import "string", "procedure" as "procedure"
                #import "local", "sendint" as "sendint"
                #import "local", "debug" as "debug"
                void main()
                {
                unsigned int i;
                //debug();
                //i=getprocaddress(libaddr, procedure);
                sendint(i);
                }
                """

  # Mixing MOSDEF with PElib.
  # Concerning Mosdef:
  #  Basically, we have a win32peresolver that pass some fixed address (that would be our PE PLT)
  # and thats returned to the compile code. The win32peresolver put all this address on a cached.
  # 
  # Concerning PE
  #  First of all, we need to compile before everything, cause we need the list of imported functions
  #  So, we send mosdef a hardcoded address(0x401A0) offset: 0x1A0 which is where the .text section start.
  #  At that address, will be our PLT (jmp *(IAT_entry)), so we have to point the Entry Address to 
  #  .code + function_number * sizeof(jmp *(IAT_entry)). So we land on the begging on the shellcode.
  #  
  #  To discover where the IAT would be (we need to know this, before creating the PLT), we need to calculate
  #  where the First thunk
  #
  #              buf+= secondpad
  #              buf+= data_buf   
  #              
  #              for a in imports:
  #                      buf+= a[0].raw()
  #              buf+= import_str
  #
  #              # ORIGINAL THUNK
  #             for a in IIBN:
  #                     for b in a: # Listing function
  #                              buf+=struct.pack("L",b[1]) 
  #                      buf+=struct.pack("L",0x0)
  #              # FIRST THUNK
  #              for a in IIBN:
  #                      for b in a: # Listing function
  #                              buf+=struct.pack("L",b[1]) 
  #                      buf+=struct.pack("L",0x0)

  # side note: .code must be aligned
  
  w=win32peresolver(0x0401A0)
  
  buf=w.compile(code, [])
  o=open("asm.txt", "w")
  o.write(buf)
  o.close()
