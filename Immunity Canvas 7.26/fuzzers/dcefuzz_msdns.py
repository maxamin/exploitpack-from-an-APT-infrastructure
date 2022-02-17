#!/usr/bin/env python
import sys
if "." not in sys.path: sys.path.append(".")

from fuzzers.dcefuzz import *

def createmsdnspkt(marshaller):
    """
    long  Function_01( [in] [unique]  [string] wchar_t * element_148,
    [in] [unique]  [string] char * element_149,
    [in] [unique]  [string] char * element_150,
    [out]  long * element_151,
    [out]  TYPE_1 * element_152
    );
    """
    data=""
    data+=wchar_t(msunistring("Word"),["pointer"],marshaller).marshall()
    data+=char_t("hell",["pointer"],marshaller).marshall()
    data+=char_t("hello",["pointer"],marshaller).marshall()
    return data


def runtest_msdns(target):
    log("Running msdns test")

    UUID="50abc2a4-574d-40b3-9d66-ee4fd5fba076"
    port=get_tcp_port(UUID,target)
    if not port:
        log("Could not get port for UUID %s"%UUID)
        return 0
    log("Found UUID on port %d"%port)
    connectionList = ["ncacn_ip_tcp:%s[%d]"% (target,port)]
    version="5.0"
    mydcefuzzer=dcefuzzer()
    #mydcefuzzer.user="Administrator"
    #mydcefuzzer.password="password"
    #mydcefuzzer.skipvars(1)
    mydcefuzzer.create_pkt="createmsdnspkt"
    mydcefuzzer.target=target
    mydcefuzzer.connectionList=connectionList
    mydcefuzzer.UUID=UUID
    mydcefuzzer.version=version
    mydcefuzzer.opcode=1
    global g_dcefuzzer
    g_dcefuzzer=mydcefuzzer
    log("Running fuzzer")
    mydcefuzzer.run()
    log("Fuzzer run done")
    return

def main():
    import sys
    runtest_msdns(sys.argv[1])

if __name__=="__main__":
    main()

