#! /usr/bin/env python
#requestandresponse.py
#encapsulates a request and response

#we don't need CGI for SILICA, and they don't ship with it by default
try:
    import cgi
except:
    pass 
    
#mostly used to pickle
class RequestAndResponse:
    def __init__(self,clientheader,clientbody,serverheader,serverbody):
        self.clientheader=clientheader
        self.clientbody=clientbody
        self.serverheader=serverheader
        self.serverbody=serverbody

    #returns true if we are the same
    def issame(self,other):
        if self.clientheader.issame(other.clientheader) and \
           self.clientbody.issame(other.clientbody) and \
           self.serverheader.issame(other.serverheader) and \
           self.serverbody.issame(other.serverbody):
            return 1
        return 0
        
    def printme(self):
        site=self.clientheader.connectHost
        result=""
        result+="Site: "+site+"<br>"
        result+="Port: "+str(self.clientheader.connectPort)+"<br>"
        result+="SSL: "
        if self.clientheader.clientisSSL:
            result+="Yes"
        else:
            result+="No"
            
        result+="<br><br>"
        #constructRequest stolen out of spkproxy
        import daveutil
        result+=cgi.escape(daveutil.constructRequest(self.clientheader,self.clientbody))
        result=result.replace("\n","<br>")
        return result
        
    def getResponse(self):
        import daveutil
        result=""
        result+=daveutil.constructResponse(self.serverheader,self.serverbody)
        return result


def main():
    """
    
    """
    import sys
    sys.path.append(".")
    import cPickle
    filename=sys.argv[1]
    infile=open(filename,"rb")
    obj=cPickle.load(infile)
    infile.close()
    print repr(obj.printme())
    print "-"*50
    print obj.getResponse()
    return 

if __name__=="__main__":
    main()
    
