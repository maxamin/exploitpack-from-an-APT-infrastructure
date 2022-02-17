#!/usr/bin/env python

"""
Converts our javaNode.java to a .jsp file for you

There's a line down there marked that you'll want to uncomment
for callback support
"""

import sys

def usage():
    print "Usage: java2jsp.py <filename>.java <filename>.jsp"
    sys.exit(1)
    
def main(args):
    """
    args should be : <input filename>.java <output filename>.jsp
    """
    if len(args)!=2:
        usage()
        
    inputLines=file(args[0],"r").readlines()
    outfile=file(args[1],"wb")
    outlines=[]
    outimports=[]
    outlines.append("<% \n")
    for line in inputLines:
        #strip comments
        line=line.split("//")[0].strip()
        #ignore blank lines
        if line=="":
            continue
        
        if line[:len("import")]=="import":
            #handle import directive
            #-1 here strips off final semicolon
            line = "<%%@ page import=\"%s\" %%>\n"%(line.split(" ")[1][:-1])
            outimports.append(line)
            continue 
        
        if line.count("public static void main"):
            #cannot have static classes in an inner class, which is what we are.
            line=line.replace("public static void main","public void main")
        #you'll want to uncomment this for callback support!            
        #line=line.replace("127.0.0.1","myip")
            
        #we have a line of code....
        line=line+"\n"        
        outlines.append(line)
    
    #trailing close jsp statement
    outlines.append("""
    javaNode jstarter=new javaNode();
    jstarter.main();
    %>""")
    
    for line in outimports:
        outfile.write(line)
    for line in outlines:
        outfile.write(line)
        
    outfile.close()
    return 
    
if __name__=="__main__":
    main(sys.argv[1:])
