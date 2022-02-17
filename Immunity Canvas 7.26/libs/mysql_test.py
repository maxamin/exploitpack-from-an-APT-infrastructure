#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import mysqllib

def main(host):
        # we can call m.setDebug() if we want packet output
        # in case that my primitive library brakes
        m=mysqllib.MySQL()
        m.connect( (host, 3306))      
        m.authenticate("username", "password", "mysql")
        
        result=m.query("SELECT '" + "@"*400+ "A" * (7696)+"'")    
        m.fetch_result(result)
        print m.fields
        print m.rows

        result=m.query("SELECT * from myclient_test")
        m.fetch_result(result)
        print m.fields
        print m.rows
                
        # INSERT with new stmt binding
        
        m.stmt_prepare("INSERT INTO test_bind_fetch VALUES(?,?,?,?,?,?,?)")
        m.stmt_bind([3,4,5,6,7,8,9])
        print m.execute()        
if __name__ == '__main__':
        main("127.0.0.1") # <- nosense, but i want to look -in-
