#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

class uniqlist(list):
    def __init__(self, ilist = []):
        list.__init__(self, [])
        self.__iadd__(ilist)
    def __iadd__(self, tlist):
        for nmember in tlist:
            if not self.__contains__(nmember):
                self.append(nmember)
        return self

