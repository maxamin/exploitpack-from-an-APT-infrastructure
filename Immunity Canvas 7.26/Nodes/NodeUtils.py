#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

class NodePrompt:
    """
    Handles the prompts for a shellserver's commandline interface
    """
    
    prompt = '(CANVAS)'
    uid = -1
    
    def getprompt(self, prompt = None):
        power = '$'
        if prompt:
            self.localPrompt = prompt
        else:
            # if prompt == None, default to self.prompt for Platform/MOSDEF> prompts
            self.localPrompt = self.prompt
        if hasattr(self, 'uid') and self.uid == 0:
            power = '#'
        #return self.localPrompt + power + ' '
        return self.localPrompt + power
