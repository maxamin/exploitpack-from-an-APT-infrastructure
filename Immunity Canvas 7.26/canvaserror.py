#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

# In which we register canvas exception types

class CANVASError(Exception):
    pass

class NodeCommandError(CANVASError):
    pass

class NodeCommandUnimplemented(NodeCommandError):
    pass
