import re, sys, types

if "." not in sys.path: sys.path.append(".")

from libs.jsparser import *
from libs.jsobfuscate.namegenerator import *
from libs.jsobfuscate.script import *

variables = {}
functions = []
patches = []

rndGen = RandomNameGenerator()




class LexicalTreeIterator:

    _attributes = ["expression", "initializer", "body",
                    "condition", "setup", "update"]

    def __init__(self, baseNode):
        self._baseNode = baseNode


    def _doIterate(self, node, action):

        action(node)

        # Look for childs on attributes
        nodeAttrs = dir(node)
        for attr in self._attributes:
            if attr in nodeAttrs:
                collectData(node[attr])

        # If we are a list of nodes, iterate over it
        for child in node:
            print child.type
            collectData(child)
 

    def iterate(self, action):
        self._doIterate(self._baseNode, action)
        



def processVarDeclaration(node):
    for var in node:
        identifier = var.value
        print "Declaracion de variable ", identifier
        newName=""
        if identifier not in variables.keys():
            newName = rndGen.genRandomName()
            variables[identifier] = newName
        else:
            newName = variables[identifier]



def processIdentifier(node):
    print "Identificador ", node.value
    # If the variable was declared, we patch it
    if node.value in variables.keys():
        patches.append([node.start, node.end, variables[node.value]])


def collectData(node):


    if node.type == "VAR":
        processVarDeclaration(node)

    elif node.type == "IDENTIFIER":
        processIdentifier(node)

    if ("expression" in dir(node)):
        collectData(node.expression)

    if ("initializer" in dir(node)):
        collectData(node.initializer)

    if ("body" in dir(node)):
        collectData(node.body)

    if ("condition" in dir(node)):
        print "CONDITION"
        collectData(node.condition)
        print "</condition>"

    if ("setup" in dir(node)):
        collectData(node.setup)

    if ("update" in dir(node)):
        collectData(node.update)

    for child in node:
        print child.type
        collectData(child)

    


fileName = sys.argv[1]
code = file(sys.argv[1]).read()
result = parse(code, fileName)
print result


#collectData(result)


def recongnitionAction(node):
    print node.type

    if node.type == "VAR":
        processVarDeclaration(node)

def patcherAction(node):

    if node.type == "IDENTIFIER":
        processIdentifier(node)



myIterator = LexicalTreeIterator(result)
myIterator.iterate(recongnitionAction)
myIterator.iterate(patcherAction)





#print result
print "Variables usadas:", variables
#print "Defined Functions:", functions
print "patches to apply:", patches


s = Script(code)

for patch in patches:
    print "Appliying patch ", patch
    s.patch(patch[0], patch[1], patch[2])

print "\n"*5
print s.getCode()
