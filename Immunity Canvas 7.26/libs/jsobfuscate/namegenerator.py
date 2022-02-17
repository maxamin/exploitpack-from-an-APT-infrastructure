import random

# Objetive:
# A class with is able to generate valid javascript names for variables
# and functions
#
# Rules to follow:
#  Variable names must begin with a letter or the underscore character or a $
#




class NameGenerator:


    def genRandomName(self):    
        raise Exception("Not implemented")


class RandomNameGenerator(NameGenerator):

    def __init__(self):
        self._validFirstChar = "abcdefghijklmnopqrstuvwxyz_$"
        self._validChars = "abcdefghijklmnopqrstuvwxyz0123456789_$"
        self._minLength = 1
        self._maxLength = 15

    def genRandomName(self):
        length = random.randint(self._minLength,self._maxLength)
        name = "".join(random.sample(self._validFirstChar,1))
        if length > 1:
            name += "".join(random.sample(self._validChars,length-1))
        return name


# Other implementation may be a dict-based generator
