#! /usr/bin/env python
#
# Test script for Crypto.Protocol.AllOrNothing
#

__revision__ = "$Id: test_allornothing.py,v 1.2 2006/07/29 02:52:51 phil Exp $"

from sancho.unittest import TestScenario, parse_args, run_scenarios
from Crypto.Cipher import AES
from Crypto.Protocol import AllOrNothing

tested_modules = [ "Crypto.Protocol.AllOrNothing" ]

class AllOrNothingTest (TestScenario):

    def setup (self):
        self.key = 'abcd' * 4

    def shutdown (self):
        del self.key

    def check_digest (self):
        self.test_stmt('AllOrNothing.AllOrNothing(AES, self.key)')
        a = AllOrNothing.AllOrNothing(AES, self.key)
        

if __name__ == "__main__":
    (scenarios, options) = parse_args()
    run_scenarios(scenarios, options)
