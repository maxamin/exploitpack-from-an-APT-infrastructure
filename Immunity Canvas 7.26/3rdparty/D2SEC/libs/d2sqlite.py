#!/usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2009
#

import sys
import os
import sqlite3

class d2sqlite:
	def __init__(self):
		pass

	def db_connect(self):
		try:
			self.conn = sqlite3.connect(self.db_name)
		except:
			self.log("[D2 LOG] Can't create db %s" % self.db_name)
			return 1

		self.conn.row_factory = sqlite3.Row
		self.cursor = self.conn.cursor()
		return

	def db_close(self):
		self.cursor.close()
		self.conn.close()
		return

	def db_savelog(self, db_log):
		(target, module, report, date) = db_log.split(';')

		if target and module:
			self.db_connect()
			self.cursor.execute("INSERT INTO D2LOG VALUES  (?, ?, ?, ?)", (target, module, report, date))
			self.conn.commit()
			self.db_close()
		return

