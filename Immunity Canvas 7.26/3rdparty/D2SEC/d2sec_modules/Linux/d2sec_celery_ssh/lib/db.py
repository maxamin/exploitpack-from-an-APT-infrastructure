# -*- coding: utf-8 -*-
###
#
# Sqlite3 management library
#
###

###
# STD modules
###
import os, sqlite3, logging

PWN_DB = "d2bfs.sqlite3"
TABLE_MAX_FIELD_SIZE = 50

###
# Sqlite3 support
###
class db(object):

  def __init__(self):
    self.log = logging.getLogger('lib.db')
    self.reset(deep=True)
    self.params['dbname'] = PWN_DB

  ###
  # Primitive database functions 
  ###
  def connect(self):
    try:
      self.params['connex'] = sqlite3.connect(self.params['dbname'])
      self.params['connex'].row_factory = sqlite3.Row
      self.params['cursor'] = self.params['connex'].cursor()
    except Exception, e:
      self.log.error("Connection failed to database : %s" % e)
      self.params['connex'] = None
      return False

  def close(self):
    if self.params['cursor']:
      self.params['cursor'].close()
    if self.params['connex']:
      self.params['connex'].close()

  def select(self, request, value):
    self.params['selects'] = []
    try:
      if not value:
        self.params['cursor'].execute(request)
      else:
        self.params['cursor'].execute(request, value)
      self.params['selects'] = self.params['cursor'].fetchall()
    except Exception, e:
      self.log.error("Select SQL request failed : %s" % e)
      #self.close()
      return False
    return True

  def delete(self, field, value):
    try:
      value = (value,)
      self.params['cursor'].execute("DELETE FROM " + self.params['table'] + " WHERE %s=?" % field, value)
      self.params['connex'].commit()
    except Exception, e:
      self.log.error("Delete SQL request failed : %s" % e)
      #self.close()
      return False
    return True

  def insert(self, request, value):
    try:
      self.db.params['cursor'].execute(request, value)
      self.db.params['connex'].commit()
    except Exception, e:
      self.log.error("Insert SQL request failed : %s" % e)
      #self.close()
      return False
    return True

  ###
  # Database manipulation
  ###
  def schema(self):
    self.select("SELECT tbl_name FROM sqlite_master WHERE type='table'", None)
    self.log.info('TABLES %s' % self.params['dbname'])
    if not self.params['selects']:
      print 'None'
    else:
      self.tables = []
      for select in self.params['selects']:
        #if not select[0] in self.tables and select[0] != 'sqlite_sequence':
        self.tables.append(select[0])
      print '\n'.join(self.tables)

  def dump(self, field, value):
    if field == None and value == None:
      self.select('SELECT * FROM %s' % self.params['table'], None)
    else:
      value = (value,)
      self.select('SELECT * FROM ' + self.params['table'] + ' WHERE %s=?' % field, value)
    self.log.info('DUMP TABLES %s FROM %s' % (self.params['table'], self.params['dbname']))
    if not self.params['selects']:
      return 'None'
    else:
      print display(self.params['selects'][0].keys(), self.params['selects'])
  
  def extract(self, value):
    field = 'id'
    value = (value,)
    self.select('SELECT * FROM ' + self.params['table'] + ' WHERE %s=?' % field, value)
    return self.params['selects']

  ###
  # Db setup
  ###
  def reset(self, deep=False):
    if not hasattr(self, 'params'):
      self.params = {}
    if deep:
      self.params['dbname'] = None
      self.params['connex'] = None
      self.params['cursor'] = None
      self.params['selects'] = dict()
      self.params['table'] = None

  ###
  # Misc functions
  ###
  def list(self):
    for file in os.listdir('databases'):
      if 'sqlite' in file: print '%s' % file

def page(text, lines=34):
  text = text.split('\n')
  for linenum in range(len(text)):
    self.log.info('%s' % text[linenum])
    if ((linenum+1)  % lines) == 0:
      key = raw_input('')
      if key == 'q': break
###
# Others
###

flatten = lambda lists: sum(lists, [])


###
# Output
###

def display_line(data=''):
	"""
	Display a string on a line, without \n at the end, and padded to 100 chars, in order to avoid
	problems due to string overlap.
	"""
	print data.ljust(100), end=='\r'

def adjust_word(word, count, zero='0'):
	"""
	Return "<count> <word>", adding a "s" to <word> if count > 1, or replacing <count> by <zero> if
	count == 0.
	"""
	if count == 0:
		return '%s %s' % (zero, word)
	elif count == 1:
		return '%d %s' % (count, word)
	else:
		return '%d %ss' % (count, word)

def align_doc_string(doc, align=''):
	"""
	Remove excessive tabulations (\t) at the beginning of every <doc> line, using the first
	line's tabulations' count as reference
	"""
	if not doc:
		return ''
	doc = doc.strip('\n').rstrip()
	for i, c in enumerate(doc):
		if c != '\t':
			break
	return align + doc[i:].replace('\n%s' % ('\t'*i), '\n%s' % align)

#
# Data table
#

def display(titles, data, error_message='No results.'):
	"""
	Return an ascii table containing <data>, with <titles> as titles, followed by the number of
	rows contained by <data>
	>>> data = [
	...     ['administrator', 'admin@site.com'],
	...     ['moderator', 'mod@site.com'],
	...     ['user', 'usermail@site.com']
	... ]
	>>> print(table(['user', 'email'], data))
	+-----------------------------------+
	| user          | email             |
	+---------------+-------------------+
	| administrator | admin@site.com    |
	| moderator     | mod@site.com      |
	| user          | usermail@site.com |
	+-----------------------------------+
						   3 rows in set
	>>>
	"""
	if data is None:
		return error_message
	data = [list(map(str, row)) for row in data]

	# If there are no titles, use them, else use integers
	if not titles:
		titles = ['#' + str(x) for x in range(len(data[0]))]

	# Get the longest value for each field
	maxSize = [len(t) for t in titles]
	nbtitles = len(titles)

	# Initialize it
	for k in range(nbtitles):
		for result in data:
			s = len(result[k])
			if s >= TABLE_MAX_FIELD_SIZE:
				maxSize[k] = TABLE_MAX_FIELD_SIZE
				break
			if maxSize[k] < s:
				maxSize[k] = s

	# Display each result
	repeat = nbtitles*3 + sum(maxSize) - 1
	xline = '+' + '-'*repeat + '+\n'
	yline = '+%s+\n' % '+'.join('-'*(x+2) for x in maxSize)
	rows = '%s in set' % adjust_word('row', len(data))
	rows = rows.rjust(repeat+2)
	table  = ''
	table += xline
	table += _display_row(titles, maxSize)
	table += yline
	for result in data:
		table += _display_row(result, maxSize)
	table += xline
	table += rows
	return table

def _display_row(array, cellLengths):
	line = '|'
	for k in range(len(array)):
		value = array[k].replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')
		if len(value) > cellLengths[k]:
			value = value[:cellLengths[k]-3] + '...'
		line += ' ' + value.ljust(cellLengths[k], ' ') + ' |'
	return line + '\n'
