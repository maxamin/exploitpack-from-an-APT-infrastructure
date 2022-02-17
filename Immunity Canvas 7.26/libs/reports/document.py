import datetime

from libs.odf import opendocument as _odoc
from libs.odf import text as _text
from libs.odf import draw as _draw
from libs.odf import style as _style
from libs.odf import table as _table
from libs.odf import chart as _chart

class ReportDocument(object):
    """odfpy wrapper for the XML files in an OpenDocument.
    
    odfpy provides a high-level API that gives you full control to edit
    every aspect of an OpenDocument. This class wraps that API and provides
    some helper methods and some CANVAS specific utils.
    """
    
    def __init__(self, filename):
        self._doc = _odoc.load(filename)
        self.filename = filename
    
    @property
    def doc(self):
        return self._doc
    
    def edit(self, data):
        """Abstract method to apply further customizations to the report."""
        raise NotImplementedError('abstract')
    
    def save(self, filename=None):
        filename = filename or self.filename
        doc = self.doc
        
        # remove ./ObjectReplacements/* in the zip file to ensure charts
        # are refreshed
        for d in doc._extra[:]:
            if d.filename.startswith('ObjectReplacements'):
                doc._extra.remove(d)
        
        # for some reason, editing these screws up the order
        doc.childobjects.sort(key=lambda d: d.folder)
        
        doc.save(filename)
    
    def updateCoverDate(self):
        """Updates the first Date field to the current datetime."""
        date = self.doc.body.getElementsByType(_text.Date)[0]
        date.setAttribute('datevalue', datetime.datetime.now().isoformat())
    
    def getObjectByName(self, name):
        doc = self.doc
        frame = None
        for f in doc.text.getElementsByType(_draw.Frame):
            if f.getAttribute('name') == name:
                frame = f
                break
        if not frame:
            raise KeyError('object not found: %s' % name)
        path = frame.childNodes[0].getAttribute('href')
        for obj in doc.childobjects:
            if path.endswith(obj.folder):
                return obj
    
    def addRowToTableRows(self, rows, rowdata):
        """Adds a row to a TableRows element."""
        row = _table.TableRow()
        for value in rowdata:
            valuetype = self.valueType(value)
            cell = _table.TableCell(valuetype=valuetype, value=value)
            p = _text.P(text=value)
            cell.addElement(p)
            row.addElement(cell)
        rows.addElement(row)
    
    def valueType(self, value):
        """Returns an OpenDocument type name for the *value*."""
        if isinstance(value, basestring):
            return 'string'
        elif isinstance(value, bool):
            return 'boolean'
        elif isinstance(value, (int, float)):
            return 'float'
