#!/usr/bin/env python


class HTML:
    """
    A flexible HTML creation class
    """
    
    def __init__(self):
        return
    
    
    def add_html(self, title="", stylesheet="", data=""):
        """
        Adds HTML Header which includes optional title,stylesheet and opening of HTML document
        data should be the html code of the document
        """
        
        return """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
        <html>
        <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>%s</title>
        <link rel="stylesheet" href="%s" type="text/css">
        </head>
        <body>
        %s
        </body>
        </html>
        """%(title, stylesheet, data)
        
        
    
    def ret_cdf(self, class_name):
        """
        Create class name string
        """
        if class_name == "":
            cdf = ""
        else:
            cdf = 'class="%s"'%class_name
            
        return cdf
    
    
    def add_tb(self, class_name="", extras="", data=""):
        """
        Opens up an html table with a preferable class name and style extras
        data should be an html code
        """
        
        return '<table %s %s>%s</table>\n'%(self.ret_cdf(class_name), extras, data)
            
    
    def add_tb_row(self, class_name="", extras="", data=""):
        """
        Adds html table row a preferable class name and style extras
        data should be html code
        """
        return '<tr %s %s>%s</tr>\n'%(self.ret_cdf(class_name), extras, data)
            
    
    def add_tb_data(self, class_name="", extras="", data=""):
        """
        Adds html table data a preferable class name and style extras
        Note: Value can be actual html code snipet
        """
        
        return '<td %s %s>%s</td>\n'%(self.ret_cdf(class_name), extras, data)
            
    
    def add_ulist(self, list_data, class_name="", extras=""):
        """
        Adds an unsorted list from the list specified, note list data can
        contain html code block snipets
        """
        
        buf = '<ul %s %s>\n'%(self.ret_cdf(class_name), extras)
        
        for x in list_data:
            buf += '<li>%s</li>\n'%str(x)
            
        buf += '</ul>\n'
        
        return buf

    
    def add_img(self, fileloc, class_name="", extras=""):
        """
        Adds an image based on file location
        """
        
        return '<img align="right" src="%s" height="350" weight="350" %s %s />\n'%(fileloc, self.ret_cdf(class_name), extras)
            
    
