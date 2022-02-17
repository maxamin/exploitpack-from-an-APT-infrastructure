#!/usr/bin/env python

"""
This allows you to quickly create and HTML file using simple API calls
"""

class TABLE:
        def __init__(self):
                self.rows=[]
                self.divisor="""<tr><td style="height: 2px;" background="line.gif"></td></tr>"""
                self.title = "HI" 
                
        def setTitle(self, title):
                self.title = title

        def add(self, row):
                self.rows.append(row)

        def raw(self):
                buf = """<center>
                <table border=0 cellspacing=1 cellpadding=1 width=90% bgcolor=#a60101>
                         <tr><td>
                         <table border=0 bgcolor="#fbecd6" width=100%>
                """

                buf+= "<tr>\n"
                buf+= " <td width=30%% rowspan=%d style=\"vertical-align: top\">" % ((len(self.rows))*2 )
                
                buf+="<h2><b>%s</b></h2>\n</td>" % self.title.raw() 

                first_row=self.rows.pop(0)

                buf+= """<td> %s </td>
                </tr>""" % first_row.raw()
                
                for a in self.rows:
                        buf+=self.divisor
                        buf+="""
                        <tr>
                          <td> %s
                          </td>
                          </tr>\n
                          
                          """ % a.raw()
                        
                buf +="""</table>\n</td></tr></table></center>\n"""
                
                return buf

class BR:
        def __init__(self):
                pass
        
        def raw(self):
                return "<br>\n"

class HTML_Container:
        def __init__(self):
                self.container= []
                self.before = ""
                self.after = ""

        def add(self, obj):
                self.container.append(obj)
                
        def raw(self):
               buf=""
               for a in self.container:
                       buf+= self.before + a.raw() + self.after +"\n"                      
               return buf
       
class LI(HTML_Container):
        def __init__(self):
                HTML_Container.__init__(self)
                self.before = "<li>"
                self.after  = "</li>"
                
class UL(HTML_Container):
        def __init__(self):
                HTML_Container.__init__(self)
                self.before = "<ul>"
                self.after  = "</ul>"

class AHREF:
        def __init__(self):
                self.text= ""
                self.url = ""
                
        def setText(self, text):
                self.text = text
       
        def setURL(self, url):
                self.url = url

        def raw(self):        
                return '<a href="%s"> %s </a>' % (self.url, self.text)

class Text_Container:
        def __init__(self):
                self.obj = None
                self.before= ""
                self.after = ""

        def set(self, obj):
                self.obj = obj

        def raw(self):
                return self.before + self.obj.raw() + self.after 
class IMAGE:
       def __init__(self, text = ""):
                self.text = text

       def set(self, text):
                self.text = text                

       def raw(self):
                return "<img src='%s'>" % self.text                

class H2(Text_Container):
        def __init__(self):
                Text_Container.__init__(self)
                self.before="<h2>"
                self.after ="</h2>"

class CENTER(Text_Container):
        def __init__(self):
                Text_Container.__init__(self)
                self.before="<CENTER>"
                self.after ="</CENTER>"

                
class STRING:
        def __init__(self, text):
                self.text = text

        def setText(self, text):
                self.text = text

        def raw(self):
                return self.text

class BOLD(Text_Container):
        def __init__(self):
                Text_Container.__init__(self)
                self.before= """<span style="font-weight: bold;">"""
                self.after = """</span>"""
        
class TEXT(HTML_Container):
        def __init__(self):
                HTML_Container.__init__(self)
        
                
class HTML:
        def __init__(self):
                self.table = TABLE()
                self.vuln = []
                self.container = HTML_Container()
                
               
        def hdr(self):
		ttag = "CANVAS"
                        
                ret = """<html>
                <head>
                <link rel="stylesheet" href="immunity.css">
                <title>Immunity """+ ttag + """ Report</title>
                <meta content="text/html; charset=ISO-8859-1"
                http-equiv="content-type">
                <!-- top.html-->
                </head>
                <body  marginheight="0" marginwidth="0" topmargin="0" leftmargin="0">
                <table width=100% border=0 cellspacing=0 cellpadding=0 bgcolor=#ffffffff>
                <tr>
                <td width=185> <img src="header.gif"></td>
                <td><center> <h1> Immunity """+ ttag + """ Report</h1></center></td>
                <td width=185> <img src="header.gif"></td>
                </tr>
                </table>
                
                """
                
                return ret
        
        def buttons(self):
                return """<table width=100% background="nav.gif" cellspacing=0 cellpadding=1 >
                <tr><td></td></tr>
                </table><center>
                <b><a href="index.py?Vulns=1">VULNERABILITIES</a> &nbsp;&nbsp;&nbsp;&nbsp;
                <a href="index.py?Tools=1">TOOLS</a> &nbsp;&nbsp;&nbsp;&nbsp; 
                <a href="index.py?Papers=1">PAPERS</a> &nbsp;&nbsp;&nbsp;&nbsp;
                <a href="index.py?Oldies=1">OLD STUFF</a> &nbsp;&nbsp;&nbsp;&nbsp;
                <a href="index.py?SPIKE=1">SPIKE</a></b></center>
                <table width=100% background="nav.gif" cellspacing=0 cellpadding=1>
                <tr><td></td></tr>
                </table>
                <br>"""
                
        def bottom(self):
                return """<p align="right"><font size="1" face="verdana">Copyright &copy; 2003 -
Immunity, Inc.<br>
All Rights Reserved.</font></p>
</body>
</html>"""
        
        def setTitle(self, txt):
                self.table.setTitle(STRING(txt))
                
        def addParagraphwithTitle(self, title, text):

                t=BOLD()
                t.set( STRING(title) )
                h2= H2()
                h2.set(t)
                c=CENTER()
                c.set(h2)
                self.container.add( c )
                #self.container.add( BR() )
                c=CENTER()
                c.set(STRING(text))
                
                self.container.add( c )
                self.container.add( BR() )
                
                
        def addPaper(self, name, text, downloads=[] ):                
                c=HTML_Container()

                t=BOLD()
                t.set ( STRING(name) ) # Vuln name

                c.add( t )
                c.add( STRING(text) )  # Small Description
                c.add( BR() )
                c.add( STRING("Download:") )  # Small Description
                c.add( BR() ) 
                li = LI()
                ul= UL()
                ul.add ( li )
                
                for a in downloads:
                        if a[1] == 0x1: # URL
                                h = AHREF()
                                sp = a[0].split("|")
                                if len(sp) == 2:
                                        h.setURL( sp[0] )
                                        h.setText( sp[1] )
                                else:
                                        # ERROR
                                        print "YAYAYAYAYYAYA"
                                        continue
                                li.add( h )
                        else:
                                li.add( STRING( a[0] ) )
                                
                c.add(ul)
                self.table.add(c)

        
        # downloads is a list of tuple ( text, flag)
        # where flag is: 0-> None  1 -> URL
        # URL text is like that: URL | Text you wanna add
        
        def addTool(self, name, description, url):
                
                c=HTML_Container()
                li= LI()
                li.add( c )
                
                h = AHREF()
                h.setText(name)
                h.setURL(url)

                t=BOLD()
                t.set ( h ) # Vuln name
                
                c.add (t)
                c.add( STRING(description) )
                
                self.table.add(li)
                
        def addSpike(self, name, downloads=[]):
                c=HTML_Container()
                
                t=BOLD()
                t.set ( STRING(name) ) # SPIKE version
                h2=H2()
                h2.set(t)
                c.add(h2)
                c.add( BR() )
                c.add( STRING("Download:") )  # Small Description
                c.add( BR() ) 
                

                li = LI()
                ul= UL()
                ul.add ( li )

                for a in downloads:
                        if a[1] == 0x1: # URL
                                h = AHREF()
                                sp = a[0].split("|")
                                if len(sp) == 2:
                                        h.setURL( sp[0] )
                                        h.setText( sp[1] )
                                else:
                                        # ERROR
                                        print "YAYAYAYAYYAYA"
                                        continue
                                li.add( h )
                        else:
                                li.add( STRING( a[0] ) )
                                
                c.add(ul)
                self.table.add(c)

        def addVulnImage(self, imageaddr):
                c = HTML_Container()
                c.add( IMAGE(imageaddr) )
                self.table.add(c)
 
        def addVuln(self, name, small_descrp, status=[], downloads=[] ):

                c=HTML_Container()
                
                t=BOLD()
                t.set ( STRING(name) ) # Vuln name
                
                c.add( t )
                c.add(BR())
                c.add( STRING(small_descrp) )  # Small Description
                c.add( BR() )

                if status:
                        c.add( STRING("Status:") )  # Small Description
                        c.add( BR() ) 

                        li = LI()
                        ul= UL()
                        ul.add ( li ) 
                
                        for a in status:
                                li.add( STRING(a) )
                        
                        c.add( ul )
                
                
                if downloads:
                        c.add( STRING("Attributes:") )  # Small Description
                        c.add( BR() ) 
        
                        li = LI()
                        ul= UL()
                        ul.add ( li )
                        
                        for a in downloads:
                                if a[1] == 0x1: # URL
                                        h = AHREF()
                                        sp = a[0].split("|")
                                        if len(sp) == 2:
                                                h.setURL( sp[0] )
                                                h.setText( sp[1] )
                                        else:
                                                continue
                                        li.add( h )
                                else:
                                        li.add( STRING( a[0] ) )
                                        
                        c.add(ul)
                
                self.table.add(c)
                return
        
                
        def addSummary(self, name, summary):
                """
                For adding summary lines during a report
                if summary is a string it is just added as a STRING. If it' a list, it's a <LI>
                """
                c=HTML_Container()
                
                t=BOLD()
                t.set ( STRING(name) ) # Vuln name
                
                c.add( t )
                
                
                if type(summary) == type([]):
                    #if summary is a list, we add it as a list
                    c.add(BR())
                    li = LI()
                    ul= UL()
                    ul.add ( li ) 
                    
                    for a in summary:
                            li.add( STRING(a) )
                            
                    c.add( ul )
                else:
                    #otherwise we add it s a strng
                    c.add( STRING(summary) )  # Small Description
                                
                
                self.table.add(c)
                return
                
        def raw(self):
                buf = self.hdr() + BR().raw() *2  #+ self.buttons()

                if self.container.container:
                        buf+= self.container.raw()
                        
                if self.table.rows:
                        buf+= self.table.raw() 
                buf+= self.bottom()
                return buf

        
