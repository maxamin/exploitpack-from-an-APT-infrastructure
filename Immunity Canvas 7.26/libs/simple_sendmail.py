##Little library to send email with subject lines and can have attachments etc etc
##
## No error handling in this, gotta wrap however you call this with exception handlers
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

class SendMail:
    
    def __init__(self, server, port, debug=0):
        """
        Set up the connection to the mail server
        """
        self.smtp=smtplib.SMTP(server, port)
        self.smtp.set_debuglevel(debug)
    
    def sendMail(self, to, frm, subject, text, files=[]):
        """
        Construct the damn email
        """   
        msg = MIMEMultipart()
        msg['From'] = frm
        msg['To'] = to
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
    
        msg.attach( MIMEText(text) )
    
        for file in files:
            part = MIMEBase('application', "octet-stream")
            part.set_payload( open(file,"rb").read() )
            Encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="%s"'
                           % os.path.basename(file))
            msg.attach(part)
    
        self.smtp.sendmail(frm, to, msg.as_string() )
        
    def close(self):
        """
        Close down the connection
        """
        self.smtp.quit()