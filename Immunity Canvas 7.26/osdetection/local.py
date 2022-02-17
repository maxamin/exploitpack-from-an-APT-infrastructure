import libs.canvasos as canvasos

class localdetect:
    def __init__(self):
        return

    def run_localdetect(self):
        """ local node os detect logic """
        
        self.log('Doing localhost OS detect')

        # if we have the win32 api .. we can just get the version ..
        result = None

        # XXX: ideally we split this out into an external file too ..
        if 'win32api' in self.node.capabilities:
            
            ret,value = self.node.shell.GetVersionEx()

            if ret:

                result = canvasos.new('Windows')

                if value['Major Version'] == 5 and value['Minor Version'] == 0:
                    result.version = '2000'
                    result.servicepack = value['SP string']

                elif value['Major Version'] == 5 and value['Minor Version'] == 1:
                    result.version = 'XP'
                    result.servicepack = value['SP string']

                elif value['Major Version'] == 5 and value['Minor Version'] == 2:
                    result.version="2003"
                    result.servicepack = value['SP string']                                               

        return result
