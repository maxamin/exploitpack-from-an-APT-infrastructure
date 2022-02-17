class languagedetect:
    def __init__(self):
        return

    def run_languagedetect(self, os=None):
        ret = self.exploitnodes('getremotelanguage', [self.node])
        self.log('LANGUAGE DETECT: Languages found: %s' % ret[0])
        if os:
            os.languagelist = ret[0]
            if len(ret[0]) == 1:
                self.log('LANGUAGE DETECT: One language found ..')
                os.language = ret[0][0]
        return os
