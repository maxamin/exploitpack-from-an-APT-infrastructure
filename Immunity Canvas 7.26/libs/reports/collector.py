import os
import re
try:
    import cPickle as pickle
except ImportError:
    import pickle

from libs import pygeoip
from libs.reports import Reporter, utils

class DataCollector(object):
    def __init__(self):
        self.data = utils.Data()
        
        self._geoip = None
        geoip_path = utils.get_canvas_path('gui', 'WorldMap', 'GeoLiteCity.dat')
        if os.path.exists(geoip_path):
            self._geoip = pygeoip.GeoIP(geoip_path, pygeoip.MMAP_CACHE)
    
    def collect(self):
        """Abstract method to collect data.
        
        Should return a *Data* object.
        """
        raise NotImplementedError('abstract')
    
    def geoip_country(self, ip):
        if self._geoip:
            try:
                return self._geoip.country_name_by_addr(ip)
            except Exception:
                return None
        return None
    
    def get_exploit_cve(self, module):
        p = getattr(module, 'PROPERTY', {})
        p.update(getattr(module, 'DOCUMENTATION', {}))
        cve = p.get('CVE Name', '')
        if not cve:
            cve = p.get('CVE', '')
        return cve
    
    def add_exploit_to_data(self, name):
        """Add exploit details to a *Data* object.
        
        Returns a new or existing *Data* object for the exploit.
        """
        import canvasengine
        
        # see if it has already been added
        exploit = self.data.exploits.get(name)
        if exploit:
            return exploit
        
        # helper func
        def attach_docs(exploit, module):
            def process_value(value):
                if isinstance(value, list):
                    return '\n'.join([process_value(v) for v in value])
                elif isinstance(value, bool):
                    return 'Yes' if value else 'No'
                else:
                    return value
            
            exploit.title = module.NAME
            exploit.version = getattr(module, 'VERSION', '')
            exploit.description = getattr(module, 'DESCRIPTION', 'No description available.')
            exploit.cve = self.get_exploit_cve(module)
            
            p = getattr(module, 'PROPERTY', {})
            p.update(getattr(module, 'DOCUMENTATION', {}))
            
            props = exploit.properties = {}
            for k, v in p.iteritems():
                lk = k.lower()
                v = str(process_value(v)).strip()
                if not v:
                    continue
                elif lk == 'notes':
                    continue
                elif lk in ['cve', 'cve name']:
                    k = 'CVE'
                    v = exploit.cve
                elif re.search('cve|cvss|mfsa|msadv|osvdb', lk):
                    k = k.upper()
                else:
                    k = k.title()
                props[k] = v
        
        # collect the exploit details
        exploit = utils.Data()
        self.data.exploits[name] = exploit
        
        # get exploit description from canvas
        mod = canvasengine.getModule(name)
        exploit.name = name
        attach_docs(exploit, mod)
        
        return exploit

class PickleCollector(DataCollector):
    """Collect data from reporting event objects in a pickle file."""
    
    def process_event(self, event):
        raise NotImplementedError('abstract')
    
    def process_report_pickle(self, filename):
        r = Reporter(data_path=filename)
        for event in r.events():
            self.process_event(event)
