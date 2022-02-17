"""CANVAS Report builder"""

import sys
import datetime
import collections

if '.' not in sys.path:
    sys.path.insert(0, '.')
from libs.reports import document, collector, utils
from exploitutils import devlog

from libs import odf
from libs.py3o.template import Template

TEMPLATE_FILE = utils.get_resources_path('report_template.odt')
LOG_LINE_LIMIT = 20

class Collector(collector.PickleCollector):
    """Collects CANVAS data and stats from a reporting pickle."""
    
    def collect(self, data_file):
        # set up the data structure
        data = self.data
        
        data.hosts = {}
        data._nodes = []
        data._exploits = {}
        data.attacks = []
        data.exploits = {}
        
        stats = data.stats = utils.Data()
        stats.hosts_discovered = 0
        stats.hosts_attacked = set()
        stats.exploits_attempted = collections.defaultdict(int)
        stats.hosts_compromised = set()
        stats.successful_exploits = collections.defaultdict(int)
        stats.timeline = collections.defaultdict(lambda: [0, 0])
        
        # process the pickle file
        self.process_report_pickle(data_file)
        
        # add attacks from collected data
        self.add_attacks()
        
        # calc some stats
        stats.hosts_attacked = len(stats.hosts_attacked)
        stats.hosts_compromised = len(stats.hosts_compromised)
        stats.total_exploits_attempted = sum(stats.exploits_attempted.values())
        stats.total_exploits_successful = sum(stats.successful_exploits.values())
        stats.exploits_attempted = len(stats.exploits_attempted)
        stats.exploits_successful = len(stats.successful_exploits)
        
        return self.data
    
    def process_event(self, event):
        if event.module != 'canvas':
            return
        
        ename = event.name
        if ename == 'new host':
            ip = event.data['ip']
            self.add_host(ip, event)
        elif ename == 'new node':
            node = utils.Data(event.data)
            node.exploit = utils.Data(node.exploit) if node.exploit else None
            node.time = event.time
            node.session_id = event.session_id
            self.data._nodes.append(node)
        elif ename.startswith('exploit'):
            self.add_exploit_event(event)
    
    def add_host(self, ip, event=None):
        data = self.data
        host = data.hosts.get(ip)
        if not host:
            host = utils.Data(event.data if event else {})
            host.ip = ip
            host.attacks = []
            host.commands = []
            data.hosts[ip] = host
            data.stats.hosts_discovered += 1
        return host
    
    def add_exploit_event(self, event):
        edata = event.data
        key = (event.session_id, edata['id'], edata['name'])
        exploit = self.data._exploits.get(key)
        if not exploit:
            exploit = utils.Data(edata)
            self.data._exploits[key] = exploit
        else:
            exploit.update(edata)
        
        start_time = event.time if event.name == 'exploit started' else None
        exploit.started = start_time
        
        # prefer finished, but take whichever is available
        if event.name == 'exploit finished':
            exploit.ended = event.time
        elif event.name == 'exploit returned':
            exploit.ended = event.time
    
    def add_attacks(self):
        data = self.data
        
        seen = set()
        
        # use nodes as a more reliable way to find successful attacks
        for node in data._nodes:
            attack = utils.Data()
            attack.target = node.ip
            attack.successful = True
            attack.node_type = node.type
            attack.node_time = utils.format_datetime(node.time)
            # raw time for sorting
            attack.raw_node_time = node.time
            
            key = None
            if node.exploit:
                attack.name = node.exploit['name']
                key = (node.session_id, node.exploit['id'], attack.name)
                
                exploit = self.add_exploit_to_data(attack.name)
                if exploit:
                    attack.title = exploit.title
                    attack.cve = exploit.cve
            else:
                attack.name = '<unknown>'
                attack.title = 'Unknown Exploit'
            
            event_data = data._exploits.get(key)
            if event_data:
                seen.add(key)
                attack.logdata = event_data.get('logdata', [])
            else:
                attack.logdata = []
            
            self._set_times(attack, event_data)
            
            self.add_attack(attack)
        
        # now check any left over exploit events
        for key, event_data in data._exploits.iteritems():
            if key in seen:
                continue
            
            name = key[2]
            exploit = self.add_exploit_to_data(name)
            exploit_type = exploit.properties['Type'].lower()
            if exploit_type == 'commands':
                continue
            elif exploit_type != 'exploit':
                continue
            
            attack = utils.Data()
            attack.name = name
            attack.target = event_data.get('target')
            attack.successful = event_data.get('success')
            attack.title = exploit.title
            attack.cve = exploit.cve
            attack.logdata = event_data.get('logdata', [])
            
            self._set_times(attack, event_data)
            
            self.add_attack(attack)
    
    def add_attack(self, attack):
        data = self.data
        
        # limit log dump
        cut = len(attack.logdata) - LOG_LINE_LIMIT
        if cut > 0:
            del attack.logdata[:cut]
            attack.logdata.insert(0, '... [%s lines cut] ...' % cut)
        
        data.attacks.append(attack)
        
        host = self.add_host(attack.target)
        host.attacks.append(attack)
        
        stats = data.stats
        stats.hosts_attacked.add(attack.target)
        stats.exploits_attempted[attack.name] += 1
        if attack.successful:
            stats.hosts_compromised.add(attack.target)
            stats.successful_exploits[attack.name] += 1
        
        attack.success_string = 'Yes' if attack.successful else 'No'
    
    def _set_times(self, attack, event_data):
        """Pull start and end times from *event_data* if available."""
        if event_data:
            raw_started = event_data.get('started')
            if raw_started:
                attack.started = utils.format_datetime(raw_started)
                attack.raw_started = raw_started
            
            raw_ended = event_data.get('ended')
            if raw_ended:
                attack.ended = utils.format_datetime(raw_ended)
                attack.raw_ended = raw_ended
            else:
                attack.raw_ended = 0
        else:
            attack.ended = attack.node_time
            attack.raw_ended = attack.raw_node_time

class Document(document.ReportDocument):
    def edit(self, data):
        self.updateCoverDate()
        
        # fill in charts
        chart_doc = self.getObjectByName('timeline_chart')
        self.fill_timeline_chart(chart_doc, data)
        
#        chart_doc = self.getObjectByName('exploited_clients_chart')
#        self.fill_successful_sessions_chart(chart_doc, data)
#        
#        chart_doc = self.getObjectByName('os_distribution_chart')
#        self.fill_os_distribution_chart(chart_doc, data)
#        
#        chart_doc = self.getObjectByName('browser_distribution_chart')
#        self.fill_browser_distribution_chart(chart_doc, data)
    
    def fill_timeline_chart(self, doc, data):
        rows = doc.body.getElementsByType(odf.table.TableRows)[0]
        # clear any existing rows
        del rows.childNodes[:]
        
        if not data.attacks:
            return
        
        times = []
        success_times = []
        for attack in data.attacks:
            t = attack.raw_ended
            if not t:
                continue
            times.append(t)
            if attack.successful is True:
                success_times.append(t)
        times.sort()
        
        lo = datetime.datetime.fromtimestamp(times[0])
        hi = datetime.datetime.fromtimestamp(times[-1])
        diff = utils.total_seconds(hi - lo)
        res = utils.time_resolution(diff / 100.0)
        
        timeline = collections.defaultdict(lambda: [0, 0])
        for t in times:
            rt = utils.round_int(t, res)
            if t in success_times:
                timeline[rt][1] += 1
                timeline[rt][0] += 1
            else:
                timeline[rt][0] += 1
        
        lo = utils.round_int(times[0], res)
        hi = utils.round_int(times[-1], res) + res
        blank_check = False
        for i in range(lo, hi, res):
            t = datetime.datetime.fromtimestamp(i).strftime('%a %b %d @ %H:%M')
            if i not in timeline:
                if blank_check:
                    continue
                else:
                    blank_check = True
                    t = '...'
                    values = [0, 0]
            else:
                values = timeline[i]
                blank_check = False
            self.addRowToTableRows(rows, [t] + values)

def generate(data_file, template_file, output_file):
    template_file = template_file or TEMPLATE_FILE
    
    data = Collector().collect(data_file)
    
    Template(template_file, output_file).render(
        {'data': utils.DefaultData(data), 'stats': utils.DefaultData(data.stats)})
    devlog('reports', 'template saved to: %s' % output_file)
    
    doc = Document(output_file)
    doc.edit(data)
    doc.save()
    devlog('reports', 'document saved to: %s' % output_file)

if __name__ == '__main__':
    generate()
