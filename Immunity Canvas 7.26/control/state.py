import sys
if '.' not in sys.path: sys.path.append('.')

import time
import logging

class Operator(object):
    """
    This class encapsulates a remote CANVAS instance (operator).
    """
    
    ACTIVE       = 'ACTIVE'
    DISCONNECTED = 'DISCONNECTED'
    LOG_EXECUTE  = logging.INFO+1
    LOG_SUCCESS  = logging.INFO+2
    LOG_FAILURE  = logging.INFO+3
   
    def __init__(self, uuid, log_root):
        self.uuid              = uuid # Unique operator id
        self.log_root          = log_root
        self.last_seen         = time.time()
        self.state             = Operator.ACTIVE
        self.alias             = ""
        self.groups            = set()
        self.targets           = []
        self.callback          = ""

        self.pong_acknowledged = True
        
        # Complete module execution history
        # Keys are tuples (module_name, module_id, module_session)
        # One can get time-linear sequence by sorting on session/id
        self.modules           = {}
        self._node_tree        = None

        # Logging
        self.logger            = logging.getLogger("%s.%s" % (self.log_root.upper(), self.uuid))

        self.logger.debug      = self._log_debug
        self.logger.info       = self._log_info
        self.logger.execute    = self._log_execute
        self.logger.success    = self._log_success
        self.logger.failure    = self._log_failure
        self.logger.warn       = self._log_warn
        self.logger.error      = self._log_error
        self.logger.critical   = self._log_critical

    
    @property
    def name(self):
        return self.alias if self.alias else self.uuid

    @property
    def node_tree(self):
        return self._node_tree

    @node_tree.setter
    def node_tree(self, value):
        self._node_tree = value

        #print '*' * 70
        #import pprint
        #pprint.pprint(value)
        
        # Parse node tree and extract useful information
        self.parse_targets()
        self.parse_callback()
    
    def parse_targets(self):
        def _parse_targets(node_tree):
            name = node_tree['name']
            ret = [x for x in node_tree['known_hosts'] if x['target']]

            map(ret.extend, map(_parse_targets, node_tree['children']))
            return ret

        self.targets = _parse_targets(self.node_tree)

    def parse_callback(self):
        def _parse_callback(node_tree):
            ret = [x for x in node_tree['interfaces'] if x['callback']]
            map(ret.extend, map(_parse_callback, node_tree['children']))
            return ret
        
        callback = _parse_callback(self.node_tree)
        self.callback = callback[0] if callback else ""

    def log(self, level, msg, *args):
        self.logger.log(level, msg, *args, extra={'uuid' : self.uuid})

    def _log_debug(self, *args):
        self.log(logging.DEBUG, *args)

    def _log_info(self, *args):
        self.log(logging.INFO, *args)

    def _log_warn(self, *args):
        self.log(logging.WARNING, *args)

    def _log_error(self, *args):
        self.log(logging.ERROR, *args)

    def _log_critical(self, *args):
        self.log(logging.CRITICAL, *args)

    def _log_success(self, *args):
        self.log(Operator.LOG_SUCCESS, *args)

    def _log_failure(self, *args):
        self.log(Operator.LOG_FAILURE, *args)

    def _log_execute(self, *args):
        self.log(Operator.LOG_EXECUTE, *args)

    def __hash__(self):
        return hash(self.uuid)
    
    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.uuid == other.uuid
    
    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            err = 'unorderable types: %s() < %s()'
            raise TypeError(err % (self.__class__, other.__class__))
        return self.name < other.name
        
    def __str__(self):
        return "Operator(%x): " % id(self) + " ".join(["%s: <%s>" % (k, v) for (k, v) in self.__dict__.items()])
