#!/usr/bin/env python

# Proprietary CANVAS source code - use only under the license agreement
# specified in LICENSE.txt in your CANVAS distribution
# Copyright Immunity, Inc, 2002-2006
# http://www.immunityinc.com/CANVAS/ for more information

import sys

if "." not in sys.path:
    sys.path.append(".")

import socket, errno
import urllib
import random
import libs.spkproxy as spkproxy
import zipfile
import tempfile
import glob
import shutil
import csv
import pickle


from exploitutils import *
from tcpexploit import *
from canvasexploit import *
from libs.apache_commons_deserialize import objectcreator

class Registry:
    def __init__(self, registry=None,  index=None, name=None, endpoint=None, classes=None, interfaces=None, fields=None, extensions=None, annotations=None):
        self.index = index if index is not None else 0
        self.registry = registry if registry is not None else ""
        self.object_name = name if name is not None else ""
        self.endpoint = endpoint if endpoint is not None else ""
        self.classes = classes if classes is not None else []
        self.interfaces = interfaces if interfaces is not None else []
        self.fields = fields if fields is not None else []
        self.extensions = extensions if extensions is not None else []
        self.annotations = annotations if annotations is not None else []
        self.strings = []



    def __iter__(self):
        return iter([self.index,self.registry,self.object_name,self.endpoint,self.classes,self.interfaces,self.fields,self.extensions,self.annotations])


class Parser:
    def __init__(self, host , port ):
        self.tc_classdata = {}
        self.keep_looping = True
        self.bound_objets = []
        self.registry = []
        self.registry_idx = 0
        self.record_registry = True
        self.reading_bound = False

        self.offset = 0
        self.path = os.path.dirname(__file__)
        self.socket = socket.socket(socket.AF_INET)

        self.host = host
        self.port = port


    def read_response_offset(self, response, size):
        if size == 0:
            size = 2
        if self.offset == len(response):
            return "end"
        ret = response[self.offset:self.offset+int(size)]
        self.offset += size
        return ret

    def handle_string_element(self, response):
        string_type = self.read_response_offset(response, 2)
        if string_type == "74":  #TC_STRING
            size = self.read_response_offset(response, 4)
            return self.read_response_offset(response, int(size, 16) * 2)
        elif string_type == "7c": #TC_LONGSTRING
            size = self.read_response_offset(response, 16)
            return self.read_response_offset(response, int(size, 16) * 2)
        elif string_type == "71": # TC_REFERENCE
            #int
            self.read_response_offset(response, 8)
            return None
        else:
            return None

    def handle_fields(self, response, tc_classdesc_flag):
        field_count = self.read_response_offset(response, 4)
        tc_field_type_codes = ""
        for i in range(0, int(field_count,16)):
            field_type_code = self.read_response_offset(response, 2)
            tc_field_type_codes = tc_field_type_codes + field_type_code
            if field_type_code.decode('hex') in ('B','C','D','F','I','J','S','Z'):
                # Skip field name
                size = self.read_response_offset(response, 4)
                self.read_response_offset(response, int(size, 16) * 2)
            elif field_type_code.decode('hex') in ('[','L'):
                size = self.read_response_offset(response, 4)
                self.read_response_offset(response, int(size, 16) * 2)

                field_value = self.handle_string_element(response)
                if field_value != None:
                    self.registry[self.registry_idx].fields.append(field_value.decode('hex'))
            else:
                pass
        if self.keep_looping == True:
            self.tc_classdata[tc_classdesc_flag] = tc_field_type_codes
        return


    def handle_class_desc_info(self,response):
        tc_classdesc_flag = self.read_response_offset(response, 2)
        self.handle_fields(response, tc_classdesc_flag)

        self.handle_class_annotation(response)

        self.handle_class_desc(response)

        return

    def handle_class_desc(self,response):

        # Get Type of classDesc
        tc_classdesc_type = self.read_response_offset(response, 2)
        if tc_classdesc_type == "72": # TC_CLASSDESC
            ## Get ClassName
            tc_classdesc_name_length = self.read_response_offset(response, 4)
            tc_classdesc_name = self.read_response_offset(response, int(tc_classdesc_name_length, 16) * 2)

            self.registry[self.registry_idx].classes.append(tc_classdesc_name.decode('hex'))

            ## Skip serial
            tc_classdesc_serial = self.read_response_offset(response, 16)
            self.handle_class_desc_info(response)


        elif tc_classdesc_type == "7d": #TC_PROXYCLASSDESC
            ## Handle PRoxyClassDesc
            self.handle_proxy_class_desc_info(response)
        elif tc_classdesc_type == "70": #TC_NULL
            return 1
        else:
            return


    def handle_object_annotation(self, response):
        while True:
            p = self.read_response_offset(response, 2)
            if p == "78": #TC_ENDBLOCKDATA

                if self.offset == len(response):
                    self.keep_looping = False
                break

            elif p == "77": #TCP_BLOCKDATA
                try:
                    size = self.read_response_offset(response, 2)
                    block = self.read_response_offset(response, int(size,16)*2)
                    tmp_offset = 4
                    unicastref = int(block[:tmp_offset],16)
                    if unicastref == 11:
                        tmp_offset += 12*2
                    elif unicastref == 10:
                        tmp_offset += 10*2
                    else:
                        pass
                    ip_size = block[tmp_offset:tmp_offset+4]
                    tmp_offset += 4
                    ip = block[tmp_offset:tmp_offset+(int(ip_size,16)*2)].decode('hex')
                    tmp_offset += int(ip_size,16)*2
                    port = int(block[tmp_offset:tmp_offset+8],16)
                    ip_port = "%s:%s" %(ip,port)

                    self.registry[self.registry_idx].endpoint = ip_port
                except (TypeError, ValueError, OverflowError) as e:
                    return None
            elif p == "73": #TC_OBJECT
                self.handle_object_element(response)
            elif p == "70": #TC_NULL
                continue
            elif p == "end":
                break
            else:
                return None
                break
        return

    def handle_class_annotation(self, response):
        tc_classdesc_class_annotation = []
        while True:
            #
            p = self.read_response_offset(response, 2)

            if p == "78": #TC_ENDBLOCKDATA
                break
            elif p == "74": #TC_STRING
                # Extract value and name append to annotations
                tc_classdesc_class_annotation_length = self.read_response_offset(response, 4)
                tc_classdesc_class_annotation.append(self.read_response_offset(response, int(tc_classdesc_class_annotation_length,16)*2).decode('hex)'))

                self.registry[self.registry_idx].annotations = tc_classdesc_class_annotation
            elif p == "71": #TC_REFERENCE
                # Skip int
                self.read_response_offset(response, 8)
            elif p == "70": #TC_NULL
                continue
            elif p == "end":
                break
            else:
                break
        return tc_classdesc_class_annotation


    def handle_proxy_class_desc_info(self,response):
        tc_classdesc_interfaces = []
        # Get number of interfaces
        tc_classdesc_count = self.read_response_offset(response, 8)
        # Get interface names
        if int(tc_classdesc_count,16) > 0:
            for i in range(0, int(tc_classdesc_count,16)):
                tc_classdesc_interface_length = self.read_response_offset(response, 4)
                tc_classdesc_interfaces.append(self.read_response_offset(response, int(tc_classdesc_interface_length,16)*2).decode('hex'))

                self.registry[self.registry_idx].interfaces = tc_classdesc_interfaces

        else:
            self.read_response_offset(response, 2)

        # Read Class annotations
        tc_classdesc_class_annotation = self.handle_class_annotation(response)

        # Read Class Desc
        self.handle_class_desc(response)

    def handle_class_data(self, response):
        for key in self.tc_classdata.keys():
            flag = key
            tc_field_type_codes = self.tc_classdata[key]
            if (hex(int(flag,16) & 0x02) == "0x2"): #SC_SERIALIZABLE
                for type in [tc_field_type_codes[i:i+2] for i in range(0, len(tc_field_type_codes), 2)]:
                    if type.decode('hex') in ('J','D'):
                        self.read_response_offset(response, 8)
                    elif type.decode('hex') in ('I','F'):
                        self.read_response_offset(response, 4)
                    elif type.decode('hex') in ('S'):
                        self.read_response_offset(response, 4)
                    elif type.decode('hex') in ('B','C','Z'):
                        self.read_response_offset(response, 2)
                    elif type.decode('hex') in ('L','['):
                        tc_obj_type = self.read_response_offset(response, 2)
                        if tc_obj_type == "73":  # TC_OBJECT
                            self.handle_object_element(response)
                        elif tc_obj_type == "74":  #TC_STRING
                            l = self.read_response_offset(response, 4)
                            self.read_response_offset(response, int(l, 16) * 2)
                        elif tc_obj_type == "71": # TC_REFERENCE
                            #int
                            self.read_response_offset(response, 8)
                        elif tc_obj_type== "70": #TC_NULL
                            continue
                    else:
                            pass
                if (hex(int(flag,16) & 0x01) == "0x1"):
                    self.handle_object_annotation(response)
            else:
                pass


        return

    def handle_object_element(self, response):

        self.handle_class_desc(response)

        ## Handle Class Data
        self.handle_class_data(response)

    def response_parser(self, response , name = "",  registry_idx = 0):

        self.offset = 0
        self.registry_idx = registry_idx
        self.registry = []

        self.reading_bound = False
        rmi_replay_head                 =   self.read_response_offset(response, 2)
        magic_number                    =   self.read_response_offset(response, 4)
        version_number                  =   self.read_response_offset(response, 4)

        while (self.offset<len(response)):
            tc_blockdata = self.read_response_offset(response, 2)
            if tc_blockdata == "77": #TC_BLOCKDATA
                ## Handle Blockdata
                # Get block length
                tc_blockdata_length = self.read_response_offset(response, 2)
                tc_blockdata_data = self.read_response_offset(response, int(tc_blockdata_length, 16) * 2)
            elif tc_blockdata == "73": #TC_OBJECT
                ## Handle ObjectElement

                self.registry.append(Registry(str(self.host) + ":" + str(self.port), self.registry_idx, name))

                self.handle_object_element(response)

                self.registry_idx += 1
            elif tc_blockdata == "75": #Bound Objects
                self.reading_bound = True

                self.registry.append(Registry(str(self.host) + ":" + str(self.port), self.registry_idx))

                self.handle_class_desc(response)

            else:
                if self.reading_bound == True:
                    self.offset -= 2
                    objs_count = int(self.read_response_offset(response, 8),16)
                    if objs_count != 0:
                        for idx in range(0,objs_count):
                            string_value = self.handle_string_element(response)
                            if string_value != None:
                                self.registry[self.registry_idx].strings.append(string_value.decode('hex'))
                    else:
                        continue

                    self.registry_idx += 1
                else:
                    self.registry_idx += 1
                    break

        return self.registry