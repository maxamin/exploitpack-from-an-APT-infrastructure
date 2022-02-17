import struct
import os
import ast

from SerializedObjectCreator import SerializedObjectCreator

class objectcreator(SerializedObjectCreator):
    def __init__(self, **kwargs):
        super(objectcreator,self).__init__(**kwargs)
        
        self.payload_files = {"java.net.InetAddr": os.path.join("deserialization_payloads",
                                                                "apache_commons_32_java_mosdef.obj"),
                              "java.util.Random": os.path.join("deserialization_payloads",
                                                               "apache_commons_random_unsafe_java_mosdef.obj"),
        }
        self.default_payload = "java.net.InetAddr"
        
