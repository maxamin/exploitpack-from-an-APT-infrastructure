import struct

class JavaPayloadModifiers(object):
    @staticmethod
    def modify_offset(data, offset, value):
        return data[:offset] + value + data[offset + len(value):]

    @staticmethod
    def replace_string(data, needle, string_value):
        start_idx = data.find(needle)
        end_idx = start_idx + len(needle)

        return data[:start_idx-2] + struct.pack(">H", len(string_value)) + \
               string_value + data[end_idx:]
    
    @staticmethod
    def replace_int(data, needle, int_value):
        start_idx = data.find(needle)
        end_idx = start_idx + 4

        print "start_idx:", start_idx
        print "end_idx:", end_idx

        return data[:start_idx] + struct.pack(">L", int_value) + data[end_idx:]
