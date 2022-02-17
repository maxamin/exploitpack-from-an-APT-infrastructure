import sys
import struct
import base64
import random

class MidiObject(object):
    def parse_variable_length(self, source, index):
        length_value  = 0
        source_index  = index
        continue_flag = 1

        while continue_flag:
            length_value  = (length_value << 7) + (ord(source[source_index]) & 0x7F)
            continue_flag = (ord(source[source_index]) & 0x80)
            source_index += 1

        return (source_index, length_value)

    def unparse_variable_length(self, length):
        continue_flag  = 1
        unparsed_value = []
        length_value   = length

        while continue_flag:
            unparsed_value.append(length_value & 0x7F)
            length_value >>= 7
            continue_flag  = (length_value > 0)

        for value_index in range(1, len(unparsed_value)):
            unparsed_value[value_index] |= 0x80

        unparsed_value = "".join(map(lambda val: chr(val), reversed(unparsed_value)))

        return unparsed_value


class MidiFile():
    def __init__(self):
        self.header = MidiHeader()
        self.tracks = []

    def from_string(self, source):
        source_length = len(source)
        source_index  = 0

        self.header.fill(source[source_index:])

        source_index += MidiHeader.size()

        while source_index < (source_length - 1):
            current_track = MidiTrack()

            current_track.fill(source[source_index:])

            source_index += current_track.chunk_size + MidiTrack.size()

            self.tracks.append(current_track)


    def dump(self):
        retval = ""
        retval = self.header.dump()

        for track in self.tracks:
            retval += track.dump()

        return retval


class MidiHeader(MidiObject):

    def __init__(self):
        self.chunk_id       = ''
        self.chunk_size     = 0
        self.format_type    = 0
        self.track_count    = 0
        self.time_signature = 0

    def size(cls):
        return struct.calcsize('>4sLHHH')

    size = classmethod(size)

    def fill(self, source):
        (
            self.chunk_id,
            self.chunk_size,
            self.format_type,
            self.track_count,
            self.time_signature
        ) = struct.unpack('>4sLHHH', source[:MidiHeader.size()] or "\0" * MidiHeader.size())

    def dump(self):
        return struct.pack('>4sLHHH',   self.chunk_id,
                                        self.chunk_size,
                                        self.format_type,
                                        self.track_count,
                                        self.time_signature)

class MidiTrack(MidiObject):
    def __init__(self):
        self.chunk_id       = ''
        self.chunk_size     = 0
        self.chunk_data     = ''
        self.event_list     = []
        self.last_event     = 0

    def size(cls):
        return struct.calcsize('>4sL')

    size = classmethod(size)

    def fill(self, source):
        (
            self.chunk_id,
            self.chunk_size
        ) = struct.unpack('>4sL', source[:MidiTrack.size()] or "\0" * MidiHeader.size())

        self.chunk_data = source[MidiTrack.size():MidiTrack.size()+self.chunk_size]

        offset = MidiTrack.size()

        while offset < (self.chunk_size + MidiTrack.size()) - 1:
            current_event = MidiEvent(self)

            current_event.fill(source[offset:])

            self.event_list.append(current_event)

            offset += current_event.event_size

    def dump(self):
        retval = struct.pack('>4sL',    self.chunk_id,
                                        self.chunk_size)

        for event in self.event_list:
            retval += event.dump()

        return retval


class MidiEvent(MidiObject):
    XXX = []

    def __init__(self, parent):
        self.parent                = parent
        self.event_size            = 0
        self.meta_event            = False
        self.sysex_event           = False
        self.delta_time            = 0
        self.event_type            = 0
        self.midi_channel          = 0
        self.parameter_a           = 0
        self.parameter_b           = 0
        self.meta_event_type       = 0
        self.meta_parameter_size   = 0
        self.meta_parameter_value  = 0
        self.sysex_parameter_size  = 0
        self.sysex_parameter_value = 0

    def size(cls):
        return 0
        #return struct.calcsize('>4sL')

    def fill(self, source):
        use_last_event = False
        source_index   = 0

        #parse the event delay
        (source_index, self.delta_time) = self.parse_variable_length(source, source_index)

        #parse the event type
        bundled_nibbles = ord(source[source_index])

        if (bundled_nibbles & 0x80):
            source_index          += 1
            use_last_event         = False
            self.parent.last_event = self
            bundled_nibbles_       = bundled_nibbles
        else:
            use_last_event   = True
            bundled_nibbles_ = self.parent.last_event.bundled_nibbles

        self.bundled_nibbles = bundled_nibbles

        if bundled_nibbles_ == 0xFF: #parse meta events
            self.meta_event = True

            self.event_type      = bundled_nibbles

            self.meta_event_type = ord(source[source_index])
            source_index        += 1

            if self.meta_event_type == 0x2F:
                self.meta_parameter_size  = 0
                self.meta_parameter_value = ""
                self.event_size           = source_index
            else:
                (source_index, self.meta_parameter_size) = self.parse_variable_length(source, source_index)

                self.meta_parameter_value = source[source_index:source_index+self.meta_parameter_size]

                self.event_size = source_index + self.meta_parameter_size

        elif bundled_nibbles_ in (0xF0, 0xF7): #parse sysex events
            self.sysex_event = True

            (source_index, self.sysex_parameter_size) = self.parse_variable_length(source, source_index)

# "The SysEx data bytes must always end with a 0xF7 byte to signal the end of the message."
# not sure about this, i don't know if the terminator byte is included in the sysex parameter size

            self.sysex_parameter_value = source[source_index:source_index+self.sysex_parameter_size ]

            self.event_size = source_index + self.sysex_parameter_size

        else: #parse midi events
            self.event_type   = bundled_nibbles & 0xF0
            self.midi_channel = bundled_nibbles & 0x0F

            if use_last_event:
                event_type = self.parent.last_event.event_type
            else:
                event_type = self.event_type

            if event_type in (0x80, 0x90, 0xA0, 0xB0): #parse 2 arguments
                (
                    self.parameter_a,
                    self.parameter_b
                ) = struct.unpack('>BB', source[source_index:source_index+2] or "\0" * 2)

                self.event_size = source_index + 2
            elif event_type in (0xC0, 0xD0): #parse 1 short argument

                self.parameter_a = struct.unpack('>B', source[source_index:source_index+1] or "\0" * 1)[0]

                self.event_size = source_index + 1

            elif event_type == 0xE0: #parse 1 long argument
                self.parameter_a = struct.unpack('>H', source[source_index:source_index+2] or "\0" * 2)[0]

                self.event_size = source_index + 2
            else:
                print "--- %20X" % self.event_type, "---"
                raise Exception("Unknown event type")


        return self.event_size

    def dump(self):
        retval  = ""

        if (self.event_type & 0x80):
            use_last_event         = False
            self.parent.last_event = self
        else:
            use_last_event   = True

        #unparse the event delay
        retval += self.unparse_variable_length(self.delta_time)

        if self.meta_event: #unparse meta events
            retval += chr(self.event_type)
            retval += chr(self.meta_event_type)
            retval += self.unparse_variable_length(self.meta_parameter_size)
            retval += self.meta_parameter_value

        elif self.sysex_event: #unparse sysex events
            retval += chr(self.event_type)
            retval += self.unparse_variable_length(self.sysex_parameter_size)
            retval += self.sysex_parameter_value

        else: #unparse midi events
            retval += chr(self.event_type | self.midi_channel)

            if use_last_event:
                event_type = self.parent.last_event.event_type
            else:
                event_type = self.event_type

            if event_type in (0x80, 0x90, 0xA0, 0xB0): #parse 2 arguments
                if not use_last_event:
                    retval += chr(self.parameter_a)

                retval += chr(self.parameter_b)
                pass

            elif event_type in (0xC0, 0xD0): #parse 1 short argument
                retval += chr(self.parameter_a)
                pass

            elif event_type == 0xE0: #parse 1 long argument
                if not use_last_event:
                    retval += struct.pack('>H', self.parameter_a)
                else:
                    retval += chr(self.parameter_a & 0xFF)
                pass

            else:
                print "--- %20X" % self.event_type, "---"
                raise Exception("Unknown event type")

            #hexdump(retval, " ", 50)

        return retval

