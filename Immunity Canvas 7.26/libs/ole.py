import struct

ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
TYPE_UNKNOWN_OR_UNALLOCATED = 0x00
TYPE_STORAGE = 0x01
TYPE_STREAM = 0x02
TYPE_ROOT = 0x05

COLOR_RED = 0x00
COLOR_BLACK = 0x01

MAXREGSID = 0xfffffffa
NOSTREAM = 0xffffffff



class CompoundFileHeader:
    def __init__(self):
        self.header_signature = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # 8 bytes
        self.CLSID = "\x00"*16                                      # 16 bytes
        self.minor_version = 0x3E                                   # 2 bytes
        self.mayor_version = 0x3                                    # 2 bytes
        self.byte_order = 0xFFFE                                    # 2 bytes
        #Sector size = 512 bytes
        self.sector_shift = 0x0009                                  # 2 bytes
        # Mini sector size = 64 bytes       
        self.mini_sector_shift = 0x0006                             # 2 bytes
        self.reserved1 = 0x00                                       # 2 bytes
        self.reserved2 = 0x00                                       # 2 bytes
        self.reserved3 = 0x00                                       # 2 bytes
        # must be 0x00 on documents version 3
        self.num_dir_sect = 0x00                                    # 4 bytes
        self.num_fat_sect = 0x00                                    # 4 bytes
        self.first_dir_sect_location = ENDOFCHAIN                   # 4 bytes
        self.transaction_sig_num = 0x00                             # 4 bytes
        self.mini_stream_cutoff_size = 0x00001000                   # 4 bytes
        self.first_mini_fat_loc = ENDOFCHAIN                        # 4 bytes
        self.num_mini_fat_sect = 0x00                               # 4 bytes
        self.first_mini_difat_sect_loc = ENDOFCHAIN                 # 4 bytes
        self.num_difat_sect = 0x00                                  # 4 bytes
        self.difat = []                                             # 4 bytes * 109
        for i in range(109):
            self.difat.append(FREESECT)

    def get_sector_size(self):
        return 2**self.sector_shift

    def get_mini_sector_size(self):
        return 2**self.mini_sector_shift

    def get_raw(self):
        tmp = ""
        tmp += self.header_signature
        tmp += self.CLSID
        tmp += struct.pack("<H", self.minor_version)
        tmp += struct.pack("<H", self.mayor_version)
        tmp += struct.pack("<H", self.byte_order)
        tmp += struct.pack("<H", self.sector_shift)
        tmp += struct.pack("<H", self.mini_sector_shift)
        tmp += struct.pack("<H", self.reserved1)
        tmp += struct.pack("<H", self.reserved2)
        tmp += struct.pack("<H", self.reserved3)
        tmp += struct.pack("<I", self.num_dir_sect)
        tmp += struct.pack("<I", self.num_fat_sect)
        tmp += struct.pack("<I", self.first_dir_sect_location)
        tmp += struct.pack("<I", self.transaction_sig_num)
        tmp += struct.pack("<I", self.mini_stream_cutoff_size)
        tmp += struct.pack("<I", self.first_mini_fat_loc)
        tmp += struct.pack("<I", self.num_mini_fat_sect)
        tmp += struct.pack("<I", self.first_mini_difat_sect_loc)
        tmp += struct.pack("<I", self.num_difat_sect)
        for i in range(109):
            tmp += struct.pack("<I", self.difat[i])

        if len(tmp) != self.get_sector_size():
            raise Exception("Something is wrong")

        return tmp

class FAT:
    def __init__(self, sector_size, nsectors):
        self.sector_size = sector_size
        self.nsectors = nsectors 
        self.sector = []

        for i in range(self.nsectors):
            self.sector.append(FREESECT)

    def sector_num_to_offset(self, sector_num):
        raise Exception("must be implemented on child")

    def chain(self, start, end):
        for i in range(start, end):
            self.sector[i] = i+1
        self.sector[end] = ENDOFCHAIN

    def sectn_to_str(self, n):
        tmp = ""
        if self.sector[n] == ENDOFCHAIN:
            tmp = "0xFFFFFFFE (ENDOFCHAIN)"
        elif self.sector[n] == FREESECT:
            tmp = "0xFFFFFFFF (FREESECT)"
        elif self.sector[n] == FATSECT:
            tmp = "0xFFFFFFFD (FATSECT)"
        elif self.sector[n] == DIFSECT:
            tmp = "0xFFFFFFFC (DIFSECT)"
        else:
            tmp = "0x%x (%d)" % (self.sector[n], self.sector[n])
        return tmp
            

    def dump(self):
        for i in range(self.nsectors):

            print "%d -> %s" % (i, self.sectn_to_str(i))

    def get_raw(self):
        tmp = ""
        for i in range(self.nsectors):
            tmp += struct.pack("<I", self.sector[i])
        return tmp


class FATSector(FAT):
    def __init__(self, header, nfatsectors = 1):
        self.header = header
        self.nfatsectors = nfatsectors
        nentries = nfatsectors * (128 if header.mayor_version == 3 else 1024)
        FAT.__init__(self, header.get_sector_size(), nentries)
        #FAT.__init__(self, header.get_sector_size(), 128 if header.mayor_version == 3 else 1024)
 
    def sector_num_to_offset(self, sector_num):
        return (sector_num + 1 ) * self.sector_size

    def get_raw(self):
        tmp = FAT.get_raw(self)
        if len(tmp) != self.header.get_sector_size() * self.nfatsectors:
            raise Exception("Something is wrong")
        return tmp



class MiniFATSector(FAT):
    def __init__(self, header):
        self.header = header
        FAT.__init__(self, header.get_mini_sector_size(), 128 if header.mayor_version == 3 else 1024)
 
    def sector_num_to_offset(self, sector_num):
        return sector_num * self.sector_size

    def get_raw(self):
        tmp = FAT.get_raw(self)
        if len(tmp) != self.header.get_sector_size():
            raise Exception("Something is wrong")
        return tmp


class DIFATSector(FAT):
    def __init__(self, header):
        FAT.__init__(self, header.get_sector_size(), 127 if header.mayor_version == 3 else 1023)
        self.header = header
        self.nextDIFAT = ENDOFCHAIN
 
    def sector_num_to_offset(self, sector_num):
        return sector_num * self.sector_size

    def get_raw(self):
        tmp = FAT.get_raw(self)
        tmp += struct.pack("<I", self.nextDIFAT)

        if len(tmp) != self.header.get_sector_size():
            raise Exception("Something is wrong")

        return tmp


class DirectoryEntry():
    def __init__(self, name=""):

        self.directory_entry_name = ""                          # 64 bytes
        self.directory_entry_name_length = 0x00                 # 2 bytes
        if len(name)>0:
            self.set_name(name)

        self.object_type = TYPE_UNKNOWN_OR_UNALLOCATED     # 1 byte
        self.color = COLOR_BLACK                           # 1 byte
        self.left_silving_id = NOSTREAM                    # 4 bytes
        self.right_silving_id = NOSTREAM                   # 4 bytes
        self.child_id = NOSTREAM                           # 4 bytes
        self.CLSID = 0x00                                       # 16 bytes
        self.state = 0x00                                       # 4 bytes
        self.creation_time = 0x00                               # 8 bytes
        self.modified_time = 0x00                               # 8 bytes
        self.starting_sector_location = 0x00                    # 4 bytes
        self.stream_size = 0x00                                 # 8 bytes

    def set_name(self, name):
        self.directory_entry_name = name.encode("utf-16") [2:]
        self.directory_entry_name_length = len(self.directory_entry_name) + 2

    def set_CLSID(self, data1, data2, data3):
        self.CLSID = data1<<8*8 | data3<<8*4 | data2
 
    def get_raw(self):

        tmp = ""
        tmp += self.directory_entry_name + "\x00"*(64-len(self.directory_entry_name))
        tmp += struct.pack("<H", self.directory_entry_name_length)
        tmp += struct.pack("<B", self.object_type)
        tmp += struct.pack("<B", self.color)
        tmp += struct.pack("<I", self.left_silving_id)
        tmp += struct.pack("<I", self.right_silving_id)
        tmp += struct.pack("<I", self.child_id)

        #TODO Is this correct?
        tmp += struct.pack("<Q", (0xFFFFFFFFFFFFFFFF0000000000000000 & self.CLSID) >> 8*8)
        tmp += struct.pack("<Q", (0xFFFFFFFFFFFFFFFF & self.CLSID))

        tmp += struct.pack("<I", self.state)
        tmp += struct.pack("<Q", self.creation_time)
        tmp += struct.pack("<Q", self.modified_time)
        tmp += struct.pack("<I", self.starting_sector_location)
        tmp += struct.pack("<Q", self.stream_size)

        if len(tmp) != 128:
            raise Exception("Something is wrong")

        return tmp

class RootDirectoryEntry(DirectoryEntry):
    def __init__(self):
        DirectoryEntry.__init__(self, "Root Entry")
        self.object_type = TYPE_ROOT

class StorageDirectoryEntry(DirectoryEntry):
    def __init__(self, name):
        DirectoryEntry.__init__(self, name)
        self.object_type = TYPE_STORAGE

class StreamDirectoryEntry(DirectoryEntry):
    def __init__(self, name):
        DirectoryEntry.__init__(self, name)
        self.object_type = TYPE_STREAM

class UnusedFreeDirectoryEntry(DirectoryEntry):
    def __init__(self):
        DirectoryEntry.__init__(self)
        self.object_type = TYPE_UNKNOWN_OR_UNALLOCATED
        self.color = COLOR_RED

       

class DirectorySector():
    def __init__(self, header):
        self.nentries = header.get_sector_size()/128
        self.entry = []
       
    def add_entry(self, e):
        self.entry.append(e)

    def get_raw(self):
        tmp = ""
        for entry in self.entry:
            tmp += entry.get_raw()
        return tmp



class MiniStreamSector():
    def __init__(self, header):
        self.header = header
        self.sector_size = header.get_mini_sector_size()
        self.nsectors = header.get_sector_size()/self.sector_size

        self.sector = []
        for i in range(self.nsectors):
            self.sector.append("\x00"*self.sector_size)

    def set_sector_data(self, id, data):
        if len(data) != self.sector_size:
            raise Exception("data must be 0x%x bytes"%self.sector_size)

        self.sector[id] = data


    def get_sector_data(self, id):
        return self.sector[id]


    def get_raw(self):
        tmp = ""
        for sector in self.sector:
            tmp += sector
        tmp += "\x00"*(self.header.get_sector_size() - len(tmp))
        return tmp

 
class SecuentialMiniStreamSectorGroup():
    def __init__(self, header):
        self.header = header
        self.ministreams = []
    
    # Add a minisector to the group, and returns the absolute sector #
    def add_minisector(self, data):

        if len(self.ministreams) == 0:
            self.ministreams.append(SecuentialMiniStreamSector(self.header))
       
        # get the last ministream
        current = self.ministreams[len(self.ministreams)-1] 
       
        if current.is_full(): 
            current = SecuentialMiniStreamSector(self.header)
            self.ministreams.append(current)
       
        nsector = current.add_minisector(data) 

        return (len(self.ministreams)-1)*current.nsectors + nsector


    def add_data(self, data):

        mini_sector_size = self.header.get_mini_sector_size()
        first_sector = None
        last_sector = None

        # padd data
        if (len(data)%mini_sector_size != 0):
            data += "\x00"*(mini_sector_size - (len(data)%mini_sector_size))

        for i in range(0,len(data)/mini_sector_size):
            chunk = data[i*mini_sector_size: (i+1)*mini_sector_size]
            nsector = self.add_minisector(chunk)

            if i == 0:
                first_sector = nsector
            last_sector = nsector 


        return (first_sector, last_sector)

    #returns the number of sectors that occupies
    def get_num_sectors(self):
        return len(self.ministreams)

    def get_raw(self):
        tmp = ""
        for m in self.ministreams:
            tmp += m.get_raw()
        return tmp


# Simplified secuential implementation
class SecuentialMiniStreamSector(MiniStreamSector):
    def __init__(self, header):
        MiniStreamSector.__init__(self, header)
        self.nextsectorptr = 0

    def is_full(self):
        return self.nextsectorptr >= self.nsectors
        

    # Adds data to the ministream in sequence, returns the sector #
    def add_minisector(self, data):
        if self.is_full():
            raise Exception("Ministream is full, cant add more data (nextsectorptr = %d)" % self.nextsectorptr)
        self.set_sector_data(self.nextsectorptr, data)
        self.nextsectorptr += 1
        return self.nextsectorptr -1


class StreamSectors():
    def __init__(self, header, data=None):
        self.sector_size = header.get_sector_size()
        self.sectors = []
        if data != None:
            self.set_data(data)

    def add_sector(self, data):
        if len(data) != self.sector_size:
            raise Exception("data must be 0x%x bytes"%self.sector_size)
        self.sectors.append(data)

    def get_num_sectors(self):
        return len(self.sectors)

    def set_data(self, data):

        # padd data
        if (len(data)%self.sector_size != 0):
            data += "\x00"*(self.sector_size - (len(data)%self.sector_size))

        nsectors = len(data)/self.sector_size
    
        for i in range(0,nsectors):
            chunk = data[self.sector_size*i: self.sector_size*(i+1)]
            self.add_sector(chunk)


    def get_raw(self):
        tmp = ""
        for s in self.sectors:
            tmp += s
        return tmp










