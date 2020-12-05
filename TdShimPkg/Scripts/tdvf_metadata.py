import argparse
import struct
import sys

ATTR_EXTENDMR_BITMASK = 0x1
SEC_TYPE_BFV = 0
SEC_TYPE_CFV = 1
SEC_TYPE_HOB = 2
SEC_TYPE_TEMP_MEM = 3
SEC_TYPE_RSVD = 4

SEC_TYPE_NAMES = [
  'BFV',
  'CFV',
  'TD_HOB',
  'TempMem',
  'Reserved'
]

def guid2str(b):
    '''Convert binary GUID to string.'''
    if len(b) != 16:
        return ""
    a, b, c, d = struct.unpack("<IHH8s", b)
    d = ''.join('%02x' % c for c in bytes(d))
    return "%08x-%04x-%04x-%s-%s" % (a, b, c, d[:4], d[4:])

EFI_FILE_TYPES = {
    0x00: ("unknown",                    "none",        "0x00"),
    0x01: ("raw",                        "raw",         "RAW"),
    0x02: ("freeform",                   "freeform",    "FREEFORM"),
    0x03: ("security core",              "sec",         "SEC"),
    0x04: ("pei core",                   "pei.core",    "PEI_CORE"),
    0x05: ("dxe core",                   "dxe.core",    "DXE_CORE"),
    0x06: ("pei module",                 "peim",        "PEIM"),
    0x07: ("driver",                     "dxe",         "DRIVER"),
    0x08: ("combined pei module/driver", "peim.dxe",    "COMBO_PEIM_DRIVER"),
    0x09: ("application",                "app",         "APPLICATION"),
    0x0a: ("system management",          "smm",         "SMM"),
    0x0b: ("firmware volume image",      "vol",         "FV_IMAGE"),
    0x0c: ("combined smm/driver",        "smm.dxe",     "COMBO_SMM_DRIVER"),
    0x0d: ("smm core",                   "smm.core",    "SMM_CORE"),
    0xf0: ("ffs padding",                "pad",         "0xf0")
}

def _get_file_type(file_type):
    return EFI_FILE_TYPES[file_type] if file_type in EFI_FILE_TYPES else (
        "unknown", "unknown")

class FirmwareFile:
    '''A firmware file is contained within a firmware file system and is
    comprised of firmware file sections.

    struct {
        UCHAR: FileNameGUID[16]
        UINT16: Checksum (header/file)
        UINT8: Filetype
        UINT8: Attributes
        UINT8: Size[3]
        UINT8: State
    };
    '''
    _HEADER_SIZE = 0x18  # 24 byte header, always

    def __init__(self, data):
        header = data[:self._HEADER_SIZE]
        self.valid_header = False

        try:
            self.guid, self.checksum, self.type, self.attributes, \
                self.size, self.state = struct.unpack("<16sHBB3sB", header)
            self.size = struct.unpack("<I", self.size + b"\x00")[0]
        except Exception as e:
            print("Exception in __init__: %s" % (str(e)))
            return

        self.type_name = _get_file_type(self.type)[1]
        self.valid_header = True

class FirmwareVolume:
    '''Describes the features and layout of the firmware volume.
    See PI Spec 3.2.1
    struct EFI_FIRMWARE_VOLUME_HEADER {
        UINT8: Zeros[16]
        UCHAR: FileSystemGUID[16]
        UINT64: Length
        UINT32: Signature (_FVH)
        UINT8: Attribute mask
        UINT16: Header Length
        UINT16: Checksum
        UINT16: ExtHeaderOffset
        UINT8: Reserved[1]
        UINT8: Revision
        [<BlockMap>]+, <BlockMap(0,0)>
    };
    '''

    _HEADER_SIZE = 0x38
    _FFS2 = "8c8ce578-8a3d-4f1c-9935-896185c32dd3"
    _NVRAM = "fff12b8d-7696-4c8b-a985-2747075b4f50"

    name = None

    def __init__(self, data):
        self.valid_header = False
        try:
            header = data[:self._HEADER_SIZE]
            self.rsvd, self.guid, self.size, self.magic, self.attributes, \
            self.hdrlen, self.checksum, self.extHeaderOffset, self.rsvd2, \
            self.revision = struct.unpack("<16s16sQ4sIHHH1sB", header)
        except Exception as e:
            print("Exception in FirmwareVolume::__init__: %s" % (str(e)))
            return

        if self.magic != b'_FVH':
            return

        str_guid = guid2str(self.guid)
        if str_guid == self._FFS2:
            self.name = "bfv"
        elif str_guid == self._NVRAM:
            self.name = "cfv"
        else:
            return

        self.valid_header = True
        pass

def find_padding_space_from_bfv(input_data):
    '''
    walk thru bfv to find out the padding space
    :param data:
    :return: paddings = [{'size': xxx, 'offset': xxx}]
    '''

    data = input_data[:128]
    fv = FirmwareVolume(data)
    assert (fv.valid_header == True and fv.name == 'bfv')
    data = input_data[fv.hdrlen:]
    total_len = len(data)
    i = 0

    paddings = []
    offset = fv.hdrlen

    while total_len > 0:
        file = FirmwareFile(data[:0x18])
        assert(file.valid_header == True)
        print("  >%d: %s, %s, %d(0x%08x)" % (i, file.type_name, guid2str(file.guid), file.size, file.size))
        size = (file.size + 7) & (~7)
        if file.type_name == "pad":
            paddings.append({'offset':offset, 'size':size})

        offset += size
        data = input_data[offset:]
        total_len -= size
        i += 1

    return paddings

def build_tdvf_desc(fv_infos, mailbox, hob, stack, heap, bfv):
    '''
    build the tdvf metadata
    :param fv_infos:
    :param mailbox
    :param hob
    :param stack
    :param heap
    :param bfv
    :return:
    '''
    tdvf_desc = TdvfDescriptor()
    bfv_data_offset = fv_infos['bfv']['offset']
    bfv_data_size = fv_infos['bfv']['size']

    ## BFV
    sec_bfv = TdvfSection(data_offset=bfv_data_offset,
                          raw_data_size=bfv_data_size,
                          memory_address=bfv['base'],
                          memory_data_size=bfv['size'],
                          sec_type=SEC_TYPE_BFV,
                          attributes=ATTR_EXTENDMR_BITMASK)
    tdvf_desc.append_section(sec_bfv)

    ## Stack
    sec_temp_mem = TdvfSection(data_offset=0,
                            raw_data_size=0,
                            memory_address=stack['base'],
                            memory_data_size=stack['size'],
                            sec_type=SEC_TYPE_TEMP_MEM,
                            attributes=0)
    tdvf_desc.append_section(sec_temp_mem)

    ## Heap
    sec_temp_mem = TdvfSection(data_offset=0,
                            raw_data_size=0,
                            memory_address=heap['base'],
                            memory_data_size=heap['size'],
                            sec_type=SEC_TYPE_TEMP_MEM,
                            attributes=0)
    tdvf_desc.append_section(sec_temp_mem)

    ## HOB
    sec_hob = TdvfSection(data_offset=0,
                          raw_data_size=0,
                          memory_address=hob['base'],
                          memory_data_size=hob['size'],
                          sec_type=SEC_TYPE_HOB,
                          attributes=0)
    tdvf_desc.append_section(sec_hob)

    ## MAILBOX
    sec_mailbox = TdvfSection(data_offset=0,
                          raw_data_size=0,
                          memory_address=mailbox['base'],
                          memory_data_size=mailbox['size'],
                          sec_type=SEC_TYPE_TEMP_MEM,
                          attributes=0)
    tdvf_desc.append_section(sec_mailbox)

    return tdvf_desc

class TdvfDescriptor:
    '''
    TDVF Descriptor
    struct {
        UINT8 Signature[4];
        UINT32 Length;
        UINT32 Version;
        UINT32 NumberOfSectionEntry;
        // TDVF_SECTION[] SectionEntries;
    }
    '''
    _VERSION = 1
    _SIGNATURE = b'TDVF'
    HEADER_SIZE = 16

    def __init__(self, data = None):
        self.sections = []

        if data is None:
            self.header = True
            self.signature = TdvfDescriptor._SIGNATURE
            self.length = TdvfDescriptor.HEADER_SIZE  ## sizeof(signature + length + version + num_of_secs)
            self.version = TdvfDescriptor._VERSION
            self.num_of_secs = 0
        else:
            self.header = False
            try:
                self.signature, self.length, self.version, self.num_of_secs = struct.unpack("<4sIII", data)
                if self.signature == TdvfDescriptor._SIGNATURE:
                    self.header = True
                else:
                    print("Signature of TDVF desc is in-correct!")

            except Exception as e:
                print("Failed to parse TDVF desc header(%s)"%(str(e)))

        pass

    def append_section(self, section):
        self.sections.append(section)
        self.length += TdvfSection.SIZE

    def build(self):
        self.num_of_secs = len(self.sections)
        data = struct.pack('<4sIII', self.signature, self.length, self.version, self.num_of_secs)
        for sec in self.sections:
            ds = sec.build()
            data = data + ds
        return data

    def dump(self):
        print("Signature             : %s" % self.signature.decode('utf-8'))
        print("Length                : %d" % self.length)
        print("Version               : %d" % self.version)
        print("NumberOfSectionEntry  : %d" % len(self.sections))
        print("Sections              :")
        for sec in self.sections:
            sec.dump()
        pass

class TdvfSection:
    '''
    TDVF Section
    struct {
        UINT32 DataOffset
        UINT32 RawDataSize
        UINT64 MemoryAddress
        UINT64 MemoryDataSize
        UINT32 Type
        UINT32 Attributes
    }
    '''
    SIZE = 32

    def __init__(self, data_offset, raw_data_size, memory_address, memory_data_size, sec_type, attributes):
        self.data_offset = data_offset
        self.raw_data_size = raw_data_size
        self.memory_address = memory_address
        self.memory_data_size = memory_data_size
        self.sec_type = sec_type if sec_type >= SEC_TYPE_BFV and sec_type <= SEC_TYPE_RSVD else SEC_TYPE_RSVD
        self.attributes = attributes

    @classmethod
    def from_data(self, data):
        sec = None
        try:
            data_offset, raw_data_size, memory_address, memory_data_size, sec_type, attributes = struct.unpack("<IIQQII", data)
            sec = TdvfSection(data_offset, raw_data_size, memory_address, memory_data_size, sec_type, attributes)
        except Exception as e:
            print("Failed to parse TdvfSection(%s)"%str(e))
        return sec

    def build(self):
        data = struct.pack(
            '<IIQQII', self.data_offset, self.raw_data_size, self.memory_address, self.memory_data_size, self.sec_type, self.attributes)
        return data

    def dump(self):
        print(" base: 0x%08x, len: 0x%08x, type: 0x%08x, attr: 0x%08x, raw_offset: 0x%08x, size: 0x%08x <-- %s" % \
              (self.memory_address, self.memory_data_size, \
               self.sec_type, self.attributes, \
               self.data_offset, self.raw_data_size, \
               SEC_TYPE_NAMES[self.sec_type]))
        pass

def walk_tdvf_for_static_infos(data, offset):
    signature = 'e9eaf9f3-168e-44d5-a8eb-7f4d8738f6ae'
    total_len = len(data)
    i = offset
    while i < total_len:
        guids = guid2str(data[i:i+16])
        if guids == signature:
            break
        i += 4

    if i == total_len:
        raise Exception("Cannot find signature(%s)!" % signature)
    else:
        i += 16

    mb_base, mb_size = struct.unpack('<QQ', data[i:i+16])
    mailbox = {'base': mb_base, 'size': mb_size}
    i += 16

    hob_base, hob_size = struct.unpack('<QQ', data[i:i+16])
    hob = {'base': hob_base, 'size': hob_size}
    i += 16

    stack_base, stack_size = struct.unpack('<QQ', data[i:i+16])
    stack = {'base': stack_base, 'size': stack_size}
    i += 16

    heap_base, heap_size = struct.unpack('<QQ', data[i:i+16])
    heap = {'base': heap_base, 'size': heap_size}
    i += 16

    bfv_base, bfv_size, rsvd = struct.unpack('<QII', data[i:i+16])
    bfv = {'base': bfv_base, 'size': bfv_size}
    i += 16

    return (mailbox, hob, stack, heap, bfv)

def walk_tdvf_for_fv_infos(input_data, size_in_kb):
    '''
    walk thru tdvf.fd to find out fv infos
    :param input_data: data of tdvf.fd
    :return:
    '''
    total_len = len(input_data)

    fv_infos = {
        'bfv': {'offset':0, 'size':0},
        'cfv': {'offset':0, 'size':0},
        'free': {'offset':0, 'size':0}
    }

    ## walk thru input_data
    skip = 0
    bfv_offset = skip

    # skip the raw data section
    while input_data[bfv_offset:bfv_offset + 1024] == b'\xFF' * 1024:
        bfv_offset += 1024

    sec_no = 0
    # then the BFV/CFV
    while bfv_offset < total_len:
        data = input_data[bfv_offset:bfv_offset + 128]
        fv = FirmwareVolume(data)
        if fv.valid_header == True:
            sec_no += 1
            fv_infos[fv.name] = {'offset': bfv_offset, 'size':fv.size}
            print("#%d %s, offset=%d(0x%08x), size=%d(0x%08x)" % (sec_no, fv.name, bfv_offset, bfv_offset, fv.size, fv.size))
            bfv_offset += fv.size
        else:
            # this is neither BFV nor CFV.
            # walk thru this raw data section
            size = 0
            quit = False
            while True and bfv_offset < total_len:
                data = input_data[bfv_offset + size:bfv_offset + size + size_in_kb]
                if data == b'\xFF' * size_in_kb:
                    size += size_in_kb
                else:
                    # try to parse it as the Firmware Volume header
                    fv = FirmwareVolume(data)
                    if fv.valid_header:
                        quit = True
                    else:
                        size += size_in_kb

                if quit:
                    if size > 0:
                        sec_no += 1
                        print("#%d Raw Data(padding), offset=%d(0x%08x), size=%d(0x%08x)" % (sec_no, bfv_offset, bfv_offset, size, size))
                    bfv_offset += size
                    break

    ## now let's walk thru bfv to find out the free space
    bfv_offset = fv_infos['bfv']['offset']
    bfv_size = fv_infos['bfv']['size']
    data = input_data[bfv_offset:bfv_offset + bfv_size]
    paddings = find_padding_space_from_bfv(data)

    for pad in paddings:
        if pad['size'] > 4096:
            fv_infos['free'] = {'offset': bfv_offset + pad['offset'], 'size': pad['size']}
            break

    return fv_infos

def do_inject_metadata(args):
    tdvf_file = args.tdvf
    output = args.output

    if tdvf_file is None or output is None:
        argparser.print_help(sys.stderr)
        return False

    return inject_metadata(tdvf_file, output) 

def inject_metadata(tdvf_file, output):
    FD_SIZE_IN_KB = 1024

    print("Try to inject metadata into %s" % tdvf_file)

    try:
        with open(tdvf_file, 'rb') as ft:
            tdvf_input_data = ft.read()
    except Exception as e:
        print("Error: Cannot read file (%s) (%s)." % (tdvf_file, str(e)))
        return False

    try:
        fv_infos = walk_tdvf_for_fv_infos(tdvf_input_data, FD_SIZE_IN_KB)
        (mailbox, hob, stack, heap, bfv) = walk_tdvf_for_static_infos(tdvf_input_data, fv_infos['bfv']['offset'])
    except Exception as e:
        print("Exception when walk tdvf(%s), %s" % (tdvf_file, str(e)))
        return False

    ## now generate the tdvf_desc
    tdvf_desc = build_tdvf_desc(fv_infos, mailbox, hob, stack, heap, bfv)

    ## Now dump the tdvf_desc
    print("Dump the tdvf metadata which is to be injected:")
    print("~" * 78)
    tdvf_desc.dump()
    print("~" * 78)

    ## build the metadata
    metadata = tdvf_desc.build()

    ## insert the metadata into fd
    fd_size = len(tdvf_input_data)
    buffer = bytearray(fd_size)
    buffer[:] = tdvf_input_data[:]
    free_start = fv_infos['free']['offset'] + 1024
    buffer[free_start:free_start + len(metadata)] = metadata

    ## set the metadata offset
    metadata_offset = struct.pack('<I', free_start)
    buffer[fd_size - 0x20 : fd_size - 0x1C] = metadata_offset

    try:
        with open(output, 'wb') as fo:
            fo.write(buffer)
            fo.flush()
        print("Metadata injected at 0x%08x" % free_start)
        print("Done.\n")
        return True
    except Exception as e:
        print("Error: Cannot write metatdata to file (%s) (%s)." % (output, str(e)))
        return False

def dump_metadata(args):
    tdvf_file = args.tdvf

    if tdvf_file is None:
        argparser.print_help(sys.stderr)
        return False

    print("Try to dump metadata info in %s" % tdvf_file)

    try:
        with open(tdvf_file, 'rb') as ft:
            tdvf_input_data = ft.read()
    except Exception as e:
        print("Error: Cannot read file (%s) (%s)." % (tdvf_file, str(e)))
        return False
    fd_size = len(tdvf_input_data)
    offset = struct.unpack("<I", tdvf_input_data[fd_size - 0x20: fd_size - 0x1C])[0]
    print("metadata offset: 0x%08x" % offset)
    if offset <= 0 or offset > fd_size:
        print("Invalid metadata offset. metadata does not exist in %s"%tdvf_file)
        return False

    data = tdvf_input_data[offset:]
    tdvf_desc = TdvfDescriptor(data[:TdvfDescriptor.HEADER_SIZE])
    if not tdvf_desc.header:
        print("Invalid metadata header in offset(0x%x). metadata does not exist in %s" % (offset, tdvf_file))
        return False

    for i in range(tdvf_desc.num_of_secs):
        offset = TdvfDescriptor.HEADER_SIZE + i * TdvfSection.SIZE
        sec = TdvfSection.from_data(data[offset:offset + TdvfSection.SIZE])
        if sec is None:
            break
        tdvf_desc.sections.append(sec)

    ## now dump
    tdvf_desc.dump()
    return True

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(
        description="Inject/dump metadata in tdvf.fd")

    argparser.add_argument(
        '-d', "--dump", action="store_true",
        help="dump the metadata info in the fd")

    argparser.add_argument(
        '-t', "--tdvf",
        help="The input tdvf.fd file")

    argparser.add_argument(
        '-o', "--output",
        help="The output file")

    args = argparser.parse_args()
    ret = True

    if args.dump:
        ret = dump_metadata(args)
    else:
        ret = do_inject_metadata(args)

    exit(0) if ret else exit(1)
