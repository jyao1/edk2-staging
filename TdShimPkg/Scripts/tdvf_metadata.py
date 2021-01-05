#!/usr/bin python
# -*- coding: UTF-8 -*-
# @file
#
# @copyright
# INTEL CONFIDENTIAL
# Copyright 2020 Intel Corporation. <BR>
#
# The source code contained or described herein and all documents related to the
# source code ("Material") are owned by Intel Corporation or its suppliers or
# licensors. Title to the Material remains with Intel Corporation or its suppliers
# and licensors. The Material may contain trade secrets and proprietary    and
# confidential information of Intel Corporation and its suppliers and licensors,
# and is protected by worldwide copyright and trade secret laws and treaty
# provisions. No part of the Material may be used, copied, reproduced, modified,
# published, uploaded, posted, transmitted, distributed, or disclosed in any way
# without Intel's prior express written permission.
#
# No license under any patent, copyright, trade secret or other intellectual
# property right is granted to or conferred upon you by disclosure or delivery
# of the Materials, either expressly, by implication, inducement, estoppel or
# otherwise. Any license under such intellectual property rights must be
# express and approved by Intel in writing.
#
# Unless otherwise agreed by Intel in writing, you may not remove or alter
# this notice or any other notice embedded in Materials by Intel or
# Intel's suppliers or licensors in any way.
##

import argparse
import struct
import sys
import re
import uuid

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


def is_guid(s):
    if s is None or type(s) is not str:
        return False
    c = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')
    res = c.match(s.lower())
    return False if res is None else True


def guid2str(b):
    '''Convert binary GUID to string.'''
    if len(b) != 16:
        return ""
    a, b, c, d = struct.unpack("<IHH8s", b)
    d = ''.join('%02x' % c for c in bytes(d))
    return "%08x-%04x-%04x-%s-%s" % (a, b, c, d[:4], d[4:])

def str2guid(s):
    '''
        Convert string GUID to binary
        "aaf32c78-947b-439a-a180-2e144ec37792"
    '''
    if s is None or not is_guid(s):
        raise Exception("Invalid GUID string - %s" %("" if s is None else s))

    fields = uuid.UUID(s).fields
    guid1 = struct.pack('<IHHBB', fields[0], fields[1], fields[2], fields[3], fields[4])
    guid2 = struct.pack('>Q', fields[5])
    return guid1 + guid2[2:]

#
# logging level
#
LOG_DBG  = 0x1
LOG_INFO = 0x2
LOG_WARN = 0x4
LOG_ERR  = 0x8

def dbg_log(log_str, build_log=None, log_level=None):
    if build_log:
        build_log.log(log_level, log_str)
    else:
        print(log_str)
    pass

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

    def __init__(self, data=None, build_log=None):
        self.sections = []
        self.build_log = build_log

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
                    dbg_log("Signature of TDVF desc is in-correct!", self.build_log, LOG_ERR)

            except Exception as e:
                dbg_log("Failed to parse TDVF desc header(%s)"%(str(e)), self.build_log, LOG_ERR)

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
        dbg_log("Signature             : %s" % self.signature.decode('utf-8'), self.build_log, LOG_DBG)
        dbg_log("Length                : %d" % self.length, self.build_log, LOG_DBG)
        dbg_log("Version               : %d" % self.version, self.build_log, LOG_DBG)
        dbg_log("NumberOfSectionEntry  : %d" % len(self.sections), self.build_log, LOG_DBG)
        dbg_log("Sections              :", self.build_log, LOG_DBG)
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

    def __init__(self, data_offset, raw_data_size, memory_address, memory_data_size, sec_type, attributes, build_log=None):
        self.data_offset = data_offset
        self.raw_data_size = raw_data_size
        self.memory_address = memory_address
        self.memory_data_size = memory_data_size
        self.sec_type = sec_type if sec_type >= SEC_TYPE_BFV and sec_type <= SEC_TYPE_RSVD else SEC_TYPE_RSVD
        self.attributes = attributes
        self.build_log = build_log

    @classmethod
    def from_data(self, data, build_log=None):
        sec = None
        try:
            data_offset, raw_data_size, memory_address, memory_data_size, sec_type, attributes = struct.unpack("<IIQQII", data)
            sec = TdvfSection(data_offset, raw_data_size, memory_address, memory_data_size, sec_type, attributes, build_log)
        except Exception as e:
            dbg_log("Failed to parse TdvfSection(%s)"%str(e), build_log, LOG_ERR)
        return sec

    def build(self):
        data = struct.pack(
            '<IIQQII', self.data_offset, self.raw_data_size, self.memory_address, self.memory_data_size, self.sec_type, self.attributes)
        return data

    def dump(self):
        dbg_log(" base: 0x%08x, len: 0x%08x, type: 0x%08x, attr: 0x%08x, raw_offset: 0x%08x, size: 0x%08x <-- %s" % \
                (self.memory_address, self.memory_data_size, \
                self.sec_type, self.attributes, \
                self.data_offset, self.raw_data_size, \
                SEC_TYPE_NAMES[self.sec_type]), self.build_log, LOG_DBG)
        pass

def do_inject_metadata(args):
    tdvf_file = args.tdvf
    output = args.output

    if tdvf_file is None or output is None:
        argparser.print_help(sys.stderr)
        return False

    return inject_metadata(tdvf_file, output) 

def inject_metadata(fd_file, output=None, build_log=None):
    '''
    Find the EFI_TDX_METADATA and inject its offset at fd_size-0x20
    '''
    signature = str2guid('e9eaf9f3-168e-44d5-a8eb-7f4d8738f6ae')
    try:
        with open(fd_file, 'rb') as fd:
            data = fd.read()
    except Exception as e:
        dbg_log("Fail to open file - %s(%s)" % (fd_file, str(e)), build_log, LOG_ERR)
        return False

    fd_size = len(data)
    i = 0
    while i < fd_size:
        if signature == data[i:i+16]:
            break
        i += 4

    if i >= fd_size:
        dbg_log("Cannot find TDVF_METADATA signature", build_log, LOG_ERR)
        return False

    i += 16
    buffer = bytearray(fd_size)
    buffer[:] = data[:]

    metadata_offset = struct.pack('<I', i)
    buffer[fd_size - 0x20 : fd_size - 0x1c] = metadata_offset
    if output is None:
        output = fd_file
    try:
        with open(output, 'wb') as fd:
            fd.write(buffer)
            fd.flush()
    except Exception as e:
        dbg_log("Error when open fd file to write. %s" % (str(e)), build_log, LOG_ERR)
        return False

    dbg_log("[Success]Inject metadata offset (0x%x) into 0x%x in file (%s)" % (i, fd_size - 0x20, fd_file), build_log, LOG_DBG)

    # let's dump the injected metadata
    dump_metadata(output, build_log)
    return True

def do_dump_metadata(args):
    tdvf_file = args.tdvf

    if tdvf_file is None:
        argparser.print_help(sys.stderr)
        return False

    return dump_metadata(tdvf_file)

def dump_metadata(tdvf_file, build_log=None):

    dbg_log("Try to dump metadata info in %s" % tdvf_file, build_log, LOG_DBG)

    try:
        with open(tdvf_file, 'rb') as ft:
            tdvf_input_data = ft.read()
    except Exception as e:
        dbg_log("Error: Cannot read file (%s) (%s)." % (tdvf_file, str(e)), build_log, LOG_ERR)
        return False

    fd_size = len(tdvf_input_data)
    offset = struct.unpack("<I", tdvf_input_data[fd_size - 0x20: fd_size - 0x1C])[0]
    dbg_log("metadata offset: 0x%08x" % offset, build_log, LOG_DBG)

    if offset <= 0 or offset > fd_size:
        dbg_log("Invalid metadata offset. metadata does not exist in %s"%tdvf_file, build_log, LOG_ERR)
        return False

    data = tdvf_input_data[offset:]
    tdvf_desc = TdvfDescriptor(data[:TdvfDescriptor.HEADER_SIZE])
    tdvf_desc.build_log = build_log
    if not tdvf_desc.header:
        dbg_log("Invalid metadata header in offset(0x%x). metadata does not exist in %s" % (offset, tdvf_file), build_log, LOG_ERR)
        return False

    for i in range(tdvf_desc.num_of_secs):
        offset = TdvfDescriptor.HEADER_SIZE + i * TdvfSection.SIZE
        sec = TdvfSection.from_data(data[offset:offset + TdvfSection.SIZE])
        sec.build_log = build_log
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
        ret = do_dump_metadata(args)
    else:
        ret = do_inject_metadata(args)

    exit(0) if ret else exit(1)
