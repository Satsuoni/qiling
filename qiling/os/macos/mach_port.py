#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# reference to <Mac OS X and IOS Internals: To the Apple's Core>

from struct import pack, unpack

from qiling.const import *

# define in kernel osfmk/mach/message.h
# mach_msg_header_t:
#   mach_msg_bits_t	msgh_bits;                  unsigned int 
#   mach_msg_size_t	msgh_size;                  4 bytes
#   mach_port_t		msgh_remote_port;           4 bytes
#   mach_port_t		msgh_local_port;            4 bytes
#   mach_port_name_t	msgh_voucher_port;      4 bytes
#   mach_msg_id_t		msgh_id;                4 bytes
class MachMsgHeader():

    def __init__(self, ql):
        self.header_size = 24
        self.ql = ql
        self.msgh_bits = None
        self.msgh_size = None
        self.msgh_remote_port = None
        self.msgh_local_port = None
        self.msgh_voucher_port = 0
        self.msgh_id = None
    
    def read_header_from_mem(self, addr):
        self.msgh_bits = unpack("<L", self.ql.mem.read(addr, 0x4))[0]
        self.msgh_size = unpack("<L", self.ql.mem.read(addr + 0x4, 0x4))[0]
        self.msgh_remote_port = unpack("<L", self.ql.mem.read(addr + 0x8, 0x4))[0]
        self.msgh_local_port = unpack("<L", self.ql.mem.read(addr + 0xc, 0x4))[0]
        self.msgh_voucher_port = unpack("<L", self.ql.mem.read(addr + 0x10, 0x4))[0]
        self.msgh_id = unpack("<L", self.ql.mem.read(addr + 0x14, 0x4))[0]
        # print("size !!!!! {}".format(self.msgh_size))
    def write_hdr_to_mem(self, addr):
        self.ql.mem.write(addr, pack("<L", self.msgh_bits))
        self.ql.mem.write(addr + 0x4, pack("<L", self.msgh_size))
        self.ql.mem.write(addr + 0x8, pack("<L", self.msgh_remote_port))
        self.ql.mem.write(addr + 0xc, pack("<L", self.msgh_local_port))
        self.ql.mem.write(addr + 0x10, pack("<L", self.msgh_voucher_port))
        self.ql.mem.write(addr + 0x14, pack("<L", self.msgh_id))
    # def __str__(self):
    #     return "[MachMsg] bits :{}, size:{}, remote port:{}, local port:{}, voucher port:{}, id:{}".format(
    #         self.msgh_bits,
    #         self.msgh_size,
    #         self.msgh_remote_port,
    #         self.msgh_local_port,
    #         self.msgh_voucher_port,
    #         self.msgh_id,
    #     )


# Mach message Class 
# mach msg: header + content + trailer
class MachMsg():
    def __init__(self, ql):
        self.ql = ql
        self.header = MachMsgHeader(self.ql)
        self.content = b''
        self.trailer = b''
        pass
    
    def read_msg_from_mem(self, addr, size):
        self.header = self.read_msg_header(addr, size)
        if size==0:
            self.header = self.read_msg_header(addr, 24)
        self.ql.log.debug("Mach msg header: msgh_id: {} size: {} remoteport: 0x{:x}  localport: 0x{:x}".format(self.header.msgh_id,self.header.msgh_size,self.header.msgh_remote_port,self.header.msgh_local_port))
        # between header and content is 4 byte \x00
        self.content = self.read_msg_content(addr + self.header.header_size, size - self.header.header_size)

    def write_msg_to_mem(self, addr):
        self.ql.mem.write(addr, pack("<L", self.header.msgh_bits))
        self.ql.mem.write(addr + 0x4, pack("<L", self.header.msgh_size))
        self.ql.mem.write(addr + 0x8, pack("<L", self.header.msgh_remote_port))
        self.ql.mem.write(addr + 0xc, pack("<L", self.header.msgh_local_port))
        self.ql.mem.write(addr + 0x10, pack("<L", self.header.msgh_voucher_port))
        self.ql.mem.write(addr + 0x14, pack("<L", self.header.msgh_id))
        if self.content:
            self.ql.mem.write(addr + 0x18, self.content)
        if self.trailer:
            self.ql.mem.write(addr + 0x18 + len(self.content), self.trailer)

    def read_msg_header(self, addr, size):
        header = MachMsgHeader(self.ql)
        header.read_header_from_mem(addr)
        header.msgh_size = size
        return header

    def read_msg_content(self, addr, size):
        self.ql.log.debug("0x{:X}, {}".format(addr, size))
        return self.ql.mem.read(addr, size)


# Mach Port Class 
# not Finished
class MachPort():

    def __init__(self, port_name):
        self.name = port_name
        pass

#from https://github.com/duo-labs/apple-t2-xpc/blob/master/xpc_types.py

import struct 
#import hexdump as hxdump
import binascii
ENDIANNESS = "little"
import sys

PY3K = sys.version_info >= (3, 0)
STRUCT_ENDIAN = "<" if ENDIANNESS == "little" else ">"

XPC_NULL              = 0x00001000
XPC_BOOL              = 0x00002000
XPC_INT64             = 0x00003000
XPC_UINT64            = 0x00004000
XPC_DOUBLE            = 0x00005000
XPC_POINTER           = 0x00006000
XPC_DATE              = 0x00007000
XPC_DATA              = 0x00008000
XPC_STRING            = 0x00009000
XPC_UUID              = 0x0000a000
XPC_FD                = 0x0000b000
XPC_SHMEM             = 0x0000c000
XPC_MACH_SEND         = 0x0000d000
XPC_ARRAY             = 0x0000e000
XPC_DICTIONARY        = 0x0000f000
XPC_ERROR             = 0x00010000
XPC_CONNECTION        = 0x00011000
XPC_ENDPOINT          = 0x00012000
XPC_SERIALIZER        = 0x00013000
XPC_PIPE              = 0x00014000
XPC_MACH_RECV         = 0x00015000
XPC_BUNDLE            = 0x00016000
XPC_SERVICE           = 0x00017000
XPC_SERVICE_INSTANCE  = 0x00018000
XPC_ACTIVITY          = 0x00019000
XPC_FILE_TRANSFER     = 0x0001a000

XPC_MAGIC             = 0x42133742 #incorrect! 
XPC_PROTO_VER         = 0x00000005
def round_up(i, multiple):
    return i + (-i % multiple)


def pad(data):
    padding = -len(data) % 4
    return data + b"\x00" * padding


def string_to_aligned_bytes(s):
    s_bytes = bytes(s, "utf-8")
    return pad(s_bytes + b"\x00")


class XPCByteStream:
    def __init__(self, data):
        self.data = data

    def __len__(self):
        return len(self.data)

    def __nonzero__(self):
        return len(self.data) > 0

    def pop_bytes(self, length):
        length_up = round_up(length, 4)
        ret, self.data = self.data[:length], self.data[length_up:]
        return ret

    def pop_uint32(self):
        ret, self.data = int.from_bytes(self.data[:4],
                                        ENDIANNESS), self.data[4:]
        return ret

    def pop_int64(self):
        ret, self.data = int.from_bytes(
            self.data[:8], ENDIANNESS, signed=True), self.data[8:]
        return ret

    def pop_uint64(self):
        ret, self.data = int.from_bytes(self.data[:8],
                                        ENDIANNESS), self.data[8:]
        return ret

    def pop_double(self):
        double_bytes, self.data = self.data[:8], self.data[8:]
        return struct.unpack(STRUCT_ENDIAN + "d", double_bytes)[0]

    def pop_aligned_string_len(self, length):
        aligned_length = round_up(length, 4)
        s, self.data = self.data[:aligned_length], self.data[aligned_length:]
        return str(s, "utf-8").rstrip('\0')

    def pop_stream(self, length):
        assert length % 4 == 0
        ret, self.data = XPCByteStream(self.data[:length]), self.data[length:]
        return ret

    def pop_dict_key(self):
        pos = self.data.find(b"\x00")
        return self.pop_aligned_string_len(pos + 1)

    # this method will peek at the next object and attempt to resolve it to a class
    def next_object_class(self):
        type_ = int.from_bytes(self.data[:4], ENDIANNESS)
        switcher = {
            XPC_NULL:               XPC_Null,
            XPC_BOOL:               XPC_Bool,
            XPC_INT64:              XPC_Int64,
            XPC_UINT64:             XPC_Uint64,
            XPC_DOUBLE:             XPC_Double,
            XPC_POINTER:            XPC_Pointer,
            XPC_DATE:               XPC_Date,
            XPC_DATA:               XPC_Data,
            XPC_STRING:             XPC_String,
            XPC_UUID:               XPC_Uuid,
            XPC_FD:                 XPC_Fd,
            XPC_SHMEM:              XPC_Shmem,
            XPC_MACH_SEND:          XPC_Mach_Send,
            XPC_ARRAY:              XPC_Array,
            XPC_DICTIONARY:         XPC_Dictionary,
            XPC_ERROR:              XPC_Error,
            XPC_CONNECTION:         XPC_Connection,
            XPC_ENDPOINT:           XPC_Endpoint,
            XPC_SERIALIZER:         XPC_Serializer,
            XPC_PIPE:               XPC_Pipe,
            XPC_MACH_RECV:          XPC_Mach_Recv,
            XPC_BUNDLE:             XPC_Bundle,
            XPC_SERVICE:            XPC_Service,
            XPC_SERVICE_INSTANCE:   XPC_Service_Instance,
            XPC_ACTIVITY:           XPC_Activity,
            XPC_FILE_TRANSFER:      XPC_File_Transfer
        }
        obj = switcher.get(type_, None)
        if not obj:
            print("Couldn't identify a type.")
            return None
        elif not "pretty_string" in dir(obj):  # unimplemented obj
            print(
                "Attempting to decode unimplemented type \"%s\". This will fail."
                % (obj.__name__))
            return None
        return obj
class XPC_Null:
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_NULL
        elif arg is None:
            self.type = XPC_NULL
        else:
            raise Exception("Requires valid argument, or no argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "Null\n"

    def to_bytes(self):
        return XPC_NULL.to_bytes(4, ENDIANNESS)


class XPC_Bool:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_BOOL
            self.value = bool(arg.pop_uint32())
        elif isinstance(arg, bool):
            self.type = XPC_BOOL
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + ("True\n" if self.value else "False\n")

    def to_bytes(self):
        return XPC_BOOL.to_bytes(4, ENDIANNESS) + self.value.to_bytes(
            4, ENDIANNESS)


class XPC_Int64:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_INT64
            self.value = arg.pop_int64()
        elif isinstance(arg, int):
            self.type = XPC_INT64
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'int64 0x%016x: %d' % (self.value,
                                                      self.value) + "\n"

    def to_bytes(self):
        return XPC_INT64.to_bytes(4, ENDIANNESS) + self.value.to_bytes(
            8, ENDIANNESS)


class XPC_Uint64:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_UINT64
            self.value = arg.pop_uint64()
        elif isinstance(arg, int) and arg >= 0:
            self.type = XPC_UINT64
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'uint64 0x%016x: %d' % (self.value,
                                                       self.value) + "\n"

    def to_bytes(self):
        return XPC_UINT64.to_bytes(4, ENDIANNESS) + self.value.to_bytes(
            8, ENDIANNESS)


class XPC_Double:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DOUBLE
            self.value = arg.pop_double()
        elif isinstance(arg, (float, int)):
            arg = float(arg)
            self.type = XPC_DOUBLE
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'double %f' % (self.value) + "\n"

    def to_bytes(self):
        return XPC_DOUBLE.to_bytes(4, ENDIANNESS) + struct.pack(
            STRUCT_ENDIAN + "d", self.value)


class XPC_Pointer:
    pass


class XPC_Date:
    # stored as nanoseconds since the epoch
    # same format as UINT64
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DATE
            self.value = arg.pop_uint64()
        elif isinstance(arg, int) and arg >= 0:
            self.type = XPC_DATE
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'date 0x%016x: %d' % (self.value,
                                                     self.value) + "\n"

    def to_bytes(self):
        return XPC_DATE.to_bytes(4, ENDIANNESS) + self.value.to_bytes(
            8, ENDIANNESS)


class XPC_Data:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DATA
            self.length = arg.pop_uint32()
            self.value = arg.pop_bytes(length)
        elif isinstance(arg, bytes):
            self.type = XPC_DOUBLE
            self.length = len(arg)
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "data 0x" + "".join("{:02x}".format(x)
                                                   for x in self.value) + "\n"

    def to_bytes(self):
        return XPC_DATA.to_bytes(4, ENDIANNESS) + self.length.to_bytes(
            4, ENDIANNESS) + pad(self.value)


class XPC_String:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_STRING
            length = arg.pop_uint32()
            self.value = arg.pop_aligned_string_len(length)
        elif isinstance(arg, str):
            self.type = XPC_STRING
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + '"%s"' % self.value + "\n"

    def to_bytes(self):
        return XPC_STRING.to_bytes(
            4, ENDIANNESS) + (len(self.value) + 1).to_bytes(
                4, ENDIANNESS) + string_to_aligned_bytes(self.value)


class XPC_Uuid:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_UUID
            self.value = arg.pop_bytes(16)
            assert len(self.value) == 16
        elif isinstance(arg, bytes) and len(arg) == 16:
            self.type = XPC_UUID
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + 'uuid 0x%s' % (binascii.hexlify(
            self.value)) + "\n"

    def to_bytes(self):
        return XPC_UUID.to_bytes(4, ENDIANNESS) + self.value


class XPC_Fd:
    # doesn't seem to be possible to pass Fd's outside a process, so they show
    # up as just the type field and no value
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_FD
        elif arg is None:
            self.type = XPC_FD
        else:
            raise Exception("Requires valid argument, or no argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "File Descriptor (missing)\n"

    def to_bytes(self):
        return XPC_FD.to_bytes(4, ENDIANNESS)


class XPC_Shmem:
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_SHMEM
            self.length = arg.pop_uint32()
            _ = arg.pop_uint32()  # pop off the 4 null bytes
        elif isinstance(arg, int) and arg >= 0:
            self.type = XPC_SHMEM
            self.length = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "Shared Memory length: %d" % (
            self.length) + "\n"

    def to_bytes(self):
        return XPC_SHMEM.to_bytes(4, ENDIANNESS) + self.length.to_bytes(
            4, ENDIANNESS) + b"\x00\x00\x00\x00"


class XPC_Mach_Send:
    #encoded mach_port_t... somehow
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_MACH_SEND
            if len(arg)==0:
                self.port=0
            elif len(arg)==1:
                print(arg.data)
                self.port=arg.data
    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "Encoded port data: {}".format(self.port) + "\n"

def normalize_py():
  ''' Problem 001 - sys.stdout in Python is by default opened in
      text mode, and writes to this stdout produce corrupted binary
      data on Windows

          python -c "import sys; sys.stdout.write('_\n_')" > file
          python -c "print(repr(open('file', 'rb').read()))"
  '''
  if sys.platform == "win32":
    # set sys.stdout to binary mode on Windows
    import os, msvcrt
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

# --- - chunking helpers
def chunks(seq, size):
  '''Generator that cuts sequence (bytes, memoryview, etc.)
     into chunks of given size. If `seq` length is not multiply
     of `size`, the lengh of the last chunk returned will be
     less than requested.

     >>> list( chunks([1,2,3,4,5,6,7], 3) )
     [[1, 2, 3], [4, 5, 6], [7]]
  '''
  d, m = divmod(len(seq), size)
  for i in range(d):
    yield seq[i*size:(i+1)*size]
  if m:
    yield seq[d*size:]

def chunkread(f, size):
  '''Generator that reads from file like object. May return less
     data than requested on the last read.'''
  c = f.read(size)
  while len(c):
    yield c
    c = f.read(size)

def genchunks(mixed, size):
  '''Generator to chunk binary sequences or file like objects.
     The size of the last chunk returned may be less than
     requested.'''
  if hasattr(mixed, 'read'):
    return chunkread(mixed, size)
  else:
    return chunks(mixed, size)
# --- - /chunking helpers


def dehex(hextext):
  """
  Convert from hex string to binary data stripping
  whitespaces from `hextext` if necessary.
  """
  if PY3K:
    return bytes.fromhex(hextext)
  else:
    hextext = "".join(hextext.split())
    return hextext.decode('hex')

def dump(binary, size=2, sep=' '):
  '''
  Convert binary data (bytes in Python 3 and str in
  Python 2) to hex string like '00 DE AD BE EF'.
  `size` argument specifies length of text chunks
  and `sep` sets chunk separator.
  '''
  hexstr = binascii.hexlify(binary)
  if PY3K:
    hexstr = hexstr.decode('ascii')
  return sep.join(chunks(hexstr.upper(), size))

def dumpgen(data):
  '''
  Generator that produces strings:

  '00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................'
  '''
  generator = genchunks(data, 16)
  for addr, d in enumerate(generator):
    # 00000000:
    line = '%08X: ' % (addr*16)
    # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 
    dumpstr = dump(d)
    line += dumpstr[:8*3]
    if len(d) > 8:  # insert separator if needed
      line += ' ' + dumpstr[8*3:]
    # ................
    # calculate indentation, which may be different for the last line
    pad = 2
    if len(d) < 16:
      pad += 3*(16 - len(d))
    if len(d) <= 8:
      pad += 1
    line += ' '*pad

    for byte in d:
      # printable ASCII range 0x20 to 0x7E
      if not PY3K:
        byte = ord(byte)
      if 0x20 <= byte <= 0x7E:
        line += chr(byte)
      else:
        line += '.'
    yield line
  
def hexdump(data, result='print'):
  '''
  Transform binary data to the hex dump text format:

  00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

    [x] data argument as a binary string
    [x] data argument as a file like object

  Returns result depending on the `result` argument:
    'print'     - prints line by line
    'return'    - returns single string
    'generator' - returns generator that produces lines
  '''
  if PY3K and type(data) == str:
    raise TypeError('Abstract unicode data (expected bytes sequence)')

  gen = dumpgen(data)
  if result == 'generator':
    return gen
  elif result == 'return':
    return '\n'.join(gen)
  elif result == 'print':
    for line in gen:
      print(line)
  else:
    raise ValueError('Unknown value of `result` argument')
class XPC_Array:
    # type, length, num_entries, [entry entry entry ...]
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DICTIONARY
            length = arg.pop_uint32()
            array_stream = arg.pop_stream(length)
            num_entries = array_stream.pop_uint32()
            self.value = []
            for i in range(num_entries):
                assert len(array_stream)
                xpc_obj_class = array_stream.next_object_class()
                if not xpc_obj_class:  # if None was returned
                    print("Couldn't decode xpc_object_t type 0x%08x" %
                          array_stream.pop_uint32())
                    hexdump(array_stream.pop_bytes(len(array_stream)))
                    return
                self.value.append(xpc_obj_class(array_stream))
        elif isinstance(arg, (tuple, list)):
            # format is a tuple or list with values that are other XPC_xxx types
            # we don't do any validation checking of the values that are passed in
            self.type = XPC_ARRAY
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        ret = ""
        # open {
        ret += "    " * numi + "[\n"
        # entries
        for v in self.value:
            ret += v.pretty_string(numi + 1)
        # close }
        ret += "    " * numi + "]\n"
        return ret

    def to_bytes(self):
        obj_bytes = b""
        for v in self.value:
            obj_bytes += v.to_bytes()
        return XPC_ARRAY.to_bytes(4, ENDIANNESS) + (
            len(obj_bytes) + 4).to_bytes(4, ENDIANNESS) + len(
                self.value).to_bytes(4, ENDIANNESS) + obj_bytes

    def is_empty(self):
        return len(self.value) == 0


class XPC_Dictionary:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_DICTIONARY
            length = arg.pop_uint32()
            print("len: {}".format(length))
            dict_stream = arg.pop_stream(length)
            num_entries = dict_stream.pop_uint32()
            print("num_entries: {}".format(num_entries))
            self.value = {}
            for i in range(num_entries):
                assert len(dict_stream)
                key = dict_stream.pop_dict_key()
                xpc_obj_class = dict_stream.next_object_class()
                if not xpc_obj_class:  # if None was returned
                    print("Couldn't decode xpc_object_t type 0x%08x" %
                          dict_stream.pop_uint32())
                    hexdump(dict_stream.pop_bytes(len(dict_stream)))
                    return
                self.value[key] = xpc_obj_class(dict_stream)
        elif isinstance(arg, dict):
            # format is a dictionary with string keys and values that are other XPC_xxx types
            # we don't do any validation checking of the dictionary entries that are passed in
            self.type = XPC_DICTIONARY
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        ret = ""
        # open {
        ret += "    " * numi + "{\n"
        #ret += "    " * numi + "{ ~%d entries~\n" % len(self.value) if len(
        #    self.value) != 1 else "    " * numi + "{ ~1 entry~\n"
        numi += 1
        # entries
        for k, v in self.value.items():
            ret += "    " * numi + '"%s":\n' % k
            ret += v.pretty_string(numi + 1)
        numi -= 1
        # close }
        ret += "    " * numi + "}\n"
        return ret

    def to_bytes(self):
        obj_bytes = b""
        for k, v in self.value.items():
            obj_bytes += string_to_aligned_bytes(k) + v.to_bytes()
        return XPC_DICTIONARY.to_bytes(4, ENDIANNESS) + (
            len(obj_bytes) + 4).to_bytes(4, ENDIANNESS) + len(
                self.value).to_bytes(4, ENDIANNESS) + obj_bytes

    def is_empty(self):
        return len(self.value) == 0


class XPC_Error:
    # https://developer.apple.com/documentation/xpc/xpc_type_error?language=objc
    # "Errors in XPC are dictionaries"
    # so this is entirely a guess, but we'll interpret this as we do a dictionary
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_ERROR
            length = arg.pop_uint32()
            dict_stream = arg.pop_stream(length)
            num_entries = dict_stream.pop_uint32()
            self.value = {}
            for i in range(num_entries):
                assert len(dict_stream)
                key = dict_stream.pop_dict_key()
                xpc_obj_class = dict_stream.next_object_class()
                if not xpc_obj_class:  # if None was returned
                    print("Couldn't decode xpc_object_t type 0x%08x" %
                          dict_stream.pop_uint32())
                    hexdump(dict_stream.pop_bytes(len(dict_stream)))
                    return
                self.value[key] = xpc_obj_class(dict_stream)
        elif isinstance(arg, dict):
            # format is a dictionary with string keys and values that are other XPC_xxx types
            # we don't do any validation checking of the dictionary entries that are passed in
            # WARNING: We haven't actually seen any XPC_Errors, so be wary what you stick in here
            self.type = XPC_ERROR
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        ret = ""
        # open {
        ret += "    " * numi + "ERROR: {\n"
        numi += 1
        # entries
        for k, v in self.value.items():
            ret += "    " * numi + '"%s":\n' % k
            ret += v.pretty_string(numi + 1)
        numi -= 1
        # close }
        ret += "    " * numi + "}\n"
        return ret

    def to_bytes(self):
        obj_bytes = b""
        for k, v in self.value.items():
            obj_bytes += string_to_aligned_bytes(k) + v.to_bytes()
        return XPC_ERROR.to_bytes(4, ENDIANNESS) + (
            len(obj_bytes) + 4).to_bytes(4, ENDIANNESS) + len(
                self.value).to_bytes(4, ENDIANNESS) + obj_bytes

    def is_empty(self):
        return len(self.value) == 0


class XPC_Connection:
    # in our testing, connections show up as just the type field and no value,
    # but under the XPC_ENDPOINT type
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_CONNECTION
        elif arg is None:
            self.type = XPC_CONNECTION
        else:
            raise Exception("Requires valid argument, or no argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "Connection (missing)\n"

    def to_bytes(self):
        return XPC_CONNECTION.to_bytes(4, ENDIANNESS)


class XPC_Endpoint:
    # in our testing, connections show up as just the type field and no value,
    # but under the XPC_ENDPOINT type
    def __init__(self, arg=None):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_ENDPOINT
        elif arg is None:
            self.type = XPC_ENDPOINT
        else:
            raise Exception("Requires valid argument, or no argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        return "    " * numi + "Endpoint (missing)\n"

    def to_bytes(self):
        return XPC_ENDPOINT.to_bytes(4, ENDIANNESS)


class XPC_Serializer:
    pass


class XPC_Pipe:
    pass


class XPC_Mach_Recv:
    pass


class XPC_Bundle:
    pass


class XPC_Service:
    pass


class XPC_Service_Instance:
    pass


class XPC_Activity:
    pass


# value should be a tuple or list of two elements
# (msg_id, transfer_size)
class XPC_File_Transfer:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            self.type = arg.pop_uint32()
            assert self.type == XPC_FILE_TRANSFER
            self.msg_id = arg.pop_uint64()
            dict_type = arg.pop_uint32()  # dict type field
            assert dict_type == XPC_DICTIONARY
            dict_length = arg.pop_uint32()  # dict length field
            dict_stream = arg.pop_stream(dict_length)
            dict_entries = dict_stream.pop_uint32()  # dict num entries field
            assert dict_entries == 1
            dict_key = dict_stream.pop_dict_key()
            assert dict_key == "s", "dict_key was \"%s\"" % repr(dict_key)
            dict_value_type = dict_stream.pop_uint32()
            assert dict_value_type == XPC_UINT64
            self.transfer_size = dict_stream.pop_uint64()
        elif isinstance(arg, (list, tuple)) and len(arg) == 2 and isinstance(
                arg[0], int) and isinstance(arg[1], int):
            self.type = XPC_FILE_TRANSFER
            self.msg_id = arg[0]
            self.transfer_size = arg[1]
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.pretty_string(0)

    def pretty_string(self, numi):
        ret = "    " * numi + "MessageId: 0x%x " % (self.msg_id) + "\n"
        ret += "    " * numi + 'File transfer size: 0x%016x %d' % (
            self.transfer_size, self.transfer_size) + "\n"
        return ret

    def to_bytes(self):
        temp_dict = XPC_Dictionary({"s": XPC_Uint64(self.value)})
        return XPC_FILE_TRANSFER.to_bytes(
            4, ENDIANNESS) + self.transfer_size.to_bytes(
                8, ENDIANNESS) + temp_dict.to_bytes()


class XPC_Root:
    def __init__(self, arg):
        if isinstance(arg, XPCByteStream):
            magic = arg.pop_uint32()
            assert magic == XPC_MAGIC
            proto = arg.pop_uint32()
            assert proto == XPC_PROTO_VER
            self.value = XPC_Dictionary(arg)
        elif isinstance(arg, XPC_Dictionary):
            self.value = arg
        else:
            raise Exception("Requires valid argument")

    def __str__(self):
        return self.value.pretty_string(0)  # indentation level

    def to_bytes(self):
        return XPC_MAGIC.to_bytes(4, ENDIANNESS) + XPC_PROTO_VER.to_bytes(
            4, ENDIANNESS) + self.value.to_bytes()

    def is_empty_dict(self):
        return self.value.is_empty()

def xpc_try_decode(ql,data):
    stream=XPCByteStream(data)
    obj=stream.next_object_class()
    inst=obj(stream)
    ql.log.info(inst.pretty_string(0))

"""typedef struct {
	mach_msg_header_t       Head;
	NDR_record_t            NDR;
	kern_return_t           RetCode;
} mig_reply_error_t;
"""
def mig_return_error(ql,in_header,in_content,retcode):
    out_msg = MachMsg(ql)
    ql.log.debug("Returning mig error {}".format(retcode))
    ndr=unpack("<Q",in_content[:8])[0]
    out_msg.header.msgh_bits = 0x00001200
    out_msg.header.msgh_size =24+8+4
    out_msg.header.msgh_remote_port = 0x00000000
    out_msg.header.msgh_local_port = ql.os.macho_mach_port.name
    out_msg.header.msgh_voucher_port = 0
    out_msg.header.msgh_id = in_header.msgh_id +100
    out_msg.content=bytes(pack("<Q",ndr))
    out_msg.content+=bytes(pack("<L",retcode))
    return out_msg
#https://gist.github.com/stek29/cdff84cdb0e51dc7f6770af1915be02d?
#0xcf is bootstrap look up
def try_xpc_bollocks(ql,in_header, in_content):
    off=0
    #true-magic=0x40585043
    test_start=struct.unpack("<L",in_content[:4])[0]
    if test_start==0x40585043:
        xpc_try_decode(ql,in_content[8:])
    else:
        (unk1,port,unk2,msg,magic,proto)=struct.unpack("<LLLLLL",in_content[:24])
        ql.log.debug("XPC?? num: {}, port: 0x{:x} unk: {}, msg?: 0x{:x}, magic: 0x{:x} proto: {}".format(unk1,port,unk2,msg,magic,proto))
        xpc_try_decode(ql,in_content[24:])
    ql.log.info("Error Mach Msgid {}  (XPC call) can not be properly handled, returning error for now".format(in_header.msgh_id))
    
    #raise Exception("XPC not yet working")
    return mig_return_error(ql,in_header, in_content,0x8d)

# Mach Port Manager : 
#   1. handle mach msg
#   2. register some Host Port

"""
 self.msgh_bits,
    #         self.msgh_size,
    #         self.msgh_remote_port,
    #         self.msgh_local_port,
    #         self.msgh_voucher_port,
    #         self.msgh_id,
"""
class MachPortManager():

    def __init__(self, ql, my_port):
        self.ql = ql
        self.host_port = MachPort(0x303)
        self.clock_port = MachPort(0x803)
        self.semaphore_port = MachPort(0x903)
        self.special_port = MachPort(0x707)
        self.my_port = my_port

    def deal_with_msg(self, msg, addr):
        self.ql.log.debug("Message header: remote port: 0x{:x} local port: 0x{:x} bits: 0x{:x}".format(msg.header.msgh_remote_port,msg.header.msgh_local_port,msg.header.msgh_bits))
        if msg.header.msgh_id == 200:
            # host info
            out_msg = self.ql.os.macho_host_server.host_info(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id == 206:
            out_msg = self.ql.os.macho_host_server.host_get_clock_service(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id == 412:
            out_msg=self.ql.os.macho_host_server.host_get_special_port(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id == 3414:
            out_msg = self.ql.os.macho_task_server.task_get_exception_ports(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id == 3418:
            out_msg = self.ql.os.macho_task_server.semaphore_create(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id == 3409:
            out_msg = self.ql.os.macho_task_server.get_special_port(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id == 3405:
            out_msg = self.ql.os.macho_task_server.task_info(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)
        elif msg.header.msgh_id==3410:
            out_msg = self.ql.os.macho_task_server.set_special_port(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)      
        elif msg.header.msgh_id==3603:
            out_msg = self.ql.os.macho_task_server.thread_get_state(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)   
        elif msg.header.msgh_id == 8000:#task_restartable_ranges_register
            out_msg = self.ql.os.macho_task_server.restartable_ranges_register(msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)   

        elif  msg.header.msgh_id >=0x40000000:
            out_msg=try_xpc_bollocks(self.ql,msg.header, msg.content)
            out_msg.write_msg_to_mem(addr)  

        else:
            self.ql.log.info("Error Mach Msgid {} can not be handled".format(msg.header.msgh_id))
            #self.ql.log.debug("Content {}".format(msg.content))
            ##XPC serialization: 
            ##01? port .. 0 \x00\x00\x13\x00
            # \x00\xf0\x00\x00 -> 0000f000 - XPC_DICTIONARY   
            raise Exception("Mach Msgid Not Found")

        self.ql.log.debug("Reply-> Header: {}, Content: {}".format(out_msg.header, out_msg.content))

    def get_thread_port(self, MachoThread):
        return MachoThread.port.name

# XNU define struct :
# struct mach_msg_overwrite_trap_args {
# 	PAD_ARG_(user_addr_t, msg);                     addr length
# 	PAD_ARG_(mach_msg_option_t, option);            int
# 	PAD_ARG_(mach_msg_size_t, send_size);           unsigned int
# 	PAD_ARG_(mach_msg_size_t, rcv_size);            unsigned int
# 	PAD_ARG_(mach_port_name_t, rcv_name);           unsigned int 
# 	PAD_ARG_(mach_msg_timeout_t, timeout);          unsigned int
# 	PAD_ARG_(mach_msg_priority_t, override);        unsigned int
# 	PAD_ARG_8
# 	PAD_ARG_(user_addr_t, rcv_msg);  /* Unused on mach_msg_trap */  addr length
# };
