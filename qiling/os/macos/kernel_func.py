#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from struct import *

from qiling.const import *
from .const import *
from .mach_port import *


def vm_shared_region_enter(ql):
    ql.mem.map(SHARED_REGION_BASE_X86_64, SHARED_REGION_SIZE_X86_64, info="[shared_region]")
    ql.macos_shared_region = True
    ql.macos_shared_region_port = MachPort(9999)        # random port name


def map_commpage(ql):
    if ql.arch.type == QL_ARCH.X8664:
        addr_base = X8664_COMM_PAGE_START_ADDRESS
        addr_size = 0x100000
    elif ql.arch.type == QL_ARCH.ARM64:
        addr_base = ARM64_COMM_PAGE_START_ADDRESS
        addr_size = 0x1000        
    ql.mem.map(addr_base, addr_size, info="[commpage]")
    time_lock_slide = 0x68
    ql.mem.write(addr_base+time_lock_slide, ql.pack32(0x1))


# reference to osfmk/mach/shared_memory_server.h
class SharedFileMappingNp:

    def __init__(self, ql):
        self.size = 32
        self.ql = ql
    
    def read_mapping(self, addr):
        content = self.ql.mem.read(addr, self.size)
        self.sfm_address = unpack("<Q", self.ql.mem.read(addr, 8))[0]
        self.sfm_size = unpack("<Q", self.ql.mem.read(addr + 8, 8))[0]
        self.sfm_file_offset = unpack("<Q", self.ql.mem.read(addr + 16, 8))[0]
        self.sfm_max_prot = unpack("<L", self.ql.mem.read(addr + 24, 4))[0]
        self.sfm_init_prot = unpack("<L", self.ql.mem.read(addr + 28, 4))[0]

        self.ql.log.debug("[ShareFileMapping]: addr: 0x{:X}, size: 0x{:X}, fileOffset:0x{:X}, maxProt: {}, initProt: {}".format(
            self.sfm_address, self.sfm_size, self.sfm_file_offset, self.sfm_max_prot, self.sfm_init_prot
            ))
"""
struct shared_file_mapping_slide_np {
    mach_vm_address_t       sms_address;     /* address at which to create mapping */
    mach_vm_size_t          sms_size;        /* size of region to map */
    mach_vm_offset_t        sms_file_offset; /* offset into file to be mapped */
    user_addr_t             sms_slide_size;  /* size of data at sms_slide_start */
    user_addr_t             sms_slide_start; /* address from which to get relocation data */
    vm_prot_t               sms_max_prot;    /* protections, plus flags, see below */
    vm_prot_t               sms_init_prot;
};
"""
class SharedFileMappingSlideNp:

    def __init__(self, ql):
        self.size = 48
        self.ql = ql
    
    def read_mapping(self, addr):
        content = self.ql.mem.read(addr, self.size)
        self.sms_address = unpack("<Q", self.ql.mem.read(addr, 8))[0]
        self.sms_size = unpack("<Q", self.ql.mem.read(addr + 8, 8))[0]
        self.sms_file_offset = unpack("<Q", self.ql.mem.read(addr + 16, 8))[0]
        self.sms_slide_size = unpack("<Q", self.ql.mem.read(addr + 24, 8))[0]
        self.sms_slide_start = unpack("<Q", self.ql.mem.read(addr + 32, 8))[0]
        self.sms_max_prot = unpack("<L", self.ql.mem.read(addr + 40, 4))[0]
        self.sms_init_prot = unpack("<L", self.ql.mem.read(addr + 44, 4))[0]
        self.ql.log.debug("[SharedFileMappingSlideNp]: addr: 0x{:X}, size: 0x{:X}, fileOffset:0x{:X}, slidesize:{} slidestart:0x{:X} maxProt: {}, initProt: {}".format(
            self.sms_address, self.sms_size, self.sms_file_offset, self.sms_slide_size, self.sms_slide_start,self.sms_max_prot, self.sms_init_prot
            ))
# Need slide info to do relocation in syscall :(

"""

#define __os_set_crash_log_cause_and_message(ac, msg) \
		({ long _ac = (long)(ac); __asm__ ( \
			"mov	%[_msg], %[_cr_msg]\n\t" \
			"mov	%[_ac], %[_cr_ac]" \
			:	[_ac] "+&a" (_ac), \
				[_cr_msg] "=m" (gCRAnnotations.message), \
				[_cr_ac] "=m" (gCRAnnotations.abort_cause) \
			:	[_msg] "r" (("" msg)) \
		); })
struct vm_shared_region_slide_info_entry_v2 {
    uint32_t        version;
    uint32_t        page_size;
    uint32_t        page_starts_offset;
    uint32_t        page_starts_count;
    uint32_t        page_extras_offset;
    uint32_t        page_extras_count;
    uint64_t        delta_mask;             // which (contiguous) set of bits contains the delta to the next rebase location
    uint64_t        value_add;
    // uint16_t    page_starts[page_starts_count];
    // uint16_t    page_extras[page_extras_count];
};
struct vm_shared_region_slide_info_entry_v3 {
    uint32_t        version;                        // currently 3
    uint32_t        page_size;                      // currently 4096 (may also be 16384)
    uint32_t        page_starts_count;
    uint64_t        value_add;
    uint16_t        page_starts[] /* page_starts_count */;
};
struct vm_shared_region_slide_info_entry_v4 {
    uint32_t    version;        // currently 4
    uint32_t    page_size;      // currently 4096 (may also be 16384)
    uint32_t    page_starts_offset;
    uint32_t    page_starts_count;
    uint32_t    page_extras_offset;
    uint32_t    page_extras_count;
    uint64_t    delta_mask;    // which (contiguous) set of bits contains the delta to the next rebase location (0xC0000000)
    uint64_t    value_add;     // base address of cache
    // uint16_t    page_starts[page_starts_count];
    // uint16_t    page_extras[page_extras_count];
};
typedef union vm_shared_region_slide_info_entry *vm_shared_region_slide_info_entry_t;
union vm_shared_region_slide_info_entry {
    uint32_t version;
    struct vm_shared_region_slide_info_entry_v2 v2;
    struct vm_shared_region_slide_info_entry_v3 v3;
    struct vm_shared_region_slide_info_entry_v4 v4;
};
"""

DYLD_CACHE_SLIDE_PAGE_ATTRS      =       0xC000  
DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA   =     0x8000  
DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE =   0x4000 
DYLD_CACHE_SLIDE_PAGE_ATTR_END     =     0x8000  
DYLD_CACHE_SLIDE_PAGE_VALUE      =       0x3FFF 
DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT   =   2
PAGE_SIZE_FOR_SR_SLIDE  = 4096
DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE  = 0xFFFF  
DYLD_CACHE_SLIDE4_PAGE_NO_REBASE       =    0xFFFF
DYLD_CACHE_SLIDE4_PAGE_INDEX       =        0x7FFF  
DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA     =      0x8000  
DYLD_CACHE_SLIDE4_PAGE_EXTRA_END      =     0x8000  

def zll (val):
    cnt=0
    while val&1 ==0:
        val=(val>>1)
        cnt+=1
    return cnt
class SharedRegionSlideEntry:
    def __init__(self, ql,maxsize):
        self.ql = ql
        self.maxsize=maxsize
        self.version=0
        #variable size..
    def read_v2(self,addr):
        offset=4
        content=self.ql.mem.read(addr+offset, 36)
        self.page_size=unpack("<I",content[:4])[0]
        self.page_starts_offset=unpack("<I",content[4:8])[0]
        self.page_starts_count=unpack("<I",content[8:12])[0]
        self.page_extras_offset=unpack("<I",content[12:16])[0]
        self.page_extras_count=unpack("<I",content[16:20])[0]
        self.delta_mask=unpack("<Q",content[20:28])[0] #which (contiguous) set of bits contains the delta to the next rebase location
        self.value_add=unpack("<Q",content[28:36])[0] 
        self.page_starts=unpack("<"+"H"* self.page_starts_count,self.ql.mem.read(addr+ self.page_starts_offset, self.page_starts_count*2))
        self.page_extras=unpack("<"+"H"* self.page_extras_count,self.ql.mem.read(addr+ self.page_extras_offset, self.page_extras_count*2))
        self.size=self.page_extras_offset+self.page_extras_count*2
        self.ql.log.debug("[SharedRegionSlideEntry]: page size: 0x{:x}, page_starts_offset: 0x{:x} page_starts_count: {} page_extras_offset: 0x{:x} page_extras_count:{} deltamask: {:b} valueadd: 0x{:x} page starts: {} page extras: {} size:0x{:x}"
                         .format(self.page_size,self.page_starts_offset,self.page_starts_count,self.page_extras_offset, self.page_extras_count,
                         self.delta_mask,self.value_add, self.page_starts,self.page_extras ,self.size ))

    def read_v3(self,addr):
        offset=4
        content=self.ql.mem.read(addr+offset, 16)
        self.page_size=unpack("<I",content[:4])[0]
        self.page_starts_count=unpack("<I",content[4:8])[0]
        self.value_add=unpack("<Q",content[8:16])[0] 
        if self.page_starts_count>0:
          self.page_starts=unpack("<"+"H"* self.page_starts_count,self.ql.mem.read(addr+ offset+16, self.page_starts_count*2))
        else:
          self.page_starts=[]
        self.size=offset+16+self.page_starts_count*2
        self.ql.log.debug("[SharedRegionSlideEntry]: page size: 0x{:x},  page_starts_count: {} valueadd: 0x{:x} page starts: {} "
                         .format(self.page_size,self.page_starts_count,
                       self.value_add, self.page_starts  ))

    def read_v4(self,addr):
        offset=4
        content=self.ql.mem.read(addr+offset, 36)
        self.page_size=unpack("<I",content[:4])[0]
        self.page_starts_offset=unpack("<I",content[4:8])[0]
        self.page_starts_count=unpack("<I",content[8:12])[0]
        self.page_extras_offset=unpack("<I",content[12:16])[0]
        self.page_extras_count=unpack("<I",content[16:20])[0]
        self.delta_mask=unpack("<Q",content[20:28])[0] #which (contiguous) set of bits contains the delta to the next rebase location
        self.value_add=unpack("<Q",content[28:36])[0] 
        self.page_starts=unpack("<"+"H"* self.page_starts_count,self.ql.mem.read(addr+ self.page_starts_offset, self.page_starts_count*2))
        self.page_extras=unpack("<"+"H"* self.page_extras_count,self.ql.mem.read(addr+ self.page_extras_offset, self.page_extras_count*2))
        self.size=self.page_extras_offset+self.page_extras_count*2
        self.ql.log.debug("[SharedRegionSlideEntry]4: page size: 0x{:x}, page_starts_offset: 0x{:x} page_starts_count: {} page_extras_offset: 0x{:x} page_extras_count:{} deltamask: {:b} valueadd: 0x{:x} page starts: {} page extras: {}"
                         .format(self.page_size,self.page_starts_offset,self.page_starts_count,self.page_extras_offset, self.page_extras_count,
                         self.delta_mask,self.value_add, self.page_starts,self.page_extras  ))

    def read_srs(self,addr):
        vers_data = self.ql.mem.read(addr, 4)
        self.version=unpack("<I",vers_data)[0]
        self.ql.log.debug("[SharedRegionSlideEntry]: version: {}".format(self.version))
        if self.version==2:
            self.read_v2(addr)
        elif self.version==3:
            self.read_v3(addr)
        elif self.version==4:
            self.read_v4(addr)
        else:
            self.ql.log.debug("[SharedRegionSlideEntry]: invalid version")
            self.size=4
    def slide(self,addr,pageIndex):
        if self.version==2:
            return self.slide_v2(addr,pageIndex)
        elif self.version==3:
            return self.slide_v3(addr,pageIndex)
        elif self.version==4:
            return self.slide_v4(addr,pageIndex)
        else:
            self.ql.log.debug("[SharedRegionSlideEntry]: invalid version {}".format(self.version))
            return -1
    def slide_v3(self,addr,pageIndex):
        slideam=0
        page_content=addr
        if self.version!=3:
            return -1
        if pageIndex>=self.page_starts_count:
            self.ql.log.info("vm_shared_region_slide_page() did not find page start in slide info: pageIndex={}, count={}".format(pageIndex,self.page_starts_count))
            return -1
        page_entry = self.page_starts[pageIndex]
        if page_entry==DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE:
            return 0
        rebaseLocation=page_content
        delta=page_entry
        while True:
            rebaseLocation += delta
            value=unpack("<Q",self.ql.mem.read(rebaseLocation,8))[0]
            ovalue=value
            delta = ((value & 0x3FF8000000000000) >> 51) * 8
            isBind = ( (value & (1 << 62)) == 1)
            if (isBind) :
                return -1
            isAuthenticated = ((value & (1 << 63)) != 0)
            if isAuthenticated:
                value = (value & 0xFFFFFFFF) 
                value+=self.value_add
            else:
                top8Bits = value & 0x0007F80000000000
                bottom43Bits = value & 0x000007FFFFFFFFFF
                targetValue = (top8Bits << 13) | bottom43Bits
                value = targetValue + 0
            self.ql.mem.write(rebaseLocation, pack("<Q",value))
            self.ql.log.debug("Relocating 0x{:x} to 0x{:x} at 0x{:x}".format(ovalue,value,loc))
            if delta ==0 : break
        return 0
    def slide_v4(self,addr,pageIndex):
        slideam=0
        page_content=addr
        if self.version!=4:
            return -1
        if pageIndex>=self.page_starts_count:
            self.ql.log.info("vm_shared_region_slide_page() did not find page start in slide info: pageIndex={}, count={}".format(pageIndex,self.page_starts_count))
            return -1 
        page_entry = self.page_starts[pageIndex]
        if (page_entry == DYLD_CACHE_SLIDE4_PAGE_NO_REBASE):
            return 0
      
        if (page_entry & DYLD_CACHE_SLIDE4_PAGE_USE_EXTRA) !=0:
            chain_index = page_entry & DYLD_CACHE_SLIDE4_PAGE_INDEX
            while True:
                if (chain_index >= self.page_extras_count):
                    self.ql.log.info("vm_shared_region_slide_page() out-of-bounds extras index: index={}, count={}".format(chain_index, self.page_extras_count))
                    return -1
                info=self.page_extras[chain_index]
                page_start_offset = ((info & DYLD_CACHE_SLIDE4_PAGE_INDEX) << DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT)&0xffff
                kr=self.rebase_chainv4(page_content,page_start_offset,0)
                if kr !=0:
                    return -1
                chain_index+=1
        else:
            page_start_offset = (page_entry << DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT)&0xffff
            kr = self.rebase_chainv4(page_content, page_start_offset, 0)
            if kr!=0:
                return -1
        return 0
    def rebase_chainv4(self,page_content,start_offset,slideam):
        last_page_offset = PAGE_SIZE_FOR_SR_SLIDE - 4
        delta_mask = self.delta_mask&0xffffffff
        value_mask = (~delta_mask)&0xffffffff
        value_add = (self.value_add)&0xffffffff
        delta_shift = zll(delta_mask) - 2 
        page_offset = start_offset
        delta = 1
        while (delta != 0 and page_offset <= last_page_offset) :
            loc = page_content + page_offset
            value=unpack("<I",self.ql.mem.read(loc,4))[0]
            ovalue=value
            delta = (value & delta_mask) >> delta_shift
            value &= value_mask

            if ((value & 0xFFFF8000) == 0) :
                # small positive non-pointer, use as-is
                pass
            elif ((value & 0x3FFF8000) == 0x3FFF8000):
                # small negative non-pointer
                value |= 0xC0000000
            else:
                # pointer that needs rebasing
                value += value_add
                value += slide_amount
            self.ql.mem.write(loc, pack("<I",value))  
            self.ql.log.debug("Relocating 0x{:x} to 0x{:x} at 0x{:x}".format(ovalue,value,loc))
            page_offset += delta
        if page_offset > last_page_offset:
          return -1
        return 0

    def slide_v2(self,vm_addr,pageIndex):
        if (pageIndex>= len(self.page_starts)) :
          self.ql.log.info("Page index too large, {} >= {}".format(pageIndex,len(self.page_starts)))
          return -1
        is_64 = ( (self.delta_mask >> 32) != 0)
        page_entry=self.page_starts[pageIndex]
        if page_entry==DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE:
            return 0
        if (page_entry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA)!=0:
            chain_index = (page_entry & DYLD_CACHE_SLIDE_PAGE_VALUE)&0xffff
            info=0
            while True:
                if chain_index>=self.page_extras_count:
                    self.ql.log.info("vm_shared_region_slide_page() out-of-bounds extras index: index={}, count={}".format(
                            chain_index,self.page_extras_count))
                    return -1
                info=self.page_extras[chain_index]
                page_start_offset = ((info & DYLD_CACHE_SLIDE_PAGE_VALUE) << DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT)&0xffff
                kr=rebase_chain(is_64, pageIndex, vm_addr, page_start_offset, 0, s_info)
                if kr!=0:
                    return -1
                chain_index+=1
                if (info & DYLD_CACHE_SLIDE_PAGE_ATTR_END)!=0: break        
        else:
            page_start_offset = (page_entry << DYLD_CACHE_SLIDE_PAGE_OFFSET_SHIFT)
            kr = self.rebase_chain(is_64, pageIndex, vm_addr, page_start_offset, 0)
            if (kr != 0):
              return -1
        return 0
    def rebase_chain(self,is_64,pageIndex, addr,page_start_offset,slideam):
        if is_64:
            kr=self.slide_chain_64(addr,page_start_offset,slideam)
        else:
            kr=self.slide_chain_32(addr,page_start_offset,slideam)
        if kr!=0:
            self.ql.log.info("m_shared_region_slide_page() offset overflow: pageIndex={}, start_offset={}, slide_amount={}".format(pageIndex,page_start_offset,slideam))
        return kr


    def slide_chain_64(self,addr,page_start_offset,slideam):
        last_page_offset = PAGE_SIZE_FOR_SR_SLIDE - 8
        value_mask = (~self.delta_mask)&0xffffffffffffffff
        delta_shift = zll(self.delta_mask) - 2
        page_offset = page_start_offset
        delta = 1
        while (delta != 0 and page_offset <= last_page_offset) :
            loc = addr + page_offset
            value=unpack("<Q",self.ql.mem.read(loc,8))[0]
            ovalue=value
     
            delta = ((value & self.delta_mask) >> delta_shift)&0xffffffff
            value &= value_mask
            if value !=0:
                value += self.value_add
                value += slideam
                #self.ql.log.debug("Relocating 0x{:x} to 0x{:x} at 0x{:x} Delta:{}".format(ovalue,value,loc,delta))
            self.ql.mem.write(loc, pack("<Q",value))
            page_offset += delta
        if page_offset + 4 == PAGE_SIZE_FOR_SR_SLIDE :
            loc = addr + page_offset
            #uint32_t value;
            value=unpack("<I",self.ql.mem.read(loc,4))[0]
            value += slideam
            self.ql.mem.write(loc, pack("<I",value))
        elif page_offset > last_page_offset:
            self.ql.log.debug("page offset too large: {}".format(page_offset))
            return -1
        return 0
    def slide_chain_32(self,addr,page_start_offset,slideam):
        last_page_offset = PAGE_SIZE_FOR_SR_SLIDE - 4
        delta_mask = self.delta_mask&0xffffffff
        value_mask = (~delta_mask)&0xffffffff
        value_add = self.value_add&0xffffffff
        delta_shift = zll(delta_mask) - 2
        page_offset = page_start_offset
        delta = 1
        while (delta != 0 and page_offset <= last_page_offset):
            loc = addr + page_offset
            value=unpack("<I",self.ql.mem.read(loc,4))[0]
            ovalue=value
            delta = (value & delta_mask) >> delta_shift
            value &= value_mask
            if (value != 0) :
                value += value_add
                value += slideam
            self.ql.mem.write(loc, pack("<I",value))    
            self.ql.log.debug("Relocating 0x{:x} to 0x{:x}".format(ovalue,value))
            page_offset += delta
        if (page_offset > last_page_offset):
            return -1
        return 0
    def relocate(self,addr,area_size):
        cur_offset=0
        retval=0
        self.ql.log.debug("Relocating mapping at 0x{:x} size: {}".format(addr,area_size))
        while retval==0 and cur_offset<area_size:
            chunk_offset=addr+cur_offset
            indeex=cur_offset//PAGE_SIZE_FOR_SR_SLIDE
            if indeex>=self.page_starts_count :
                self.ql.log.debug("Ending relocations at 0x{:x} ({})".format(chunk_offset,indeex)) 
                break
            #self.ql.log.debug("Indeex: {}".format(indeex))
            retval = self.slide(chunk_offset,indeex)
            #self.ql.log.debug("Retval :{}".format(retval))
            cur_offset+=PAGE_SIZE_FOR_SR_SLIDE
        return retval

class SharedFileNp:

    def __init__(self, ql):
        self.size = 12
        self.ql = ql
    
    def read_sf(self, addr):
        #content = self.ql.mem.read(addr, self.size)
        self.sf_fd = unpack("<i", self.ql.mem.read(addr, 4))[0]
        self.sf_mappings_count = unpack("<I", self.ql.mem.read(addr + 4, 4))[0]
        self.sf_slide = unpack("<I", self.ql.mem.read(addr + 8, 4))[0]
        self.ql.log.debug("[SharedFileNp]: fd: {}, sf_mappings_count: {}, sf_slide:0x{:X}".format(
            self.sf_fd, self.sf_mappings_count, self.sf_slide
            ))

# reference to bsd/sys/proc_info.h
class ProcRegionWithPathInfo():

    def __init__(self, ql):
        self.ql = ql
        pass
    
    def set_path(self, path):
        self.vnode_info_path_vip_path = path

    def write_info(self, addr):
        addr += 248
        self.ql.mem.write(addr, self.vnode_info_path_vip_path)


# virtual FS
# Only have some basic func now 
# tobe completed
class FileSystem():

    def __init__(self, ql):
        self.ql = ql
        self.base_path = ql.rootfs

    def get_common_attr(self, path, cmn_flags):
        real_path = self.vm_to_real_path(path)
        if not os.path.exists(real_path):
            return None
        attr = b''
        file_stat = os.stat(real_path)
        filename = ""

        if cmn_flags & ATTR_CMN_NAME != 0:
            filename = path.split("/")[-1]
            filename_len = len(filename) + 1        # add \0
            attr += pack("<L", filename_len)
            self.ql.log.debug("FileName :{}, len:{}".format(filename, filename_len))

        if cmn_flags & ATTR_CMN_DEVID != 0:
            attr += pack("<L", file_stat.st_dev)
            self.ql.log.debug("DevID: {}".format(file_stat.st_dev))

        if cmn_flags & ATTR_CMN_OBJTYPE != 0:
            if os.path.isdir(path):
                attr += pack("<L", VDIR)
                self.ql.log.debug("ObjType: DIR")
            elif os.path.islink(path):
                attr += pack("<L", VLINK)
                self.ql.log.debug("ObjType: LINK")
            else:
                attr += pack("<L", VREG)
                self.ql.log.debug("ObjType: REG")
            
        if cmn_flags & ATTR_CMN_OBJID != 0:
            attr += pack("<Q", file_stat.st_ino)
            self.ql.log.debug("VnodeID :{}".format(file_stat.st_ino))

        # at last, add name 
        if cmn_flags & ATTR_CMN_NAME != 0:
            name_offset = len(attr) + 4
            attr = pack("<L", name_offset) + attr
            attr += filename.encode("utf8")
            attr += b'\x00'
        
        self.ql.log.debug("Attr : {}".format(attr))
    
        return attr

    def vm_to_real_path(self, vm_path):
        if not vm_path:
            return None
        if vm_path[0] == '/':
            # abs path 
            return os.path.join(self.base_path, vm_path[1:])
        else:
            # rel path
            return os.path.join(self.base_path, vm_path)

    def open(self, path, open_flags, open_mode):

        real_path = self.vm_to_real_path(path)
        
        if real_path:
            return os.open(real_path, open_flags, open_mode)
        else:
            return None

    def isexists(self, path):
        real_path = self.vm_to_real_path(path)
        return os.path.exists(real_path)
