#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import struct
from unicorn import UcError
from qiling.exception import *
from qiling.const import *
from qiling.arch.x86_const import *
from qiling.os.posix.const_mapping import *
from qiling.os.filestruct import *
from qiling.os.freebsd.const import *

from .const import *
from .thread import *
from .mach_port import *
from .kernel_func import *
from .utils import *

# TODO: We need to finish these syscall
# there are three kinds of syscall, we often use posix syscall, mach syscall is used by handle mach msg
# Unfortunately we dont have enough doc about mach syscallios 
# We can find all of these syscalls in kernel source code, some pthread func may found in libpthread

################
# ios syscall #
################
__global_shared_region=None
def ql_syscall_fgetattrlist(ql, fd, alist, attributeBuffer, bufferSize, options, *args, **kw):
    ql.log.debug("fgetattrlist(fd: 0x%x, alist: 0x%x, attributeBuffer: 0x%x, bufferSize: 0x%x, options: 0x%x)" % (
        fd, alist, attributeBuffer, bufferSize, options
    ))

    attrlist = {}
    attrlist["bitmapcount"] = unpack("<H", ql.mem.read(alist, 2))[0]
    attrlist["reserved"] = unpack("<H", ql.mem.read(alist + 2, 2))[0]
    attrlist["commonattr"] = unpack("<L", ql.mem.read(alist + 4, 4))[0]
    attrlist["volattr"] = unpack("<L", ql.mem.read(alist + 8, 4))[0]
    attrlist["dirattr"] = unpack("<L", ql.mem.read(alist + 12, 4))[0]
    attrlist["fileattr"] = unpack("<L", ql.mem.read(alist + 16, 4))[0]
    attrlist["forkattr"] = unpack("<L", ql.mem.read(alist + 20, 4))[0]

    ql.log.debug("bitmapcount: 0x%x, reserved: 0x%x, commonattr: 0x%x, volattr: 0x%x, dirattr: 0x%x, fileattr: 0x%x, forkattr: 0x%x\n" % (
        attrlist["bitmapcount"], attrlist["reserved"], attrlist["commonattr"], attrlist["volattr"], attrlist["dirattr"], attrlist["fileattr"], attrlist["forkattr"]
    ))

    # path_str = macho_read_string(ql, path, MAX_PATH_SIZE)

    attr = b''
    if attrlist["commonattr"] != 0:
        commonattr = ql.os.macho_fs.get_common_attr(ql.path, attrlist["commonattr"])
        if not commonattr:
            raise QlErrorSyscallError("Error File Not Exist")
        attr += commonattr
    
    attr_len = len(attr) + 4
    attr = struct.pack("<L", attr_len) + attr

    if len(attr) > bufferSize:
        ql.log.debug("Length error")
        return 1
    else:

        ql.mem.write(attributeBuffer, attr)
        #set_eflags_cf(ql, 0x0)
        return KERN_SUCCESS


def ql_syscall_poll(ql, target, address, size, *args, **kw):
    return KERN_SUCCESS


################
# mach syscall #
################

# 0xa
def ql_syscall_kernelrpc_mach_vm_allocate_trap(ql, port, addr, size, flags, *args, **kw):
    ql.log.debug("[mach] mach vm allocate trap(port: 0x%x, addr: 0x%x, size: 0x%x, flags: 0x%x" % (port, addr, size, flags))
    mmap_address = ql.os.macho_task.min_offset
    mmap_end = page_align_end(mmap_address + size, PAGE_SIZE)
    ql.mem.map(mmap_address, mmap_end - mmap_address)
    ql.mem.write(mmap_address, b'\x00'*(mmap_end - mmap_address))
    ql.os.macho_task.min_offset = mmap_end
    ql.log.debug("vm alloc from 0x%x to 0x%0x" % (mmap_address, mmap_end))
    ql.mem.write(addr, struct.pack("<Q", mmap_address))
    return 0

# 0xc
def ql_syscall_kernelrpc_mach_vm_deallocate_trap(ql, target, address, size, *args, **kw):
    ql.log.debug("[mach] mach vm deallocate trap")
    return KERN_SUCCESS

# 0xf
def ql_syscall_kernelrpc_mach_vm_map_trap(ql, target, address, size, mask, flags, cur_protection):
    ql.log.debug("[mach] mach vm map trap(target: 0x%x, address: 0x%x, size: 0x%x, mask: 0x%x, flag: 0x%x, cur_protect: 0x%x)" % (
        target, address, size, mask, flags, cur_protection
    ))

    if ql.os.macho_vmmap_end & mask > 0:
        ql.os.macho_vmmap_end = ql.os.macho_vmmap_end - (ql.os.macho_vmmap_end & mask)
        ql.os.macho_vmmap_end += mask + 1

    
    vmmap_address = page_align_end(ql.os.macho_vmmap_end, PAGE_SIZE)
    vmmap_end = page_align_end(vmmap_address + size, PAGE_SIZE)

    ql.os.macho_vmmap_end = vmmap_end
    ql.mem.map(vmmap_address, vmmap_end - vmmap_address)
    ql.mem.write(address, struct.pack("<Q", vmmap_address))
    return KERN_SUCCESS

# 0x12
def ql_syscall_kernelrpc_mach_port_deallocate_trap(ql, *args, **kw):
    ql.log.debug("[mach] mach port deallocate trap")

# 0x13
def ql_syscall_kernelrpc_mach_port_mod_refs_trap(ql, target, name, right, delta, *args, **kw):
    ql.log.debug("[mach] mach port mod refs trap(target: 0x%x, name: 0x%x, right: 0x%x, delta: 0x%x)" % (
        target, name, right, delta
    ))
    return 0
    pass

# 0x18
def ql_syscall_kernelrpc_mach_port_construct_trap(ql, target, options, context, name, *args, **kw):
    ql.log.debug("[mach] mach port construct trap(target: 0x%x, options: 0x%x, context: 0x%x, name: 0x%x)" % (
        target, options, context, name
    ))
    pass

# 0x1a
def ql_syscall_mach_reply_port(ql, *args, **kw):
    ql.log.debug("[mach] mach reply port , ret: %s" % (ql.os.macho_mach_port.name))
    return ql.os.macho_mach_port.name

# 0x1b
def ql_syscall_thread_self_trap(ql, *args, **kw):
    port_manager = ql.os.macho_port_manager
    thread_port = port_manager.get_thread_port(ql.os.macho_thread)
    ql.log.debug("[mach] thread_self_trap: ret: %s" % (thread_port))
    return thread_port

# 0x1c
def ql_syscall_task_self_trap(ql, *args, **kw):
    ql.log.debug("[mach] task self trap, ret: %d" % (ql.os.macho_task.id))
    return ql.os.macho_task.id

def ql_syscall_mach_timebase_info_trap(ql, ptr,*args, **kw):
    ql.log.debug("[mach] mach_timebase info trap, ptr: %X ret: %d" % (ptr,1))
    ql.mem.write(ptr,struct.pack("<L",1))
    ql.mem.write(ptr+4,struct.pack("<L",1))
    return 0

# 0x1d
def ql_syscall_host_self_trap(ql, *args, **kw):
    port_manager = ql.os.macho_port_manager
    ql.log.debug("[mach] host_self_trap, ret: %s" % (ql.os.macho_port_manager.host_port.name))
    return port_manager.host_port.name

# 0x1f
def ql_syscall_mach_msg_trap(ql, args, opt, ssize, rsize, rname, timeout):
    ql.log.debug("[mach] mach_msg_trap(args: 0x%x opt: 0x%x, ssize: 0x%x, rsize: 0x%x, rname: 0x%x, timeout: %d)" % (
        args, opt, ssize, rsize, rname, timeout))
    mach_msg = MachMsg(ql)
    mach_msg.read_msg_from_mem(args, ssize)
    ql.log.debug("Recv-> Header: %s, ID: %d Content: %s" % (mach_msg.header,mach_msg.header.msgh_id, mach_msg.content))
    ql.os.macho_port_manager.deal_with_msg(mach_msg, args)
    return 0

#170	AUE_CSOPS	ALL	{ int csops_audittoken(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize, user_addr_t uaudittoken); }
def ql_syscall_csops_audittoken(ql, pid,ops,useraddr,usersize,audittoken):
    dat=ql.mem.read(audittoken,32)
    ql.log.debug("csops_audittoken: pid: 0x{:x} ops: {} useraddr: 0x{:x} usersize: {} audittoken: 0x{:x} data: {}".format(pid,ops,useraddr,usersize,audittoken,dat))
    #ql.mem.write(useraddr,bytes(dat))
    flag = struct.pack("<L", (CS_ENFORCEMENT | CS_GET_TASK_ALLOW))
    ql.mem.write(useraddr, flag)
    return 0
#################
# POSIX syscall #
#################

# 0x21
def ql_syscall_access_macos(ql, path, flags, *args, **kw):
    path_str = ql.os.utils.read_cstring(path)
    ql.log.debug("access(path: %s, flags: 0x%x)" % (path_str, flags))
    if not ql.os.macho_fs.isexists(path_str):
        return ENOENT
    else:
        return KERN_SUCCESS

# 0x30 
def ql_syscall_sigprocmask(ql, how, mask, omask, *args, **kw):
    ql.log.debug("sigprocmask(how: 0x%x, mask: 0x%x, omask: 0x%x)" % (how, mask, omask))
    return 0
# 0x5c
from qiling.os.posix.syscall.fcntl import ql_syscall_fcntl as fcntls
def ql_syscall_fcntl64_macos(ql, fcntl_fd, fcntl_cmd, fcntl_arg, *args, **kw):
    regreturn = 0
    ret=fcntls(ql, fcntl_fd, fcntl_cmd, fcntl_arg)
    if ret==0:
        ql.log.debug("fcntl64_mac(fd: %d, cmd: %d, arg: 0x%x) = %d" % (fcntl_fd, fcntl_cmd, fcntl_arg, regreturn))
        return 0
    if fcntl_cmd == F_GETFL:
        regreturn = 2
    elif fcntl_cmd == F_SETFL:
        regreturn = 0
    elif fcntl_cmd == F_GETFD:
        regreturn = 2
    elif fcntl_cmd == F_SETFD:
        regreturn = 0
    elif fcntl_cmd == F_ADDFILESIGS_RETURN:
        ql.mem.write(fcntl_arg, ql.pack32(0xefffffff))
        regreturn = 0
    elif fcntl_cmd == F_GETPATH:
        regreturn = 0
    else:
        regreturn = 0
        raise Exception("unknown fcntl {}".format(fcntl_cmd))

    ql.log.debug("fcntl64_mac(fd: %d, cmd: %d, arg: 0x%x) = %d" % (fcntl_fd, fcntl_cmd, fcntl_arg, regreturn))
    return regreturn

# 0x99
def ql_syscall_pread(ql, fd, buf, nbyte, offset, *args, **kw):
    ql.log.debug("pread(fd: 0x%x, buf: 0x%x, nbyte: 0x%x, offset: 0x%x)" % (
        fd, buf, nbyte, offset
    ))

    if fd in range(MAX_FD_SIZE + 1):
        ql.os.fd[fd].seek(offset)
        data = ql.os.fd[fd].read(nbyte)
        ql.mem.write(buf, data)

    set_eflags_cf(ql, 0x0)
    return nbyte

# 0xa9
def ql_syscall_csops(ql, pid, ops, useraddr, usersize, *args, **kw):
    flag = struct.pack("<L", (CS_ENFORCEMENT | CS_GET_TASK_ALLOW))
    ql.mem.write(useraddr, flag)
    ql.log.debug("csops(pid: %d, ops: 0x%x, useraddr: 0x%x, usersize: 0x%x) flag: 0x%x" % (
        pid, ops, useraddr, usersize, ((CS_ENFORCEMENT | CS_GET_TASK_ALLOW))
    ))
    return KERN_SUCCESS

# 0xdc
def ql_syscall_getattrlist(ql, path, alist, attributeBuffer, bufferSize, options, *args, **kw):
    ql.log.debug("getattrlist(path: 0x%x, alist: 0x%x, attributeBuffer: 0x%x, bufferSize: 0x%x, options: 0x%x)" % (
        path, alist, attributeBuffer, bufferSize, options
    ))
    attrlist = {}
    attrlist["bitmapcount"] = unpack("<H", ql.mem.read(alist, 2))[0]
    attrlist["reserved"] = unpack("<H", ql.mem.read(alist + 2, 2))[0]
    attrlist["commonattr"] = unpack("<L", ql.mem.read(alist + 4, 4))[0]
    attrlist["volattr"] = unpack("<L", ql.mem.read(alist + 8, 4))[0]
    attrlist["dirattr"] = unpack("<L", ql.mem.read(alist + 12, 4))[0]
    attrlist["fileattr"] = unpack("<L", ql.mem.read(alist + 16, 4))[0]
    attrlist["forkattr"] = unpack("<L", ql.mem.read(alist + 20, 4))[0]
    path_str = ql.os.utils.read_cstring(path)

    ql.log.debug("bitmapcount: 0x%x, reserved: 0x%x, commonattr: 0x%x, volattr: 0x%x, dirattr: 0x%x, fileattr: 0x%x, forkattr: 0x%x\n" % (
        attrlist["bitmapcount"], attrlist["reserved"], attrlist["commonattr"], attrlist["volattr"], attrlist["dirattr"], attrlist["fileattr"], attrlist["forkattr"]
    ))
    ql.log.debug("path str: %s\n" % (path_str))

    attr = b''
    if attrlist["commonattr"] != 0:
        commonattr = ql.os.macho_fs.get_common_attr(path_str, attrlist["commonattr"])
        if not commonattr:
            ql.log.debug("Error File Not Exist: %s" % (path_str))
            raise QlErrorSyscallError("Error File Not Exist %s" % path_str)
        attr += commonattr
    
    attr_len = len(attr) + 4
    attr = struct.pack("<L", attr_len) + attr

    if len(attr) > bufferSize:
        ql.log.debug("Length error")
        return 1
    else:
        ql.mem.write(attributeBuffer, attr)
        set_eflags_cf(ql, 0x0)
        return KERN_SUCCESS

# 0xc2
# struct rlimit {
#     rlim_t	rlim_cur;		/* current (soft) limit */       uint64
#     rlim_t	rlim_max;		/* maximum value for rlim_cur */ uint64
# };
def ql_syscall_getrlimit(ql, which, rlp, *args, **kw):
    ql.log.debug("getrlimit(which:0x%x, rlp:0x%x)" % (which, rlp))
    _RLIMIT_POSIX_FLAG = 0x1000
    RLIM_NLIMITS = 9
    which = which & _RLIMIT_POSIX_FLAG
    if which >= RLIM_NLIMITS:
        return EINVAL
    else:
        ql.mem.write(rlp, b'\x00\x13\x00\x00\x00\x00\x00\x00')  # rlim_cur
        ql.mem.write(rlp, b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F')  # rlim_max
        pass
    pass
def sysctl_rdquad(ql,oldp, oldlenp, newp, val):
    if oldlenp==0:
        return -1
    ln=struct.unpack("<Q",ql.mem.read(oldlenp,8))[0]
    if ln<8:
        return -1
    if newp!=0:
        return -1
    ql.mem.write(oldlenp,struct.pack("<Q",8))
    ql.mem.write(oldp,struct.pack("<Q",val))
    return 0
def sysctl_rdstr(ql,oldp, oldlenp, newp, strval):
    if oldlenp==0:
        return -1
    ln=struct.unpack("<Q",ql.mem.read(oldlenp,8))[0]
    if ln<len(strval):
        return -1
    #if newp!=0:
    #    return -1
    ql.mem.write(oldlenp,struct.pack("<Q",len(strval)))
    try:
      ql.mem.write(oldp,bytes(strval))
    except TypeError:
      ql.mem.write(oldp,bytes(strval,'utf8'))
    return 0

from qiling.os.macos.structs import *    
def ql_syscall_sysctl_kernel_proc(ql, name, namelen, old, oldlenp, new_arg, newlen):
    if namelen==0: return 0
    nm=struct.unpack("<I",ql.mem.read(name,4))[0]
    if nm==KERN_PROC_PID:
        pid=struct.unpack("<I",ql.mem.read(name+4,4))[0]
        ql.log.debug("Sysctl by PID: 0x{:x}".format(pid))
    #put proc and eproc structsg
    cur_eproc_addr = old+ctypes.sizeof(miniproc_t)
    cur_proc = miniproc_t(ql, old)
    cur_proc.p_pid = 0x512
    cur_proc.p_ppid = 1
    cur_proc.p_pgrpid = 0x512
    cur_proc.p_flag = 0x00000004 # 64 bit proccess
    cur_proc.p_uid = 0
    cur_proc.p_gid = 0
    cur_proc.p_ruid = 0
    cur_proc.p_rgid = 0
    cur_proc.p_svuid = 0
    cur_proc.p_svgid = 0    
    cur_proc.updateToMem()
    ln=struct.unpack("<Q",ql.mem.read(oldlenp,8))[0]
    ql.mem.write(cur_eproc_addr,pack("<Q",old))
    ql.log.debug("Sysctl proc: 0x{:x}  eproc:0x{:x} oldlen:{} szof:{}".format(old,cur_eproc_addr,ln,ctypes.sizeof(proc_t)))
    return 0
def ql_syscall_sysctl_kernel(ql, name, namelen, old, oldlenp, new_arg, newlen):
    if namelen==0: return 0
    nm=struct.unpack("<I",ql.mem.read(name,4))[0]
    if nm==KERN_USRSTACK64:  #LP64 user stack query
      ql.log.debug("LP64 user stack query")
      return sysctl_rdquad(ql,old,oldlenp,new_arg,0xff00ff00ff00)
    elif nm==KERN_OSVERSION:
      ql.log.debug("sysctl.OSVersion")
      return sysctl_rdstr(ql,old,oldlenp,new_arg,'21G217')
    elif nm==KERN_SAFEBOOT:
      ql.log.debug("sysctl. safe boot. Our boot is safe, though MacOsX may not be")
      return sysctl_rdquad(ql,old,oldlenp,new_arg,1)
    elif nm==KERN_PROC:
      return ql_syscall_sysctl_kernel_proc(ql,name+4,namelen-1, old, oldlenp, new_arg, newlen)
    ql.log.debug("sysctl_kernel unknown... {} ".format(nm))
    return 0
def ql_syscall_sysctl_hw(ql, name, namelen, old, oldlenp, new_arg, newlen):
    if namelen==0: return 0
    nm=struct.unpack("<I",ql.mem.read(name,4))[0]
    if nm==HW_PAGESIZE:  #pagesize
      ql.log.debug("pagesizequery")
      return sysctl_rdquad(ql,old,oldlenp,new_arg,PAGE_SIZE)
    ql.log.debug("sysctl_hw unknown... {} ".format(nm)) 
    return 0
# 0xca
def ql_syscall_sysctl(ql, name, namelen, old, oldlenp, new_arg, newlen):
    ql.log.debug("sysctl(name: 0x%x, namelen: 0x%x, old: 0x%x, oldlenp: 0x%x, new: 0x%x, newlen: 0x%x)" % (
        name, namelen, old, oldlenp, new_arg, newlen
    ))
    for r in range(namelen):
        nm=ql.mem.read(name+r*4,4)
        ql.log.debug("Name {} {}".format(r,struct.unpack("<I",nm)[0]))
    if namelen>0:
        nm=struct.unpack("<I",ql.mem.read(name,4))[0]
        if nm==CTL_KERN: #Kernel
            return ql_syscall_sysctl_kernel(ql,name+4,namelen-1, old, oldlenp, new_arg, newlen)
        elif nm==CTL_HW: 
            return ql_syscall_sysctl_hw(ql,name+4,namelen-1, old, oldlenp, new_arg, newlen)
        else:
            ql.log.debug("Unimplemented sysctl") 

    return KERN_SUCCESS

# 0x112
def ql_syscall_sysctlbyname(ql, name, namelen, old, oldlenp, new_arg, newlen):
    ql.log.debug("sysctlbyname(name: 0x%x, namelen: 0x%x, old: 0x%x, oldlenp: 0x%x, new: 0x%x, newlen: 0x%x)" % (
        name, namelen, old, oldlenp, new_arg, newlen
    ))
    return KERN_SUCCESS

# 0x126
# check shared region if avalible , return not ready every time
def ql_syscall_shared_region_check_np(ql, p, uap, retvalp, *args, **kw):
    ql.log.debug("shared_region_check_np(p: 0x%x, uap: 0x%x, retvalp: 0x%x) = 0x%x" % (p, uap, retvalp, EINVAL))
    global __global_shared_region
    print(__global_shared_region)
    if __global_shared_region is None:
      return EINVAL
    else:
      ql.log.debug("Shared region found at 0x{:x}".format(__global_shared_region))
      ql.mem.write(p, struct.pack("<Q",__global_shared_region))
      return KERN_SUCCESS

# 0x150
def ql_syscall_proc_info(ql, callnum, pid, flavor, arg, buff, buffer_size):
    retval = struct.unpack("<Q", ql.mem.read(ql.arch.regs.rsp, 8))[0]
    ql.log.debug("proc_info(callnum: 0x%x, pid: %d, flavor:0x%x, arg: 0x%x, buffer: 0x%x, buffersize: 0x%x, retval: 0x%x)" % (
        callnum, pid, flavor, arg, buff, buffer_size, retval
    ))
    if callnum == PROC_INFO_CALL_PIDINFO:
        if flavor == PROC_PIDREGIONPATHINFO:
            info = ProcRegionWithPathInfo(ql)
            info.set_path(b"/usr/lib/dyld")
            info.write_info(buff)
        elif flavor==PROC_PIDTBSDINFO:
            info=ProcBSDInfo(ql)
            info.write_to_addr(buff)
        elif  flavor==PROC_PIDUNIQIDENTIFIERINFO:  #adds uuid to PROC_PIDTBSDINFO
            info=ProcBSDInfo(ql)
            info.write_to_addr(buff)
        
            #ql.mem.write(buffer_size,struct.pack("<Q",info.sizeof))
        pass
    return 0
def ql_syscall_pthread_sigmask(ql,how,set,oldset):
    return 0

def ql_syscall_pthread_kill(ql,thread,signal):
    return 0

#int cond_sem, int mutex_sem, int timeout, int relative, __int64_t tv_sec, __int32_t tv_nsec
def ql_syscall_semwait_signal_nocancel(ql,semaphore,mutex,timeout,relative,tvsec,tvnsec):
    ql.log.debug("semwait_nocancel: Sema: {} mutex: 0x{:x} tout: {} rel: {} tvsec: {} tvnsec: {}".format(semaphore,mutex,timeout,relative,tvsec,tvnsec))
    return 0
#478	AUE_NULL	ALL	{ int bsdthread_ctl(user_addr_t cmd, user_addr_t arg1, user_addr_t arg2, user_addr_t arg3) NO_SYSCALL_STUB; }
def ql_syscall_bsdthread_ctl(ql,cmd, arg1, arg2, arg3):
    return 0
# 0x16e
def ql_syscall_bsdthread_register(ql, threadstart, wqthread, flags, stack_addr_hint, targetconc_ptr, dispatchqueue_offset):
    set_eflags_cf(ql, 0x0)
    return 0x00000000400000df

# 0x174
def ql_syscall_thread_selfid(ql, *args, **kw):
    thread_id = ql.os.macho_thread.id
    return thread_id

def ql_syscall_sem_getvalue(ql, sem, x ):
    return -78 #unimplemented


def ql_syscall_fstatfs64(ql, fd, buf):
    data = b"0" * (12 * 8)  # for now, just return 0s
    regreturn = 0

    try:
        ql.mem.write(buf, data)
    except:
        regreturn = -1

    if data:
        ql.log.debug("fstatfs() CONTENT:")
        ql.log.debug(str(data))

    return regreturn
#host_create_mach_voucher_trap( mach_port_name_t host, mach_voucher_attr_raw_recipe_array_t (8b,addr) recipes,int recipes_size,mach_port_name_t *voucher);
def ql_syscall_host_create_mach_voucher_trap(ql,host,recipes, recipes_size,voucher):
    ql.mem.write(voucher,pack("<L",12))
    ql.log.debug("Mak voucher: host: 0x{:x} recipes: 0x{:x} {} size: {} cvoucher: 0x{:x}".format(host,recipes,ql.mem.read(recipes,recipes_size*4),recipes_size,voucher))
    return 0
# 0x18d
def ql_syscall_write_nocancel(ql, write_fd, write_buf, write_count, *args, **kw):
    regreturn = 0
    buf = None

    try:
        buf = ql.mem.read(write_buf, write_count)
        if buf:
            ql.log.debug("write() CONTENT:")
            ql.log.debug("%s" % buf)

        if hasattr(ql.os.fd[write_fd], "write"):
            ql.os.fd[write_fd].write(buf)
        else:
            ql.log.debug("write(%d,%x,%i) failed due to write_fd" % (write_fd, write_buf, write_count, regreturn))
        regreturn = write_count

    except:
        regreturn = -1

        if ql.verbose >= QL_VERBOSE.DEBUG:
            raise
    #if buf:
    #    ql.log.info(buf.decode(errors='ignore'))
    return 0

def ql_syscall_read_nocancel(ql, fd,  buf,  nbytes):
    ql.log.debug("ql_syscall_read_nocancel fd: {} buf: 0x{:x} nbytes: {}".format(fd,  buf,  nbytes))
    if not hasattr(ql.os.fd[fd], "read"):
        ql.log.debug("read_nocancel: invalid fd: {}".format(fd))
        return -1
    dat=ql.os.fd[fd].read(nbytes)
    ql.mem.write(buf,dat)
    return len(dat)
def ql_syscall_close_nocancel(ql,fd):
    return ql.os.fd[fd].close()
def ql_syscall_shm_open(ql, filename, flags, mode, *args, **kw):
    path = ql.mem.string(filename)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags = flags & 0xffffffff
    mode = mode & 0xffffffff

    idx = next((i for i in range(MAX_FD_SIZE + 1) if ql.os.fd[i] is None), -1)

    if idx == -1:
        regreturn = -1
    else:
        try:
            if ql.arch.type == QL_ARCH.ARM:
                mode = 0

            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError:
            regreturn = -1

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug("Shared File Found: %s" % relative_path)
    else:
        ql.log.debug("Shared File Not Found %s" % relative_path)
    return regreturn
# 0x18e
def ql_syscall_open_nocancel(ql, filename, flags, mode, *args, **kw):
    path = ql.mem.string(filename)
    relative_path = ql.os.path.transform_to_relative_path(path)

    flags = flags & 0xffffffff
    mode = mode & 0xffffffff

    idx = next((i for i in range(MAX_FD_SIZE + 1) if ql.os.fd[i] is None), -1)

    if idx == -1:
        regreturn = -1
    else:
        try:
            if ql.arch.type == QL_ARCH.ARM:
                mode = 0

            ql.os.fd[idx] = ql.os.fs_mapper.open_ql_file(path, flags, mode)
            regreturn = idx
        except QlSyscallError:
            regreturn = -1

    if regreturn >= 0 and regreturn != 2:
        ql.log.debug("File Found: %s" % relative_path)
    else:
        ql.log.debug("File Not Found %s" % relative_path)
    return regreturn
def ql_syscall_thread_get_special_reply_port(ql):
    port_manager = ql.os.macho_port_manager
    #thread_port = port_manager.get_thread_port(ql.os.macho_thread)
    ql.log.debug("[mach] thread_get_special_reply_port: ret: %s" % (ql.os.macho_mach_port.name))
    return ql.os.macho_mach_port.name

# 0x1b6
def ql_syscall_shared_region_map_and_slide_np(ql, fd, count, mappings_addr, slide, slide_start, slide_size):
    #extern "C" int __shared_region_map_and_slide_np(int fd, uint32_t count, const shared_file_mapping_np mappings[], long slide, const dyld_cache_slide_info2* slideInfo, size_t slideInfoSize);
    ql.log.debug("shared_region_map_and_slide_np(fd: %d, count: 0x%x, mappings: 0x%x, slide: 0x%x, slide_start: 0x%x, slide_size: 0x%x)" % (
                fd, count ,mappings_addr, slide, slide_start, slide_size
            ))
    mapping_list = []
    for i in range(count):
        mapping = SharedFileMappingNp(ql)
        mapping.read_mapping(mappings_addr)
        ql.os.fd[fd].seek(mapping.sfm_file_offset)
        content = ql.os.fd[fd].read(mapping.sfm_size)
        ql.mem.write(mapping.sfm_address, content)
        mappings_addr += mapping.size
        mapping_list.append(mapping)
    return slide_size
"""
struct shared_file_np {
	int                     sf_fd;             /* file to be mapped into shared region */
	uint32_t                sf_mappings_count; /* number of mappings */
	uint32_t                sf_slide;          /* distance in bytes of the slide */
};
"""
def ql_syscall_shared_region_map_and_slide_2_np(ql, count,files_addr,mappings_count, mappings_addr):
    global __global_shared_region
    #extern "C" int __shared_region_map_and_slide_2_np(uint32_t files_count, const shared_file_np files[], uint32_t mappings_count, const shared_file_mapping_slide_np mappings[]);
    ql.log.debug("shared_region_map_and_slide_2_np( count: 0x%x, files: 0x%x, mappings_count: %d,mappings: 0x%x )" % (
                count,files_addr,mappings_count, mappings_addr
            ))
    mapping_list = []
    mp_offset=0
    slide_size=0
    slides=[]
    for f in range(count):
        fnp=SharedFileNp(ql)
        fnp.read_sf(files_addr)
        slide_size=fnp.sf_slide
        for i in range(fnp.sf_mappings_count):
            if mp_offset<mappings_count:
                mapping = SharedFileMappingSlideNp(ql)
                mapping.read_mapping(mappings_addr)  
                ql.os.fd[fnp.sf_fd].seek(mapping.sms_file_offset)  
                content = ql.os.fd[fnp.sf_fd].read(mapping.sms_size)
                try:
                  ql.mem.write(mapping.sms_address, content)
                except UcError as e: 
                  ql.mem.map(mapping.sms_address,mapping.sms_size)
                  ql.mem.write(mapping.sms_address, content)
                  #dyld hack...
                if mapping.sms_slide_size>0:
                    slides.append(mapping)
                #if mapping.sms_address<=0x7ff841a6d4e0 and mapping.sms_address+mapping.sms_size>0x7ff841a6d4e0:
                #    rdf=ql.mem.read(0x7ff841a6d4e0,0x38)
                #    ql.log.debug(bytes(rdf).hex())
                #    rstart=struct.unpack("<Q",ql.mem.read(0x7ff841a6d4e0+0x18,8))[0]
                #    ralign=int(rstart/0x4000)*0x4000
                #    ql.log.debug("trying to map 0x{:x} -> 0x{:x}".format(rstart,ralign))
                    #ql.mem.map(ralign,mapping.sms_size)
                  
                mapping_list.append(mapping)
                mappings_addr += mapping.size
                mp_offset+=1
        files_addr+=fnp.size
    if len(slides)>0:
         ql.log.debug("Relocating mappings")
    for sl in slides:
        #rdf=ql.mem.read(sl[0],sl[1])
        srs=SharedRegionSlideEntry(ql,sl.sms_slide_size)
        srs.read_srs(sl.sms_slide_start)
        srs.relocate(sl.sms_address,sl.sms_size)
        #ql.log.debug(bytes(rdf).hex())
    if len(mapping_list) >0:
        ql.log.debug("Setting global cache: 0x{:x}".format(mapping_list[0].sms_address))
        __global_shared_region=mapping_list[0].sms_address
    return 0#slide_size

def ql_syscall_sigaction(ql, signum, act, oldact):
    ql.log.debug("Sigaction: signum: {}  act: 0x{:x} oldact: 0x{:x}".format(signum,act,oldact))
    return 0

# 0x1e3
def ql_syscall_csrctl(ql, op, useraddr, usersize, *args, **kw):
    ql.log.debug("csrctl(op: 0x%x, useraddr :0x%x, usersize: 0x%x)" % (op, useraddr, usersize))
    return 1

# 0x1f4
cure=0
def ql_syscall_getentropy(ql, buffer, size, *args, **kw):
    global cure
    ql.log.debug("getentropy(buffer: 0x%x, size: 0x%x)" % (buffer, size))
    kk=[]
    for a in range(size):
      kk.append(cure)
      cure=(cure+1)%256
    ql.mem.write(buffer,bytes(kk))
    #ql.mem.write(buffer,b"\xab"*size)
    return KERN_SUCCESS

# 0x208
def ql_syscall_terminate_with_payload(ql, pid, reason_namespace, reason_code, payload, payload_size, reason_string):
    ql.log.debug("terminate_with_payload(pid: %d, reason_namespace: 0x%x, reason_code: 0x%x, payload: 0x%x \
            payload_size: 0x%x, reason_string: 0x%x)" % (pid, reason_namespace, reason_code,
            payload, payload_size, reason_string))
    ql.emu_stop()
    return KERN_SUCCESS

# 0x209
def ql_syscall_abort_with_payload(ql, reason_namespace, reason_code, payload, payload_size, reason_string, reason_flags):
    ql.log.debug("abort_with_payload(reason_namespace: 0x%x, reason_code: 0x%x, payload: 0x%x, payload_size: 0x%x, reason_string: 0x%x,\
            reason_flags: 0x%x)" % (reason_namespace, reason_code, payload, payload_size, reason_string, reason_flags))
    return KERN_SUCCESS



################
# mdep syscall #
################

# 0x3d
# thread_set_tsd_base
def ql_syscall_thread_fast_set_cthread_self64(ql, u_info_addr, *args, **kw):
    ql.log.debug("[mdep] thread fast set cthread self64(tsd_base:0x%x)" % (u_info_addr))
    ql.arch.msr.write(IA32_GS_BASE_MSR, u_info_addr)
    return KERN_SUCCESS

def __get_timespec_struct(archbits):
    long  = getattr(ctypes, f'c_int{archbits}')
    ulong = getattr(ctypes, f'c_uint{archbits}')

    class timespec(ctypes.Structure):
        _pack_ = archbits // 8

        _fields_ = (
            ('tv_sec', ulong),
            ('tv_nsec', long)
        )

    return timespec
from datetime import datetime 
from math import floor
import ctypes

def __get_timespec_obj(ql,archbits):
    now = datetime.now().timestamp()
    
    tv_sec = floor(now)
    tv_nsec = floor((now - floor(now)) * 1e6)
    ql.log.debug("gettimeofday seconds: {} usec: {} ".format(tv_sec,tv_nsec))
    ts_cls = __get_timespec_struct(archbits)

    return ts_cls(tv_sec=tv_sec, tv_nsec=tv_nsec)

def ql_syscall_gettimeofday(ql, tv, tz,machabstime):
    ql.log.debug("gettimeofday tv: 0x{:x}, tz: 0x{:x}, abstime: 0x{:x}".format(tv,tz,machabstime))
    if tv:
        ts_obj = __get_timespec_obj(ql,ql.arch.bits)
        ql.mem.write(tv, bytes(ts_obj))
        ql.mem.write(machabstime,pack("<Q",1))
    if tz:
        ql.mem.write(tz, b'\x00' * 8)

    return 0