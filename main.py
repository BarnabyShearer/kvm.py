#! /usr/bin/env python3

import sys
import ctypes
import ctypes.util
import struct
import mmap
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

KVM_NR_INTERRUPTS = 256

class kvm_userspace_memory_region(ctypes.Structure):
    _fields_ = [
        ("slot", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("guest_phys_addr", ctypes.c_uint64),
        ("memory_size", ctypes.c_uint64),
        ("userspace_addr", ctypes.c_uint64)
    ]

class kvm_segment(ctypes.Structure):
    _fields_ = [
        ("base", ctypes.c_uint64),
        ("limit", ctypes.c_uint32),
        ("selector", ctypes.c_uint16),
        ("type", ctypes.c_uint8),
        ("present", ctypes.c_uint8),
        ("dpl", ctypes.c_uint8),
        ("db", ctypes.c_uint8),
        ("s", ctypes.c_uint8),
        ("l", ctypes.c_uint8),
        ("g", ctypes.c_uint8),
        ("avl", ctypes.c_uint8),
        ("unusable", ctypes.c_uint8),
        ("padding", ctypes.c_uint8)
    ]

class kvm_dtable(ctypes.Structure):
    _fields_ = [
        ("base", ctypes.c_uint64),
        ("limit", ctypes.c_uint16),
        ("padding", ctypes.c_uint16 * 3)
    ]

class kvm_sregs(ctypes.Structure):
    _fields_ = [
        ("cs", kvm_segment),
        ("ds", kvm_segment),
        ("es", kvm_segment),
        ("fs", kvm_segment),
        ("gs", kvm_segment),
        ("ss", kvm_segment),
        ("tr", kvm_segment),
        ("ldt", kvm_segment),
        ("gdt", kvm_dtable),
        ("idt", kvm_dtable),
        ("cr0", ctypes.c_uint64),
        ("cr2", ctypes.c_uint64),
        ("cr3", ctypes.c_uint64),
        ("cr4", ctypes.c_uint64),
        ("cr8", ctypes.c_uint64),
        ("efer", ctypes.c_uint64),
        ("apic_base", ctypes.c_uint64),
        ("interrupt_bitmap", ctypes.c_uint64 * int((KVM_NR_INTERRUPTS + 63) / 64))
    ]

class kvm_regs(ctypes.Structure):
    _fields_ = [
        ("rax", ctypes.c_uint64),
        ("rbx", ctypes.c_uint64),
        ("rcx", ctypes.c_uint64),
        ("rdx", ctypes.c_uint64),
        ("rsi", ctypes.c_uint64),
        ("rdi", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("rbp", ctypes.c_uint64),
        ("r8", ctypes.c_uint64),
        ("r9", ctypes.c_uint64),
        ("r10", ctypes.c_uint64),
        ("r11", ctypes.c_uint64),
        ("r12", ctypes.c_uint64),
        ("r13", ctypes.c_uint64),
        ("r14", ctypes.c_uint64),
        ("r15", ctypes.c_uint64),
        ("rip", ctypes.c_uint64),
        ("rflags", ctypes.c_uint64)
    ]

class kvm_run_io(ctypes.Structure):
    _fields_ = [
        ("direction", ctypes.c_uint8),
        ("size", ctypes.c_uint8),
        ("port", ctypes.c_uint16),
        ("count", ctypes.c_uint32),
        ("data_offset", ctypes.c_uint64)
    ]

class kvm_run_union(ctypes.Union):
    _fields_ = [
        ("io", kvm_run_io)
    ]

class kvm_run(ctypes.Structure):
    _fields_ = [
        ("request_interrupt_window", ctypes.c_uint8),
        ("padding1", ctypes.c_uint8 * 7),
        ("exit_reason", ctypes.c_uint32),
        ("ready_for_interrupt_injection", ctypes.c_uint8),
        ("if_flag", ctypes.c_uint8),
        ("flags", ctypes.c_uint16),
        ("cr8", ctypes.c_uint64),
        ("apic_base", ctypes.c_uint64),
        ("u", kvm_run_union)
    ]

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + 8
_IOC_SIZESHIFT = _IOC_TYPESHIFT + 8
_IOC_DIRSHIFT = _IOC_SIZESHIFT + 14

def _IOC(dir, type, nr, size):
    return (dir << _IOC_DIRSHIFT) | (type << _IOC_TYPESHIFT) | (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT)

def _IO(type, nr):
    return _IOC(0, type, nr, 0)

def _IOW(type, nr, size):
    return _IOC(1, type, nr, ctypes.sizeof(size))

def _IOR(type, nr, size):
    return _IOC(2, type, nr, ctypes.sizeof(size))

KVMIO = 0xAE
KVM_API_VERSION = 12
KVM_GET_API_VERSION = _IO(KVMIO, 0x00)
KVM_CREATE_VM = _IO(KVMIO, 0x01)
KVM_GET_VCPU_MMAP_SIZE = _IO(KVMIO, 0x04)
KVM_CREATE_VCPU = _IO(KVMIO, 0x41)
KVM_SET_USER_MEMORY_REGION = _IOW(KVMIO, 0x46, kvm_userspace_memory_region)
KVM_SET_TSS_ADDR = _IO(KVMIO, 0x47)

KVM_RUN = _IO(KVMIO, 0x80)
KVM_GET_REGS = _IOR(KVMIO, 0x81, kvm_regs)
KVM_SET_REGS = _IOW(KVMIO, 0x82, kvm_regs)
KVM_GET_SREGS = _IOR(KVMIO, 0x83, kvm_sregs)
KVM_SET_SREGS = _IOW(KVMIO, 0x84, kvm_sregs)

KVM_EXIT_IO = 2
KVM_EXIT_HLT = 5

PDE64_PRESENT = 1
PDE64_RW = 1 << 1
PDE64_USER = 1 << 2
PDE64_PS = 1 << 7

X86_CR4_PAE = 1 << 5
X86_CR0_PE = 1 << 0
X86_CR0_MP = 1 << 1
X86_CR0_ET = 1 << 4
X86_CR0_NE = 1 << 5
X86_CR0_WP = 1 << 16
X86_CR0_AM = 1 << 18
X86_CR0_PG = 1 << 31

EFER_LME = 1 << 8

def main(payload):
    with open("/dev/kvm", "r+b") as sys_file:
        sys_fd = sys_file.fileno()
        assert libc.ioctl(sys_fd, KVM_GET_API_VERSION, 0) == KVM_API_VERSION
        vm_fd = libc.ioctl(sys_fd, KVM_CREATE_VM, 0)
        assert vm_fd >= 0
        assert libc.ioctl(vm_fd, KVM_SET_TSS_ADDR, ctypes.c_ulong(0xfffbd000)) >= 0
        mem = mmap.mmap(
            -1,
            0x100000,
            prot=mmap.PROT_READ | mmap.PROT_WRITE,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
        )
        memreg = kvm_userspace_memory_region()
        memreg.slot = 0
        memreg.flags = 0
        memreg.guest_phys_addr = 0
        memreg.memory_size = 0x100000
        memreg.userspace_addr = ctypes.cast(ctypes.pointer(ctypes.c_int.from_buffer(mem)), ctypes.c_void_p).value
        assert libc.ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, ctypes.byref(memreg)) >= 0
        vcpu_fd = libc.ioctl(vm_fd, KVM_CREATE_VCPU, 0)
        assert vcpu_fd >= 0
        vcpu_mmap_size = libc.ioctl(sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0)
        assert vcpu_mmap_size >= 0
        run_buf = mmap.mmap(vcpu_fd, vcpu_mmap_size, prot=mmap.PROT_READ | mmap.PROT_WRITE, flags=mmap.MAP_SHARED)
        run = kvm_run.from_buffer(run_buf)

        sregs = kvm_sregs()
        regs = kvm_regs()
        assert libc.ioctl(vcpu_fd, KVM_GET_SREGS, ctypes.byref(sregs)) >= 0

        sregs.gdt.base = 0x1000
        sregs.gdt.limit = 3 * 8 - 1

        pml4 = ctypes.cast(memreg.userspace_addr + 0x2000, ctypes.POINTER(ctypes.c_uint64))
        pdpt = ctypes.cast(memreg.userspace_addr + 0x3000, ctypes.POINTER(ctypes.c_uint64))
        pd = ctypes.cast(memreg.userspace_addr + 0x4000, ctypes.POINTER(ctypes.c_uint64))

        pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | 0x3000
        pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | 0x4000
        pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS

        sregs.cr3 = 0x2000
        sregs.cr4 = X86_CR4_PAE
        sregs.cr0 = X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | X86_CR0_PG
        sregs.efer = EFER_LME

        sregs.cs.base = 0
        sregs.cs.limit = 0xffffffff
        sregs.cs.selector = 3 << 3
        sregs.cs.present = 1
        sregs.cs.type = 11 # Code: execute, read, accessed
        sregs.cs.dpl = 0
        sregs.cs.db = 0
        sregs.cs.s = 1 # Code/data
        sregs.cs.l = 1
        sregs.cs.g = 1 # 4KB granularity

        gdt = ctypes.cast(memreg.userspace_addr + sregs.gdt.base, ctypes.POINTER(ctypes.c_uint64))

        sregs.gdt.limit = 4 * 8 - 1

        limit = (sregs.cs.limit >> 12) if sregs.cs.g else sregs.cs.limit
        gdt[sregs.cs.selector >> 3] = ctypes.c_uint64(
            (limit & 0xffff) \
            | (sregs.cs.base & 0xffffff) << 16 \
            | sregs.cs.type << 40 \
            | sregs.cs.s << 44 \
            | sregs.cs.dpl << 45 \
            | sregs.cs.present << 47 \
            | ((limit & 0xf0000) << 48) & 0xFFFFFFFF \
            | sregs.cs.avl << 52 \
            | sregs.cs.l << 53 \
            | sregs.cs.db << 54 \
            | sregs.cs.g << 55 \
            | (sregs.cs.base & 0xff000000) << 56
        )

        assert libc.ioctl(vcpu_fd, KVM_SET_SREGS, ctypes.byref(sregs)) >= 0

        regs.rflags = 2
        regs.rip = 0x10000
        regs.rsp = memreg.memory_size

        assert libc.ioctl(vcpu_fd, KVM_SET_REGS, ctypes.byref(regs)) >= 0

        mem.seek(regs.rip)
        with open(payload, 'rb') as f:
            for b in f.read():
                mem.write_byte(b)

        while True:
            assert libc.ioctl(vcpu_fd, KVM_RUN, 0) >= 0

            if run.exit_reason == KVM_EXIT_HLT:
                assert libc.ioctl(vcpu_fd, KVM_GET_REGS, ctypes.byref(regs)) >= 0
                exit(ctypes.c_int(regs.rdi).value)
            elif run.exit_reason == KVM_EXIT_IO:
                print(chr(run_buf[run.u.io.data_offset]), end='')
            else:
                raise Exception("Unkown exit reasone %d", run.exit_reason)

if __name__ == "__main__":
    main(sys.argv[1])
