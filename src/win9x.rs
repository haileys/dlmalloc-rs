use core::ptr;
use core::convert::TryFrom;
use core::ffi::c_void;
use crate::Allocator;

use win9x_sync::critical_section::CriticalSection;

mod winapi {
    use core::ffi::{c_void, c_ulong, c_long};

    pub const MEM_COMMIT: c_ulong = 0x00001000;
    pub const MEM_RESERVE: c_ulong = 0x00002000;
    pub const MEM_DECOMMIT: c_ulong = 0x00004000;
    pub const MEM_RELEASE: c_ulong = 0x00008000;
    pub const PAGE_READWRITE: c_ulong = 0x04;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn VirtualAlloc(
            lpAddress: *mut c_void,
            dwSize: c_ulong,
            flAllocationType: c_ulong,
            flProtect: c_ulong,
        ) -> *mut c_void;

        pub fn VirtualFree(
            lpAddress: *mut c_void,
            dwSize: c_ulong,
            dwFreeType: c_ulong,
        ) -> bool;
    }
}

/// System setting for Win9x
pub struct System {
    _priv: (),
}

impl System {
    pub const fn new() -> System {
        System { _priv: () }
    }
}

unsafe impl Allocator for System {
    fn alloc(&self, size: usize) -> (*mut u8, usize, u32) {
        let addr = unsafe {
            winapi::VirtualAlloc(
                0 as *mut _,
                u32::try_from(size).expect("size: usize -> u32"),
                winapi::MEM_COMMIT | winapi::MEM_RESERVE,
                winapi::PAGE_READWRITE,
            )
        };

        if addr == ptr::null_mut() {
            (ptr::null_mut(), 0, 0)
        } else {
            (addr as *mut u8, size, 0)
        }
    }

    fn remap(&self, _ptr: *mut u8, _oldsize: usize, _newsize: usize, _can_move: bool) -> *mut u8 {
        ptr::null_mut()
    }

    fn free_part(&self, ptr: *mut u8, oldsize: usize, newsize: usize) -> bool {
        assert!(newsize <= oldsize);

        let free_base = unsafe { ptr.add(newsize) };
        let free_size = u32::try_from(oldsize - newsize)
            .expect("size: usize -> u32");

        unsafe {
            winapi::VirtualFree(
                free_base as *mut c_void,
                free_size,
                // best we can do here is decommit this memory,
                // virtual address ranges reserved by VirtualAlloc
                // may only be freed in their entirety.
                winapi::MEM_DECOMMIT,
            )
        }
    }

    fn free(&self, ptr: *mut u8, _size: usize) -> bool {
        unsafe {
            winapi::VirtualFree(
                ptr as *mut c_void,
                0,
                // MEM_RELEASE requires that size == 0 and that ptr is
                // as originally allocated
                winapi::MEM_RELEASE,
            )
        }
    }

    fn can_release_part(&self, _flags: u32) -> bool {
        true
    }

    fn allocates_zeros(&self) -> bool {
        true
    }

    fn page_size(&self) -> usize {
        4096
    }
}

static LOCK: CriticalSection = CriticalSection::new();

#[cfg(feature = "global")]
pub fn acquire_global_lock() {
    unsafe { LOCK.enter(); }
}

#[cfg(feature = "global")]
pub fn release_global_lock() {
    unsafe { LOCK.leave(); }
}

#[cfg(feature = "global")]
pub unsafe fn enable_alloc_after_fork() {
    unimplemented!("no fork on win9x");
}
