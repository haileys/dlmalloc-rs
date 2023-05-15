use core::ptr;
use core::convert::TryFrom;
use core::ffi::c_void;
use Allocator;

mod winapi {
    use core::ffi::{c_void, c_ulong, c_long};

    #[allow(non_camel_case_types)]
    #[allow(non_snake_case)]
    #[repr(C)]
    pub struct CRITICAL_SECTION {
        DebugInfo: *mut c_void,
        LockCount: c_long,
        RecursionCount: c_long,
        OwningThread: c_ulong,
        LockSemaphore: c_ulong,
        SpinCount: c_ulong,
    }

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

        pub fn InitializeCriticalSection(ptr: *mut CRITICAL_SECTION);
        pub fn EnterCriticalSection(ptr: *mut CRITICAL_SECTION);
        pub fn LeaveCriticalSection(ptr: *mut CRITICAL_SECTION);

        pub fn Sleep(dwMilliseconds: c_ulong);
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

// #[cfg(feature = "global")]
// static mut LOCK: libc::pthread_mutex_t = libc::PTHREAD_MUTEX_INITIALIZER;

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

mod critical_section {
    use core::mem::MaybeUninit;
    use core::sync::atomic::{AtomicU32, Ordering};
    use super::winapi;

    static mut LOCK: MaybeUninit<winapi::CRITICAL_SECTION> = MaybeUninit::uninit();

    // win9x never supported SMP, but ideally this works
    // on newer versions of windows too
    static LOCK_INIT: AtomicU32 = AtomicU32::new(0);

    pub fn get() -> *mut winapi::CRITICAL_SECTION {
        while LOCK_INIT.load(Ordering::SeqCst) != 2 {
            let init_val = LOCK_INIT.compare_exchange(
                0,
                1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );

            match init_val {
                Ok(_) => {
                    // we got it!
                    unsafe {
                        winapi::InitializeCriticalSection(LOCK.as_mut_ptr());
                    }

                    LOCK_INIT.store(2, Ordering::SeqCst);
                }
                Err(_) => {
                    // another thread got it.
                    // sleeping for 1 millisecond is the closest thing to a
                    // yield we have on this platform
                    unsafe { winapi::Sleep(1); }
                }
            }
        }

        unsafe { LOCK.as_mut_ptr() }
    }
}

#[cfg(feature = "global")]
pub fn acquire_global_lock() {
    let crit = critical_section::get();
    unsafe { winapi::EnterCriticalSection(crit); }
}

#[cfg(feature = "global")]
pub fn release_global_lock() {
    let crit = critical_section::get();
    unsafe { winapi::LeaveCriticalSection(crit); }
}

#[cfg(feature = "global")]
pub unsafe fn enable_alloc_after_fork() {
    unimplemented!("no fork on win9x");
}
