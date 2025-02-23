//! This module implements a global allocator. This allocator takes a pre-allocated
//! heap and provides allocator for fixed-sized blocks. This allocator eliminates
//! dependencies onto platform API for memory management at runtime. This is
//! important as calling platform API from the hypervisor is unsound.

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::{NonNull, addr_of, addr_of_mut},
};

use bitvec::{array::BitArray, prelude::*};
use spin::{Mutex, Once};

pub const ALLOCATION_BYTES: usize = 0x80_0000;
pub const ALLOCATION_PAGES: usize = ALLOCATION_BYTES / 0x1000;

/// Initializes the global allocator. `ptr` must be as large as `ALLOCATION_BYTES`
/// and must be 4096 byte-aligned.
pub fn init(ptr: *mut u8) {
    let _ = METADATA.call_once(|| Mutex::new(Metadata::new(ptr)));
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    /// Allocates memory. If the requested size is smaller than 4096 bytes, it
    /// returns 128-byte aligned block(s). If greater than 4096 bytes, it returns
    /// 4096-byte aligned block(s).
    ///
    /// Allocation of memory that is physically continuous for 2 or more pages are
    /// not supported.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut meta = METADATA.get().expect("init() is not called").lock();
        let blocks = unsafe { meta.blocks.as_mut() };

        if layout.size() >= BLOCK_SIZE_4096 {
            alloc_internal(layout, &mut blocks.block4096, &mut meta.bitmap4096)
        } else {
            alloc_internal(layout, &mut blocks.block128, &mut meta.bitmap128)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut meta = METADATA.get().expect("init() is not called").lock();
        let blocks = unsafe { meta.blocks.as_mut() };

        if layout.size() >= BLOCK_SIZE_4096 {
            dealloc_internal(ptr, layout, &blocks.block4096, &mut meta.bitmap4096);
        } else {
            dealloc_internal(ptr, layout, &blocks.block128, &mut meta.bitmap128);
        }
    }
}

fn alloc_internal<const BLOCK_COUNT: usize, const BLOCK_SIZE: usize, const BIT_COUNT: usize>(
    layout: Layout,
    blocks: &mut [Block<BLOCK_SIZE>; BLOCK_COUNT],
    bitmap: &mut BitArray<[u8; BIT_COUNT], Msb0>,
) -> *mut u8 {
    // Find contiguous, unused blocks.
    let required_block_count = round_up_by(layout.size(), BLOCK_SIZE);
    let position = find_empty_blocks(bitmap, required_block_count);
    if position.is_none() {
        return core::ptr::null_mut();
    }

    // Mark them as in-use.
    let start = position.unwrap();
    for index in start..start + required_block_count {
        assert!(!bitmap.get(index).unwrap());
        bitmap.set(index, true);
    }

    // Return a block of memory.
    addr_of_mut!(blocks[start].block).cast::<u8>()
}

fn dealloc_internal<const BLOCK_COUNT: usize, const BLOCK_SIZE: usize, const BIT_COUNT: usize>(
    ptr: *mut u8,
    layout: Layout,
    blocks: &[Block<BLOCK_SIZE>; BLOCK_COUNT],
    bitmap: &mut BitArray<[u8; BIT_COUNT], Msb0>,
) {
    let offset = ptr as usize - addr_of!(*blocks) as usize;
    let start = offset / BLOCK_SIZE;
    let block_count = round_up_by(layout.size(), BLOCK_SIZE);

    // Clear bitmap.
    for index in start..start + block_count {
        assert!(bitmap.get(index).unwrap());
        bitmap.set(index, false);
    }
}

fn round_up_by(number: usize, size: usize) -> usize {
    let round_down = number / size;
    if number % size != 0 {
        round_down + 1
    } else {
        round_down
    }
}

fn find_empty_blocks<const BIT_COUNT: usize>(
    bitmap: &BitArray<[u8; BIT_COUNT], Msb0>,
    count: usize,
) -> Option<usize> {
    let mut empty_block_count = 0;
    let mut start = 0;
    for (index, bit) in bitmap.iter().enumerate() {
        empty_block_count = if *bit {
            0
        } else {
            if empty_block_count == 0 {
                start = index;
            }
            empty_block_count + 1
        };

        if empty_block_count == count {
            return Some(start);
        }
    }
    None
}

const NUMBER_OF_BLOCK_4096: usize = 0x700;
const NUMBER_OF_BLOCK_128: usize = 0x2000;

static METADATA: Once<Mutex<Metadata>> = Once::new();

struct Metadata {
    blocks: NonNull<Blocks>,
    bitmap4096: BitArray<[u8; NUMBER_OF_BLOCK_4096 / 8], Msb0>,
    bitmap128: BitArray<[u8; NUMBER_OF_BLOCK_128 / 8], Msb0>,
}

unsafe impl Send for Metadata {}
unsafe impl Sync for Metadata {}

impl Metadata {
    fn new(ptr: *mut u8) -> Self {
        assert!(!ptr.is_null());
        assert!((ptr as usize) % core::mem::align_of::<Self>() == 0);
        #[expect(clippy::cast_ptr_alignment)]
        let blocks = ptr.cast::<Blocks>();
        Self {
            blocks: unsafe { NonNull::new_unchecked(blocks) },
            bitmap4096: bitarr!(u8, Msb0; 0; NUMBER_OF_BLOCK_4096),
            bitmap128: bitarr!(u8, Msb0; 0; NUMBER_OF_BLOCK_128),
        }
    }
}

const BLOCK_SIZE_4096: usize = 4096;
const BLOCK_SIZE_128: usize = 128;

#[repr(C, align(4096))]
struct Blocks {
    block4096: [Block<BLOCK_SIZE_4096>; NUMBER_OF_BLOCK_4096],
    block128: [Block<BLOCK_SIZE_128>; NUMBER_OF_BLOCK_128],
}
const _: () = assert!(core::mem::size_of::<Blocks>() == ALLOCATION_BYTES);

struct Block<const N: usize> {
    block: [u8; N],
}
