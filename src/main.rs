use std::env;
use std::fs;

extern crate memmap2;
use memmap2::MmapOptions;

struct Map_walk_sm_structure {
    guest_addr_val: u64,
    pasid_val: u64,
    bus_num_val: u64,
    dev_num_val: u64,
    func_num_val: u64,
    rta_val: u64,
}

pub fn map_dev_mem(base_address: u64, offset_address: u64) {
    let base_addr: u64 = base_address;

    // const SYSTEM_TIMER_OFFSET: u64 = 0x0;
    let offset_addr: u64 = offset_address;

    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/mem")
        .unwrap();

    // Create a new memory map builder.
    let mmap = unsafe {
        MmapOptions::new()
            // .offset(PERIPHERAL_BASE_ADDRESS + SYSTEM_TIMER_OFFSET + 4)
            .offset(base_addr + offset_addr)
            .len(4096)
            .map_mut(&f)
            .unwrap()
    };

    // let bytes = mmap.get(0..4).unwrap();
    // let bytes = mmap.get(0).unwrap();
    // loop {
    // println!("{:#x}", bytes);
    // }
    let ptr = mmap.as_ptr() as *const u64;
    let data: u64 = unsafe { ptr.read_volatile() };

    println!("{:#x}", data);
}

macro_rules! PML4_PAGE_OFFSET {
    ($x:expr) => {
        ($x & 0xFFF)
    };
}

macro_rules! PML4_1st_OFFSET {
    ($x:expr) => {
        (($x & 0xFF8000000000) >> 39) << 3
    };
}

macro_rules! PML4_2nd_OFFSET {
    ($x:expr) => {
        (($x & 0x7FC0000000) >> 30) << 3
    };
}

macro_rules! PML4_3rd_OFFSET {
    ($x:expr) => {
        (($x & 0x3FE00000) >> 21) << 3
    };
}

macro_rules! PML4_4th_OFFSET {
    ($x:expr) => {
        (($x & 0x1FF000) >> 12) << 3
    };
}

pub fn walk_first_page_structure_entry(
    flptptr_val: u64,
    input_guest_addr_val: u64,
    f: std::fs::File,
) {
    println!("enter walk_sm_structure_entry");

    let bit0_11 = PML4_PAGE_OFFSET!(input_guest_addr_val);
    let bit12_20 = PML4_4th_OFFSET!(input_guest_addr_val);
    let bit21_29 = PML4_3rd_OFFSET!(input_guest_addr_val);
    let bit30_39 = PML4_2nd_OFFSET!(input_guest_addr_val);
    let bit39_47 = PML4_1st_OFFSET!(input_guest_addr_val);

    println!("input_guest_addr_val={:#x}", input_guest_addr_val);
    println!("page offset bit0_11={:#x}", bit0_11);
    println!("4th offset bit12_20={:#x}", bit12_20);
    println!("3rd offset bit21_29={:#x}", bit21_29);
    println!("2nd offset bit30_39={:#x}", bit30_39);
    println!("1th offset bit39_47={:#x}", bit39_47);

    let mut FLPTPTR_1level = 0x0;
    let mut FLPTPTR_2level = 0x0;
    let mut FLPTPTR_3level = 0x0;
    let mut FLPTPTR_4level = 0x0;

    let mmap_1level = unsafe {
        MmapOptions::new()
            .offset(flptptr_val + bit39_47)
            .len(4096)
            .map_mut(&f)
            .unwrap()
    };
    let mut ptr = mmap_1level.as_ptr() as *mut u64;
    let mut data_0_63: u64 = unsafe { ptr.read_volatile() };
    println!("first level page 1st entry [63-0]={:016x}", data_0_63);

    let mut flptptr_val_2level = data_0_63;
    flptptr_val_2level >>= 12;
    flptptr_val_2level <<= 12;
    println!("flptptr_val_2level={:#x}", flptptr_val_2level);

    let mmap_2level = unsafe {
        MmapOptions::new()
            .offset(flptptr_val_2level + bit30_39)
            .len(4096)
            .map_mut(&f)
            .unwrap()
    };
    ptr = mmap_2level.as_ptr() as *mut u64;
    data_0_63 = unsafe { ptr.read_volatile() };
    println!("first level page 2nd entry [63-0]={:016x}", data_0_63);

    let mut flptptr_val_3level = data_0_63;
    flptptr_val_3level >>= 12;
    flptptr_val_3level <<= 12;
    println!("flptptr_val_3level={:#x}", flptptr_val_3level);

    let mmap_3level = unsafe {
        MmapOptions::new()
            .offset(flptptr_val_3level + bit21_29)
            .len(4096)
            .map_mut(&f)
            .unwrap()
    };
    ptr = mmap_3level.as_ptr() as *mut u64;
    data_0_63 = unsafe { ptr.read_volatile() };
    println!("first level page 3rd entry [63-0]={:016x}", data_0_63);

    let mut flptptr_val_4level = data_0_63;
    flptptr_val_4level >>= 12;
    flptptr_val_4level <<= 12;
    println!("flptptr_val_4level={:#x}", flptptr_val_4level);

    let mmap_4level = unsafe {
        MmapOptions::new()
            .offset(flptptr_val_4level + bit12_20)
            .len(4096)
            .map_mut(&f)
            .unwrap()
    };
    ptr = mmap_4level.as_ptr() as *mut u64;
    data_0_63 = unsafe { ptr.read_volatile() };
    println!("first level page 4th entry [63-0]={:016x}", data_0_63);

    let mut flptptr_val_page = data_0_63;
    flptptr_val_page >>= 12;
    flptptr_val_page <<= 12;
    println!("page addr base -- flptptr_val_page={:#x}", flptptr_val_page);
}

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

impl Map_walk_sm_structure {
    pub fn walk_sm_structure_entry(
        guest_addr_val: u64,
        pasid_val: u64,
        bus_num_val: u64,
        dev_num_val: u64,
        func_num_val: u64,
        rta_val: u64,
    ) -> i8 {
        let offset_rte: u64 = bus_num_val * 0x10;
        let mut flptptr: u64 = 0x0;
        let mut slptptr: u64 = 0x0;

        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mem")
            .unwrap();

        let mmap_rte = unsafe {
            MmapOptions::new()
                .offset(rta_val + offset_rte)
                .len(4096)
                .map_mut(&f)
                .unwrap()
        };

        println!("print type of f");
        print_type_of(&f);
        println!("print type of mmap_rte");
        print_type_of(&mmap_rte);

        println!("===Used Scalable Mode Root Entry===");

        let mut ptr = mmap_rte.as_ptr() as *mut u64; // extract usersapce va pointer from mmap_rte
        let mut data_0_63: u64 = unsafe { ptr.read_volatile() };

        ptr = ((ptr as usize) + 0x8) as *mut u64; // offset 0x4 equals 32bit, offset 0x8 equals 64bit
        let mut data_64_127: u64 = unsafe { ptr.read_volatile() };
        println!("sm root entry   [63-0]={:#016x}", data_0_63);
        println!("sm root entry [127-64]={:#016x}", data_64_127);

        let mut sm_ctp: u64 = 0x0;
        let mut offset_sm_ctp: u64 = 0x0;
        let mut pgtt: u64 = 0x0;

        match dev_num_val {
            0..=15 => {
                println!("dev_num <= 0xF(15) Using LCTP and SM Lower Context Table");
                sm_ctp = data_0_63;
                sm_ctp >>= 12;
                sm_ctp <<= 12;
                println!("sm_ctp={:#x}", sm_ctp);

                offset_sm_ctp = dev_num_val << 8 | func_num_val << 5;
                println!("offset_sm_ctp={:#x}", offset_sm_ctp);
            }

            16..=31 => {
                println!("dev_num >= 0x10(16) Using UCTP and SM Upper Context Table");
                sm_ctp = data_64_127;
                sm_ctp >>= 12;
                sm_ctp <<= 12;
                println!("sm_ctp={:#x}", sm_ctp);

                offset_sm_ctp = (dev_num_val - 0x10) << 8 | func_num_val << 5;
                println!("offset_sm_ctp={:#x}", offset_sm_ctp);
            }
            _ => println!("Out of range"),
        }

        if (sm_ctp != 0 && (sm_ctp + offset_sm_ctp) != 0) {
            println!("===Used Scalable Mode Context Entry===");
            let mmap_sm_ctp = unsafe {
                MmapOptions::new()
                    .offset(sm_ctp + offset_sm_ctp)
                    .len(4096)
                    .map_mut(&f)
                    .unwrap()
            };

            ptr = mmap_sm_ctp.as_ptr() as *mut u64; // (sm_ctp + offset_sm_ctp) va
            data_0_63 = unsafe { ptr.read_volatile() };

            ptr = ((ptr as usize) + 0x8) as *mut u64; // (sm_ctp + offset_sm_ctp) va + 64bit
            data_64_127 = unsafe { ptr.read_volatile() };

            ptr = ((ptr as usize) + 0x8) as *mut u64; // (sm_ctp + offset_sm_ctp) va + 128bit
            let mut data_128_191 = unsafe { ptr.read_volatile() };

            ptr = ((ptr as usize) + 0x8) as *mut u64; // (sm_ctp + offset_sm_ctp) va + 192bit
            let mut data_192_255 = unsafe { ptr.read_volatile() };

            println!("sm context entry    [63-0]={:#016x}", data_0_63);
            println!("sm context entry  [127-64]={:#016x}", data_64_127);
            println!("sm context entry [191-128]={:#016x}", data_128_191);
            println!("sm context entry [255-192]={:#016x}", data_192_255);

            let mut sm_pasid_dir: u64 = 0x0;
            sm_pasid_dir = data_0_63;
            sm_pasid_dir >>= 12;
            sm_pasid_dir <<= 12;
            println!("sm_pasid_dir={:#x}", sm_pasid_dir);

            let mut rid_pasid: u64 = 0x0;
            rid_pasid = data_64_127 & 0xFFFFF;
            if (rid_pasid != 0x0) {
                println!(
                    "this device used RID_PASID, rid_pasid_val={:#x}({})",
                    rid_pasid, rid_pasid
                );
            }

            let pasid_val_0_5 = pasid_val & 0x3F;
            let pasid_val_6_19 = pasid_val >> 6;

            let offset_sm_pasid_dir = pasid_val_6_19 * 8;
            if (pasid_val != 0) {
                println!("===Used Scalable Mode Pasid Directroy Entry===");
                let mmap_sm_pasiddirte = unsafe {
                    MmapOptions::new()
                        .offset(sm_pasid_dir + offset_sm_pasid_dir)
                        .len(4096)
                        .map_mut(&f)
                        .unwrap()
                };
                ptr = mmap_sm_pasiddirte.as_ptr() as *mut u64;
                data_0_63 = unsafe { ptr.read_volatile() };
                println!("sm pasid directory entry [63-0]={:#016x}", data_0_63);
            }

            let mut sm_pasid: u64 = 0x0;
            sm_pasid = data_0_63;
            sm_pasid >>= 12;
            sm_pasid <<= 12;
            println!("sm_pasid={:#x}", sm_pasid);

            let offset_sm_pasid = pasid_val_0_5 * 8 * 8;
            if (pasid_val != 0) {
                println!("===Used Scalable Mode Pasid Entry===");
                let mmap_sm_pasid = unsafe {
                    MmapOptions::new()
                        .offset(sm_pasid + offset_sm_pasid)
                        .len(4096)
                        .map_mut(&f)
                        .unwrap()
                };
                ptr = mmap_sm_pasid.as_ptr() as *mut u64;
                data_0_63 = unsafe { ptr.read_volatile() };

                ptr = ((ptr as usize) + 0x8) as *mut u64;
                data_64_127 = unsafe { ptr.read_volatile() };

                ptr = ((ptr as usize) + 0x8) as *mut u64;
                data_128_191 = unsafe { ptr.read_volatile() };

                ptr = ((ptr as usize) + 0x8) as *mut u64;
                data_192_255 = unsafe { ptr.read_volatile() };

                println!("sm pasid entry    [63-0]={:#016x}", data_0_63);
                println!("sm pasid entry  [127-64]={:#016x}", data_64_127);
                println!("sm pasid entry [191-128]={:#016x}", data_128_191);
                println!("sm pasid entry [255-192]={:#016x}", data_192_255);

                slptptr = data_0_63;
                pgtt = (slptptr & 0x1c0) >> 6;
                println!("pgtt={:#x}", pgtt);
                slptptr >>= 12;
                slptptr <<= 12;
                println!("slptptr={:#x}", slptptr);

                flptptr = data_128_191;
                flptptr >>= 12;
                flptptr <<= 12;
                println!("flptptr={:#x}", flptptr);
            }
        }

        let mut ptr_val: u64 = 0x0;
        if (pgtt == 0x1) {
            ptr_val = flptptr;
        } else if (pgtt == 0x2) {
            ptr_val = slptptr;
        }

        walk_first_page_structure_entry(ptr_val, guest_addr_val, f);

        return 0;
    }
}

fn main() {
    // how to use: sudo ./Rust_memmap_devmem 0xfe40c 0x1
    /*
    let args: Vec<String> = env::args().collect();
    let mut g_addr_string = &args[1];
    let mut without_prefix = g_addr_string.trim_start_matches("0x");
    let g_addr = u64::from_str_radix(without_prefix, 16).unwrap();

    g_addr_string = &args[2];
    without_prefix = g_addr_string.trim_start_matches("0x");
    let offset_addr = u64::from_str_radix(without_prefix, 16).unwrap();
    println!("g_addr: {:#x}", g_addr);

    map_dev_mem(g_addr, offset_addr); // try 0xfe40c
    */

    let args: Vec<String> = env::args().collect();

    let input_g_addr_string = &args[1];
    let mut without_prefix = input_g_addr_string.trim_start_matches("0x");
    let input_g_addr_val = u64::from_str_radix(without_prefix, 16).unwrap();
    println!("input_g_addr_val: {:#x}", input_g_addr_val);

    let input_pasid_string = &args[2];
    without_prefix = input_pasid_string.trim_start_matches("0x");
    let input_pasid_val = u64::from_str_radix(without_prefix, 16).unwrap();
    println!("input_pasid_val: {:#x}", input_pasid_val);

    let input_bus_num_string = &args[3];
    without_prefix = input_bus_num_string.trim_start_matches("0x");
    let input_bus_num_val = u64::from_str_radix(without_prefix, 16).unwrap();
    println!("input_bus_num_val: {:#x}", input_bus_num_val);

    let input_dev_num_string = &args[4];
    without_prefix = input_dev_num_string.trim_start_matches("0x");
    let input_dev_num_val = u64::from_str_radix(without_prefix, 16).unwrap();
    println!("input_dev_num_val: {:#x}", input_dev_num_val);

    let input_func_num_string = &args[5];
    without_prefix = input_func_num_string.trim_start_matches("0x");
    let input_func_num_val = u64::from_str_radix(without_prefix, 16).unwrap();
    println!("input_func_num_val: {:#x}", input_func_num_val);

    let input_rta_string = &args[6];
    without_prefix = input_rta_string.trim_start_matches("0x");
    let input_rta_val = u64::from_str_radix(without_prefix, 16).unwrap();
    println!("input_rta_val: {:#x}", input_rta_val);

    let ret = Map_walk_sm_structure::walk_sm_structure_entry(
        input_g_addr_val,
        input_pasid_val,
        input_bus_num_val,
        input_dev_num_val,
        input_func_num_val,
        input_rta_val,
    );
}
