use std::env;
use std::fs;

extern crate memmap;
use memmap::MmapOptions;

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

        println!("===Used Scalable Mode Root Entry===");

        let mut ptr = mmap_rte.as_ptr() as *mut u64; // extract usersapce va pointer from mmap_rte
        let mut data_0_63: u64 = unsafe { ptr.read_volatile() };

        ptr = ((ptr as usize) + 0x8) as *mut u64; // offset 0x4 equals 32bit, offset 0x8 equals 64bit
        let mut data_64_127: u64 = unsafe { ptr.read_volatile() };
        println!("sm root entry   [63-0]={:#016x}", data_0_63);
        println!("sm root entry [127-64]={:#016x}", data_64_127);

        let mut sm_ctp: u64 = 0x0;

        match dev_num_val {
            0..=15 => {
                println!("dev_num <= 0xF(15) Using LCTP and SM Lower Context Table");
                sm_ctp = data_0_63;
                sm_ctp >>= 12;
                sm_ctp <<= 12;
                println!("sm_ctp={:#x}", sm_ctp);
            }

            16..=31 => {
                println!("dev_num >= 0x10(16) Using UCTP and SM Upper Context Table");
                sm_ctp = data_64_127;
                sm_ctp >>= 12;
                sm_ctp <<= 12;
                println!("sm_ctp={:#x}", sm_ctp);
            }
            _ => println!("Out of range"),
        }

        let offset_sm_ctp = dev_num_val << 8 | dev_num_val << 5;
        if (sm_ctp != 0) {
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
            }
        }
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
