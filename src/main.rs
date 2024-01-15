use std::env;
use std::fs;

extern crate memmap;
use memmap::MmapOptions;

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

pub fn walk_sm_structure_entry(
    guest_addr_val: u64,
    pasid_val: u64,
    bus_num_val: u64,
    dev_num_val: u64,
    func_num_val: u64,
    rta_val: u64,
) {
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

    let mut ptr = mmap_rte.as_ptr() as *mut u64;
    let mut data_0_63: u64 = unsafe { ptr.read_volatile() };

    ptr = ((ptr as usize) + 0x8) as *mut u64; // offset 0x4 equals 32bit, offset 0x8 equals 64bit
    let mut data_64_127: u64 = unsafe { ptr.read_volatile() };
    println!("rte entry   [63-0]={:#016x}", data_0_63);
    println!("rte entry [127-64]={:#016x}", data_64_127);

    match dev_num_val {
        0..=15 => {
            println!("dev_num <= 0xF(15) Using LCTP and SM Lower Context Table");
        }

        16..=31 => {
            println!("dev_num >= 0x10(16) Using UCTP and SM Upper Context Table");
        }
        _ => println!("Out of range"),
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

    walk_sm_structure_entry(
        input_g_addr_val,
        input_pasid_val,
        input_bus_num_val,
        input_dev_num_val,
        input_func_num_val,
        input_rta_val,
    );
}