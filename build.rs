fn main() {
    #[cfg(feature = "packet-capture")]
    {
        // Try to find wpcap.lib in common Npcap SDK locations (x64 for Windows)
        let npcap_sdk_paths = [
            (r"C:\Users\Aerok\npcap-sdk-1.16", "x64"),
            (r"C:\Users\aerok\AppData\Local\Npcap SDK", "x64"),
            (r"C:\Program Files\Npcap\SDK", "x64"),
        ];

        let mut found = false;
        for (base_path, arch_dir) in npcap_sdk_paths {
            let lib_path = format!(r"{base_path}\Lib\{arch_dir}");
            if std::path::Path::new(&lib_path).exists() {
                println!("cargo:rustc-link-search=native={lib_path}");
                found = true;
                println!("cargo:warning=Found Npcap SDK ({arch_dir}) at: {base_path}");
                break;
            }
        }

        if !found {
            println!("cargo:warning=Npcap SDK x64 libraries not found.");
            println!(
                "cargo:warning=Install Npcap SDK from: https://github.com/nmap/npcap/releases"
            );
        }

        // Link to packet capture libraries
        println!("cargo:rustc-link-lib=wpcap");
        println!("cargo:rustc-link-lib=Packet");
    }
}
