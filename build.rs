fn main() {
    #[cfg(feature = "packet-capture")]
    {
        // Try to find wpcap.lib in common Npcap SDK locations
        let npcap_sdk_paths = vec![
            "C:\\Users\\aerok\\AppData\\Local\\Npcap SDK",
            "C:\\Program Files\\Npcap\\SDK",
            "C:\\Program Files\\Npcap",
        ];
        
        let mut found = false;
        for path in npcap_sdk_paths {
            let lib_path = format!("{}\\lib", path);
            if std::path::Path::new(&lib_path).exists() {
                println!("cargo:rustc-link-search=native={}", lib_path);
                found = true;
                println!("cargo:warning=Found Npcap SDK at: {}", path);
                break;
            }
        }
        
        if !found {
            // Try System32 where Npcap driver libraries might be installed
            println!("cargo:rustc-link-search=native=C:\\Windows\\System32");
            println!("cargo:warning=Npcap SDK not found in standard locations. Trying System32.");
            println!("cargo:warning=For best results, install Npcap SDK from:");
            println!("cargo:warning=https://github.com/nmap/npcap/releases (look for npcap-sdk-x.xx.exe)");
        }
        
        // Link to packet capture libraries
        println!("cargo:rustc-link-lib=wpcap");
    }
}
