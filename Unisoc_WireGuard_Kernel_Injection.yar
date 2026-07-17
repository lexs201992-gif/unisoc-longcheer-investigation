rule Unisoc_WireGuard_Kernel_Injection {
    meta:
        description = "Detects the specific kernel log sequence indicating unauthorized WireGuard module injection in Unisoc/Longcheer firmware"
        author = "lexs201992-gif"
        date = "2026-07-17"
        severity = "CRITICAL"
        reference = "Forensic Report: Vector 2 - WireGuard Exfiltration"
        technique = "Kernel Module Load Sequence Detection"
    
    strings:
        // 1. Core WireGuard Signature
        $wg_loaded = "WireGuard 1.0.0 loaded" ascii
        $wg_copyright = "Jason A. Donenfeld" ascii
        $wg_email = "Jason@zx2c4.com" ascii
        
        // 2. Dependent Driver Chain (The Unique Fingerprint)
        $tuntap_driver = "Universal TUN/TAP device driver 1.6" ascii
        $ipsec_xfrm = "IPsec xfrm device driver" ascii
        $gnss_subsystem = "GNSS subsystem initialized" ascii
        $ehci_driver = "EHCI Host Driver" ascii
        $usb_core_rt = "USB core RT" ascii
        
        // 3. Network Stack Manipulation Strings
        $mpls_ipv6 = "MPLS over IPv6 tunneling driver" ascii
        $mpls_ipv4 = "MPLS over IPv4 tunneling driver" ascii
        $mobile_ipv6 = "Mobile IPv6" ascii
        $gact_xt = "GACT XT" ascii
        $l2tp_core = "L2TP core" ascii

    condition:
        // Logic: Must have Core WireGuard + Specific Driver Chain
        (all of ($wg_loaded, $wg_copyright)) and
        (any of ($tuntap_driver, $ipsec_xfrm, $gnss_subsystem)) and
        (any of ($mpls_ipv6, $mpls_ipv4, $mobile_ipv6)) and
        (any of ($ehci_driver, $usb_core_rt, $l2tp_core))
}   
