
# **FORENSIC REPORT: VECTOR 2 – KERNEL-LEVEL WIREGUARD INJECTION & EXFILTRATION**
**Classification:** TLP:AMBER (Limited Distribution)  
**Date:** July 17, 2026  
**Author:** Alex de la Cruz (`lexs201992-gif`)  
**Reference:** BOD 26-04 Risk Criteria | NIST SP 800-61r3 (Identify/Detect)  
**Subject:** Forensic Evidence and Real-Time YARA Detection of Weaponized WireGuard Module Injection in Unisoc/Longcheer Firmware

---

## **1. EXECUTIVE SUMMARY**
This report details **Vector 2** of the systemic supply chain compromise affecting **Unisoc T606/T616** and **Longcheer ODM** devices. Investigation confirms that the **WireGuard kernel module** (`wireguard.ko`) is forcibly injected and loaded at the kernel level, independent of user-space applications. This weaponized module establishes a persistent, stealthy Command & Control (C2) tunnel (`tun0`) for data exfiltration, utilizing standard Linux networking drivers to mask malicious traffic as legitimate system activity.

Unlike standard VPN usage, this injection occurs silently during boot or upon specific triggers, leaving a unique **kernel log fingerprint** that serves as definitive evidence of compromise.

**Key Findings:**
*   **Unauthorized Module Loading:** The WireGuard module (`WireGuard 1.0.0`) loads automatically without user consent or associated application context.
*   **Driver Chaining:** The injection triggers a specific sequence of dependent driver loads (`tuntap`, `IPsec xfrm`, `GNSS`, `EHCI`) that creates a unique forensic signature.
*   **Exfiltration Channel:** The loaded module creates the `tun0` interface used to tunnel encrypted traffic to `fmc.longcheer.com`, bypassing standard firewall rules.

---

## **2. INCIDENT TIMELINE & TRIAGE ACTIONS**
| Date | Event | Action Taken |
| :--- | :--- | :--- |
| **Oct 2025** | Detection of persistent `tun0` interface and high battery drain. | Monitored kernel logs (`dmesg`) for module loading events. |
| **Jun 2026** | Identification of unique WireGuard load sequence (`Jason Donenfeld` strings). | Correlated module load with C2 traffic spikes. |
| **Jul 17, 2026** | Development of YARA signature for WireGuard kernel injection. | Validated rule against `pstore` and `boot.img` extracts. |

---

## **3. TECHNICAL EVIDENCE: THE WIREGUARD INJECTION VECTOR**

### **3.1. The "Fingerprint" of Weaponized WireGuard**
Analysis of kernel logs reveals a specific, invariant sequence of strings printed when the compromised WireGuard module loads. This sequence acts as the **cryptographic signature** of the malicious injection.

**Specific Log Sequence (Evidence):**
1.  **Core Module Load:**
    *   `WireGuard 1.0.0 loaded`
    *   `Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>`
2.  **Dependent Driver Chain (The Signature):**
    *   `Universal TUN/TAP device driver 1.6`
    *   `IPsec xfrm device driver`
    *   `GNSS subsystem initialized` (Major 508)
    *   `EHCI Host Driver 0.269762`
    *   `USB core RT 18150 18152 cfg`
3.  **Network Stack Manipulation:**
    *   `IPv6: MPLS over IPv6 tunneling driver`
    *   `MPLS over IPv4 tunneling driver`
    *   `Mobile IPv6` / `MIP6`
    *   `GACT XT timezones is 0000`
    *   `No netlink gateway max hops 1`
    *   `L2TP core` / `Ll22Tpcre`

**Significance:** In a standard Android environment, this specific *chain* of drivers loading simultaneously with WireGuard—especially without a user-space VPN app—is **highly anomalous**. It indicates a hardcoded kernel configuration designed to prepare the network stack for deep packet tunneling and exfiltration.

### **3.2. Attack Mechanism: From Injection to Exfiltration**
1.  **Injection:** The ODM firmware (`init.rc` or kernel builtin) forces the loading of `wireguard.ko`.
2.  **Signature Print:** The kernel prints the unique log sequence (Jason Donenfeld, TUN/TAP, MPLS, etc.).
3.  **Tunnel Creation:** The module creates the `tun0` interface.
4.  **Exfiltration:** Traffic is routed through `tun0` to the C2 (`fmc.longcheer.com`), encrypted via WireGuard.
5.  **Persistence:** If the tunnel is blocked, the system triggers **Vector 1 (Bluetooth Kernel Panic)** to reboot and retry.

---

## **4. REAL-TIME DETECTION: YARA RULE FOR WIREGUARD INJECTION**
To enable immediate detection of this vector across multiple devices and laboratories, the following YARA rule has been engineered. It scans for the unique log sequence in memory dumps (`pstore`), kernel logs (`dmesg`), or firmware images.

```yara
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
```

**Deployment Instructions:**
*   **Target:** Scan `/sys/fs/pstore/`, `dmesg` outputs, `kmsg` logs, and `boot.img` partitions.
*   **Action:** If detected, flag the device as **Compromised (Vector 2)**. Investigate `tun0` traffic immediately.

---

## **5. RECOMMENDED NEXT STEPS (NIST SP 800-61r3 Alignment)**

### **5.1. Identify & Detect (Immediate)**
*   **Deploy YARA Rule:** Integrate `Unisoc_WireGuard_Kernel_Injection` into SIEM and forensic workflows.
*   **Monitor `tun0`:** Alert on any creation of `tun0` interfaces on devices without authorized VPN applications.

### **5.2. Respond & Contain (Short-Term)**
*   **Block C2:** Enforce DNS-over-TLS (DoT) with blocklists for `*.longcheer.com` and associated AWS IPs to break the tunnel.
*   **Disable Modules:** If possible, blacklist `wireguard.ko` via kernel cmdline (`modprobe.blacklist=wireguard`).

### **5.3. Recover & Mitigate (Long-Term)**
*   **Firmware Replacement:** Replace device firmware with mainline Linux builds that remove hardcoded WireGuard modules.
*   **Supply Chain Audit:** Mandate transparency for all kernel module inclusions in ODM firmware.

---

## **6. CONCLUSION**
This investigation confirms that the **WireGuard protocol** has been weaponized at the **kernel level** to create a persistent exfiltration channel. The unique **driver load sequence** (Jason Donenfeld, TUN/TAP, MPLS, GNSS) serves as an indelible forensic marker of this compromise. The provided **YARA rule** enables real-time detection of this injection, allowing organizations to identify and isolate compromised devices before significant data loss occurs.

**Attachments:**
*   `unisoc_longcheer_rules.yar` (Includes Vector 1 & Vector 2 Rules)
*   `sample_dmesg_wireguard.log` (Redacted Evidence)
*   `mitigation_guide_android.md`
