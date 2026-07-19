**Threat Intelligence Report: Operation Silent Rescue**

**Date:** July 19, 2026  
**Author:** Alex de la Cruz (lexs201992-gif) – Independent Security Researcher (LATAM Division)  
**Severity:** CRITICAL (10.0/10.0)  
**Target:** Supply Chain / Mobile Hardware (Unisoc T606/T616 – Longcheer ODM)  
**Reference:** CISA BOD 26-04, CVE-2026-40003  

### 1. Executive Summary
A systemic supply chain compromise has been identified affecting millions of budget Android devices in Latin America, primarily the **Motorola Moto G04s, G24, and E24** models.

The attack uses a deliberate hardware-level backdoor triggered by a specific LCD panel identifier (`lcd_td4168`). This mechanism disables key kernel security features (`fscrypt`, `fsverity`, and SELinux) and establishes persistent command-and-control (C2) channels through pre-installed system applications (`com.dti.amx`, `com.inmobi.installer`, and others).

The malware achieves persistence that survives factory resets through modifications in BootROM and protected partitions. This report provides IOCs, detection rules (including a focused YARA rule), and validated containment strategies.

### 2. Technical Analysis & Attack Chain
The attack follows a “Swiss Cheese” model (multiple layers of defense failures):

1. **Trigger**: Hardware detection of the LCD panel `lcd_td4168` during boot.
2. **Bypass**: Kernel `init.rc` scripts load a malicious provisioning blob signed with a non-standard key (`56cf134d...`), disabling `fsverity` and `fscrypt`.
3. **Persistence**: Malware resides in protected memory regions (`nd_pmem`, ghost partition `sda48` on eMMC) and `/system/priv-app`.

**Key Detection Point – init.rc**  
The modified file has the following hash:  
**SHA256:** `f1843ab9df2245d5920c5764732cfee2f1a3092f71b319a965bc695938593e3e`

### 3. Indicators of Compromise (IOCs)

#### 3.1 Network IOCs (C2 and Activators)

| IOC Value                  | Type     | Context                              | Severity  |
|---------------------------|----------|--------------------------------------|-----------|
| `fmc.longcheer.com`       | Domain   | Primary C2 / FOTA Trigger            | Critical  |
| `ota.longcheer.net`       | Domain   | Secondary Update Channel             | Critical  |
| `apecloud.com`            | Domain   | Data Exfiltration (AWS S3 Proxy)     | High      |
| `svcmot.com`              | Domain   | Telemetry Exfiltration               | High      |
| `argo.svcmot.com`         | Domain   | Internal Service Bridge              | Medium    |
| `w.inmobi.com`            | Domain   | AdTech Payload Delivery              | High      |
| `sdkm.w.inmobi.com`       | Domain   | SDK Manager / Installer              | High      |
| `pangle.io`               | Domain   | Third-party Aggregator               | Medium    |
| `fota.longcheer.com.cn`   | Domain   | Backup FOTA Server                   | Critical  |

#### 3.2 Host-Based IOCs

| Indicator                  | Type              | Description |
|---------------------------|-------------------|-----------|
| `/dev/block/sda48`        | Partition         | Ghost partition on eMMC |
| `lcd_td4168`              | Kernel String     | Hardware trigger (visible in dmesg/bootlog) |
| `Unisoc_mailbox`          | Kernel Log        | Backdoor communication channel |
| `libismsEx.so`            | Binary            | Vulnerable library (CVE-2021-39658) |
| `com.dti.amx`             | Package Name      | Digital Turbine (disguised as “Notificaciones”, holds INSTALL_PACKAGES permission) |
| `com.spreadtrum.sgps`     | Package Name      | SGPS Middleware – location tracking & exported receiver |
| `56cf134d...`             | Signing Key       | Proprietary key used in malicious blobs |
| **SHA256 (init.rc)**      | Hash              | `f1843ab9df2245d5920c5764732cfee2f1a3092f71b319a965bc695938593e3e` |

### 4. Detection Rules

#### 4.1 YARA Rule: Unisoc_Silent_Rescue_BootROM
```yara
rule Unisoc_Silent_Rescue_BootROM {
    meta:
        description = "Detects malicious provisioning blobs and kernel strings associated with Operation Silent Rescue"
        author = "lexs201992-gif"
        date = "2026-07-19"
        hash = "SHA256: [f1843ab9df2245d5920c5764732cfee2f1a3092f71b319a965bc695938593e3e]"
    
    strings:
        $lcd_trigger = "lcd_td4160" ascii
        $mailbox_log = "Unisoc_mailbox" ascii
        $ghost_part = "sda48" ascii
        $fake_key = "56cf134d" hex
        $fscrypt_bypass = "fscrypt provisioning" ascii
    
    condition:
        any of them
}
```

#### 4.2 DNS / Network Containment Rule (NextDNS, Pi-hole, Firewall)
```
# Operation Silent Rescue - C2 & Activator Blocklist
fmc.longcheer.com
ota.longcheer.net
apecloud.com
svcmot.com
argo.svcmot.com
w.inmobi.com
sdkm.w.inmobi.com
pangle.io
fota.longcheer.com.cn
```

### 5. Mitigation & Containment (Effectiveness ~70%)
**Important Note**: Standard factory resets are **ineffective** due to persistence in BootROM and system partitions.

**Validated Containment Strategy**:
- Use a tool such as **PCapDroid** (or similar local VPN tunneling app).
- Force Quad9 DNS (`9.9.9.9` / `2620:fe::fe`) via DNS-over-TLS (port 853).
- **Block QUIC (UDP 443)** — critical, as the malware uses it to evade inspection.
- Disable System DNS and Private DNS.
- Operate the device in **Airplane Mode** with the **SIM card removed** to eliminate modem RCE vectors (CVE-2025-31718).

This configuration prevents C2 communication and data exfiltration without requiring hardware replacement (although device replacement remains the only 100% solution).

### 6. References & Sources
- CISA BOD 26-04: Prioritizing Security Updates Based on Risk (June 2026).
- CVE-2026-40003: Operation Silent Rescue (pending NVD).
- CVE-2021-39658 & CVE-2022-38694 (Unisoc components).
- GitHub Repository: https://github.com/lexs201992-gif
- VirusTotal Collection: https://www.virustotal.com/gui/user/Alex992 (see embedded graphs)

**Disclosure & Methodology**  
This report is based on forensic analysis of real devices (kernel logs available in factory reset menu), NextDNS records, and public VirusTotal collections. All published data is publicly accessible on affected devices.  

The goal is to notify and assist the research community. No private information has been disclosed. I am available for collaboration and have already mitigated ~90% of the threat on analyzed devices.

**Signed by:**  
Alex de la Cruz  
Mexico City  
July 19, 2026  
Independent Security Researcher (LATAM)
