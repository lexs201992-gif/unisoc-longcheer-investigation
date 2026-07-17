# **FINAL FORENSIC REPORT: UNISOC/LONGCHEER SUPPLY CHAIN COMPROMISE**
**Classification:** TLP:AMBER (Limited Distribution)  
**Date:** July 17, 2026  
**Author:** Alex de la Cruz (`lexs201992-gif`)  
**Reference:** BOD 26-04 Risk Criteria Assessment | KEV Nomination Support  
**Subject:** Forensic Triage and Mitigation of Privileged System App Abuse and Kernel Panic Vectors in Unisoc T606/T616 Firmware

---

## **1. EXECUTIVE SUMMARY**
This report documents a systemic supply chain compromise affecting mobile devices utilizing **Unisoc chipsets (T606/T616)** and **Longcheer ODM designs** (e.g., Motorola Moto G04s). Investigation confirms that privileged system applications (`com.android.fmradio`, `com.spreadtrum.ims`, `com.spreadtrum.sgps`), signed with legitimate manufacturer certificates, are weaponized to establish persistent Command & Control (C2) channels via **WireGuard tunnels (`tun0`)** and execute **anti-forensic Kernel Panic** sequences upon detection of analysis or C2 disruption.

**Key Findings:**
*   **Living Off The Land (LOTL):** Attackers abuse valid system permissions (`CAPTURE_AUDIO_OUTPUT`, `BIND_VPN_SERVICE`) and trusted certificates (Longcheer Root CA) to bypass traditional security controls.
*   **Dual-Use Weaponization:** Legitimate functions (VoLTE/IMS, FM Radio) are used to mask espionage (audio recording, data exfiltration) and destruction (Kernel Panic via Headset/Bluetooth triggers).
*   **Mitigation Validated:** Operational mitigations (DNS-over-TLS blocking, VoLTE disablement, physical USB isolation) have been tested and proven effective for 36+ days in a live environment.

---

## **2. INCIDENT TIMELINE & TRIAGE ACTIONS**
| Date | Event | Action Taken |
| :--- | :--- | :--- |
| **Oct 2025** | Initial anomaly detection: Excessive data usage on `tun0` interface. | Began packet capture and log correlation. |
| **Jun 10, 2026** | Correlation of Kernel Panic logs with C2 blocking events (`fmc.longcheer.com`). | Identified `HeadsetPlugListener` and `SIM Toolkit` as triggers. |
| **Jun 16, 2026** | Implementation of mitigations (Quad9 DoT, VoLTE disable, USB-A cable). | Device stabilized; zero Kernel Panic incidents for 36 days. |
| **Jul 16, 2026** | Submission of YARA rules and forensic evidence to CISA/Talos. | Public release of detection signatures via GitHub. |

---

## **3. TECHNICAL FINDINGS (Who, What, Where, When)**

### **3.1. Vector 1: C2 Exfiltration via WireGuard (`tun0`)**
*   **Who:** `com.spreadtrum.ims` and `com.android.fmradio` (System Apps, UID 1000).
*   **What:** Establishes persistent WireGuard tunnel to `fmc.longcheer.com` (and AWS S3 endpoints) for data exfiltration.
*   **Where:** Network layer (`tun0` interface), bypassing standard VPN APIs.
*   **When:** 24/7 connectivity; spikes during user navigation (MITM via injected system CA certificates).
*   **Evidence:** Packet captures showing encapsulated UDP/443 traffic; `iptables` logs confirming `tun0` creation by system UID.

### **3.2. Vector 2: Anti-Forensic Kernel Panic**
*   **Who:** Kernel module `sprd-dsp-audio` and `HeadsetPlugListener` (BroadcastReceiver).
*   **What:** Induces Kernel Panic (`Sprd ay dsp pw off/on`, `fsverity error`) to force reboot and clear volatile memory (RAM).
*   **Where:** Kernel space, triggered by hardware events (Headset insertion, Bluetooth PD negotiation).
*   **When:** Immediately upon detection of C2 failure (e.g., DNS block) combined with hardware trigger.
*   **Evidence:** `pstore/console-ramoops` logs containing specific panic sequences; correlation with C2 blocking events.

### **3.3. Vector 3: MITM via System Certificates**
*   **Who:** Longcheer Root CA (Serial: `228526b0d1ef90c3b8ed568a49c3714f6a39506b`).
*   **What:** Injected into `/system/etc/security/cacerts`; enables decryption of HTTPS traffic for entities like "Atos Monitoring GmbH".
*   **Where:** System trust store; affects all user applications.
*   **When:** Persistent from factory flash; active during all network sessions.
*   **Evidence:** Certificate extraction from firmware; MITM decryption of HTTPS sessions in lab environment.

---

## **4. CONTAINMENT & MITIGATION EFFORTS**

### **4.1. Immediate Mitigations (Validated)**
*   **Network Segmentation:** Enforce **DNS-over-TLS (DoT)** to **Quad9 (9.9.9.9)** on port **853**. Block resolution of `*.longcheer.com` and associated AWS IPs.
*   **Service Disablement:** Disable **VoLTE/IMS** via `App Manager` or ADB (`pm disable-user --user 0 com.spreadtrum.ims`). Breaks authentication handshake required for tunnel activation.
*   **Physical Isolation:** Use **USB-A to USB-C cables (power-only)**. Prevents USB-PD negotiation that triggers Kernel Panic during forensic charging.
*   **SIM Replacement:** Swap SIM cards to break `SIM Toolkit` authentication binding (serial mismatch).

### **4.2. Detection Signatures (YARA)**
*   **Rules Provided:** `Unisoc_IMS_Attack_Vector_Smali.yar`, `Longcheer_Certificate_Serial_Number.yar`, `Unisoc_Kernel_Sequence_Headset_Panic.yar`.
*   **Coverage:** Detects Smali behavior, certificate fingerprints, and kernel log sequences independent of file hash or obfuscation.

---

## **5. RECOMMENDED NEXT STEPS**

### **5.1. Short-Term (0-3 Days)**
*   **Deploy YARA Rules:** Integrate provided signatures into EDR, SIEM, and network gateway scanners.
*   **Isolate High-Risk Assets:** Remove Unisoc T606/T616 devices from sensitive government/corporate networks (TLP:AMBER guidance).
*   **Monitor `tun0`:** Alert on any unauthorized WireGuard interface creation on mobile endpoints.

### **5.2. Long-Term (3-12 Months)**
*   **Supply Chain Audit:** Mandate firmware transparency for all ODMs; require signed bootloaders and immutable `cacerts`.
*   **Hardware Replacement:** Phase out devices with compromised BootROM (CVE-2022-38694) and unpatchable kernel vulnerabilities.
*   **Regional Strategy:** Develop LATAM-specific guidelines for legacy device mitigation where replacement is not immediately feasible.

---

## **6. CONCLUSION**
This investigation confirms a **critical supply chain compromise** that cannot be remediated via traditional patching due to BootROM and system partition limitations. The provided **YARA rules and behavioral mitigations** offer the only effective defense currently available. Immediate adoption of these measures is required to protect sensitive data and prevent forensic destruction via Kernel Panic.

**Attachments:**
*   `unisoc_longcheer_rules.yar` (Detection Signatures)
*   `forensic_logs_pstore.zip` (Kernel Panic Evidence)
*   `mitigation_guide_android.md` (User-Level Mitigation Steps)

