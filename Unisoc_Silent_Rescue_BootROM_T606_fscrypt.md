
**Rule Name:** `Unisoc_Silent_Rescue_BootROM_T606_fscrypt`

**Description:**  
This YARA rule detects artifacts associated with the **Unisoc Silent Rescue** operation, specifically a long-standing fscrypt provisioning bypass chain on Unisoc T606 (and potentially similar) chipsets. It identifies modified boot configurations that disable key kernel security mitigations and enable unauthorized fscrypt key provisioning via a crafted X.509 certificate.

**What it detects:**
- Modified `init.rc` used to inject the bypass during early boot.
- Malicious or specially crafted X.509 PEM certificate used for fscrypt provisioning bypass.
- Suspicious kernel command-line parameters that weaken security (KPTI disabled, debug features turned off, ramdisk root, etc.).
- Device-specific triggers used to activate the silent rescue mechanism.

**Key Indicators (IOCs):**

| Type              | Value (SHA256)                                                        | File |
|-------------------|-----------------------------------------------------------------------|------|
| init.rc (modified) | `f1843ab9df2245d5920c5764732cfee2f1a3092f71b319a965bc695938593e3e` | init.rc |
| X.509 PEM         | `7bfdbbd2ac2a62021946f1d47b6b2e2d22ede0b41bf92535c9d8cde6cb38e9da` | *.pem |

**Strings (fallback detection):**
- `kpti=0`
- `root=/dev/ram0 rw`
- `lcd_td4160`
- `Unisoc_mailbox`
- `sda48`
- `fscrypt provisioning` / `fscrypt-provisioning`
- `X509`

**Confidence Level:**  
**High (85-90%)** when a file matches any of the two exact SHA256 hashes.  
**Medium-High (70-75%)** when only strings are matched (due to possible legitimate overlaps in Unisoc firmware).

