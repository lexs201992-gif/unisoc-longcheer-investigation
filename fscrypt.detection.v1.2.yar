rule Unisoc_Silent_Rescue_BootROM_T606_fscrypt 
{
    meta:
        description = "Detects Unisoc T606 Silent Rescue - modified init.rc + fscrypt X.509 provisioning bypass"
        author = "lexs17"
        date = "2026-07-20"
        version = "1.2"
        reference = "Operation Silent Rescue - Unisoc T606"
        vt_init_rc = "f1843ab9df2245d5920c5764732cfee2f1a3092f71b319a965bc695938593e3e"
        vt_x509_pem = "7bfdbbd2ac2a62021946f1d47b6b2e2d22ede0b41bf92535c9d8cde6cb38e9da"

    strings:
        $lcd_trigger   = "lcd_td4160" ascii
        $mailbox       = "Unisoc_mailbox" ascii
        $partition     = "sda48" ascii
        $fscrypt_prov  = "fscrypt provisioning" ascii
        $fscrypt_key   = "fscrypt-provisioning" ascii
        $x509          = "X509" nocase ascii
        $kpti          = "kpti=0" ascii
        $ramdisk       = "root=/dev/ram0 rw" ascii

    condition:
        // Detección directa por hashes (alta precisión)
        hash.sha256(0, filesize) == "f1843ab9df2245d5920c5764732cfee2f1a3092f71b319a965bc695938593e3e" or
        hash.sha256(0, filesize) == "7bfdbbd2ac2a62021946f1d47b6b2e2d22ede0b41bf92535c9d8cde6cb38e9da"
        or
        // Detección por strings (para variantes)
        (any of ($kpti, $ramdisk)) and
        (any of ($lcd_trigger, $mailbox, $partition)) and
        (any of ($fscrypt_prov, $fscrypt_key)) and
        $x509
}
