rule Unisoc_Bluetooth_Kernel_Panic_Trigger {
    meta:
        description = "Detects the specific Kernel Panic sequence induced by Bluetooth/HCI driver manipulation in Unisoc T606/T616 firmware"
        author = "lexs201992-gif"
        date = "2026-07-17"
        severity = "CRITICAL"
        reference = "Final Forensic Report: Unisoc/Longcheer Supply Chain"
        technique = "Kernel Log Sequence Detection / Anti-Forensic Trigger"
        note = "Detecta la secuencia de inicialización de Bluetooth que precede al Panic y la activación de ramoops para borrado de evidencia."

    strings:
        // 1. Secuencia de Inicialización de Bluetooth (El Gatillo)
        $bt_core_init = "Bluetooth: core ver" ascii
        $bt_pf_proto = "PF_BLUETOOTH protocol" ascii
        $bt_hci_dev = "HCI device and connection manager initialized" ascii
        $bt_hci_socket = "Bluetooth: HCI socket layer initialized" ascii
        $bt_sco_socket = "Bluetooth: SCO socket layer initialized" ascii
        
        // 2. Activación de Mecanismos de Persistencia/Panic (La Trampa)
        $ramoops_enable = "console-ramoops-1: enabled" ascii
        $ramoops_persistent = "ramoops: using" ascii // O "persistent store backend"
        $edac_init = "EDAC MC: ver:" ascii
        
        // 3. Cadenas Específicas de Versión y Copyright (La Firma del Compromiso)
        // Estas cadenas fijan la versión del kernel comprometido
        $giometti_copyright = "Rodolfo Giometti" ascii
        $giometti_email = "giometti@linux.it" ascii
        $ptp_clock = "PTP clock support registered" ascii
        $media_policy = "Linux media interface: v0.10" ascii
        $software_ver = "Software Version: 5.36" ascii // O la versión específica que viste
        $copyright_years = "2005-2022" ascii

        // 4. Contexto de Error Crítico (El Resultado)
        $kernel_panic_str = "Kernel panic" ascii
        $invalid_policy = "invalid policy" ascii

    condition:
        // Lógica de Detección:
        // Debe tener la secuencia de Bluetooth Y la activación de ramoops Y las cadenas de copyright específicas
        
        (all of ($bt_core_init, $bt_hci_dev, $bt_hci_socket)) and
        ($ramoops_enable) and
        (all of ($giometti_copyright, $ptp_clock)) and
        (
            // Opción A: Secuencia completa de inicio + Panic
            ($kernel_panic_str)
            
            // Opción B: Solo la secuencia de inicialización específica (indicador de alto riesgo)
            or (all of ($media_policy, $software_ver, $copyright_years))
        )
}   
