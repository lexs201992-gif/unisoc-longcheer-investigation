/**
 * UNISOC/LONGCHEER SUPPLY CHAIN INVESTIGATION
 * Author: Alex de la Cruz (lexs201992-gif)
 * Date: 2026-07-16
 * Context: BOD 26-04 Critical Submission
 */

import "hash"
import "pe"

// Regla 1: Detección de Spyware en Manifiesto (Nivel Alto)
rule Unisoc_FakeFM_Radio_Spyware {
    meta:
        description = "Detects malicious system app disguised as FM Radio with spyware capabilities"
        author = "lexs201992-gif"
        date = "2026-07-16"
        severity = "CRITICAL"
        reference = "github.com/lexs201992-gif/unisoc-longcheer-investigation"
    
    strings:
        $perm_audio_out = "android.permission.CAPTURE_AUDIO_OUTPUT" ascii wide
        $perm_hotword = "android.permission.CAPTURE_AUDIO_HOTWORD" ascii wide
        $perm_bg_service = "android.permission.START_FOREGROUND_SERVICES_FROM_BACKGROUND" ascii wide
        $perm_manage_users = "android.permission.MANAGE_USERS" ascii wide
        $perm_eng_mode = "com.sprd.engineermode.ENG_BROADCAST" ascii wide
        $pkg_fake = "com.android.fmradio" ascii wide

    condition:
        $pkg_fake and 
        ( ($perm_audio_out and $perm_hotword) or ($perm_bg_service and $perm_manage_users) or ($perm_eng_mode) )
}

// Regla 2: Detección del Gatillo de Espionaje (Nivel Smali)
rule Unisoc_CQA_Broadcast_Spy_Trigger {
    meta:
        description = "Detects malicious BroadcastReceiver triggering call recording"
        author = "lexs201992-gif"
        date = "2026-07-16"
        severity = "CRITICAL"
    
    strings:
        $broadcast_receiver = "Landroid/content/BroadcastReceiver;" ascii wide
        $on_receive = "onReceive(Landroid/content/Context;Landroid/content/Intent;)V" ascii wide
        $intent_call_state = "android.intent.action.PHONE_STATE" ascii wide
        $media_recorder = "Landroid/media/MediaRecorder;" ascii wide
        $audio_source_voice = "VOICE_CALL" ascii wide
        $cqa_class = "CqaFmMainActivity" ascii wide

    condition:
        ( $broadcast_receiver and $on_receive ) and 
        ( ($intent_call_state or $cqa_class) and ($media_recorder or $audio_source_voice) )
}

// Regla 3: Detección de Abuso de Servicio VPN (Activada y Corregida)
rule Unisoc_Longcheer_VPN_Service_Abuse {
    meta:
        description = "Detects Privileged Apps abusing BIND_VPN_SERVICE to establish covert WireGuard/System tunnels"
        author = "lexs201992-gif"
        date = "2026-07-16"
        severity = "CRITICAL"
        reference = "Addendum 82-F / VPN Service Hijack Vector"
        technique = "Detection of VpnService.Builder and WireGuard initialization in Privileged Context"
    
    strings:
        // 1. Llamadas críticas a la API de VPN de Android
        $vpn_service_builder = "Landroid/net/VpnService$Builder;" ascii wide
        $vpn_add_route = "addRoute" ascii wide
        $vpn_add_dns = "addDnsServer" ascii wide
        $vpn_establish = "establish" ascii wide
        
        // 2. Cadenas específicas de WireGuard o Túneles
        $wg_interface = "wg0" ascii wide
        $wg_config = "[Interface]" ascii wide
        $wg_private_key = "PrivateKey" ascii wide
        $tunnel_svc = "TunnelService" ascii wide
        
        // 3. Invocaciones de permisos privilegiados
        $bind_vpn_perm = "android.permission.BIND_VPN_SERVICE" ascii wide
        $network_stack = "Landroid/net/ConnectivityManager;" ascii wide
        $set_global_proxy = "setGlobalProxy" ascii wide
        
        // 4. Patrones Hex de invocación (OpCodes Dalvik)
        $dalvik_vpn_establish = { 6E ?? ?? ?? ?? ?? } "establish" ascii wide

    condition:
        // Lógica de Detección:
        ( $vpn_service_builder and $vpn_establish )
        or 
        ( $bind_vpn_perm and ( $vpn_add_dns or $vpn_add_route ) )
        or 
        ( $wg_config and $wg_private_key )
}   // ---------------------------------------------------------------------------
// SECCIÓN 2: DETECCIÓN DE CERTIFICADOS Y FIRMA DE CADENA DE SUMINISTRO
// ---------------------------------------------------------------------------

rule Longcheer_Root_CA_Certificate {
    meta:
        description = "Detects the compromised Longcheer Root CA certificate installed in Unisoc T606/T616 supply chain"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "CRITICAL"
        cve = "CVE-2026-40003"
        reference = "Addendum 82-D: Certificate Forensics"
        issuer = "CN=Longcheer, O=Longcheer, C=CN"
        validity_end = "2051-01-31"
    
    strings:
        // Certificate Subject/Issuer Strings
        $issuer_cn = "CN=Longcheer" ascii
        $issuer_o = "O=Longcheer" ascii
        $issuer_email = "release@Longcheer.com" ascii
        $issuer_loc = "L=ShangHai" ascii
        
        // Validity Date Strings (DER/ASCII representation)
        $valid_from = "Sep 15 07:31:06 2023 GMT" ascii
        $valid_to = "Jan 31 07:31:06 2051 GMT" ascii
        
        // Public Key Exponent (Common RSA 65537)
        $rsa_exponent = { 01 00 01 }
        
        // Specific Modulus Bytes (Unique fingerprint of the public key)
        $modulus_start = { d6 0f bb 9d 0f bb a8 05 8e 66 f2 68 c8 38 bc 05 }
        $modulus_end = { 5e af a2 f2 c3 5a 32 ea 56 83 7e f0 19 12 2c 87 6d }

        // X509v3 Subject Key Identifier (Unique to this cert)
        $key_id = { 97 B6 E1 F1 B2 AC DB DA 80 5C 56 B0 4E 82 D0 52 83 3C 8F 7B }

    condition:
        // Detect if key identifiers are present
        (all of ($issuer_cn, $issuer_o, $valid_to)) and 
        $key_id and
        $modulus_start and
        $modulus_end
}

rule Longcheer_Certificate_Serial_Number {
    meta:
        description = "Detects the specific serial number of the compromised Longcheer CA certificate"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "CRITICAL"
        serial_hex = "22:85:26:b0:d1:ef:90:c3:b8:ed:56:8a:49:c3:71:4f:6a:39:50:6b"
        reference = "Addendum 82-D"
    
    strings:
        // Full Serial Number in Hex (Big Endian DER encoding)
        $serial_full = { 22 85 26 b0 d1 ef 90 c3 b8 ed 56 8a 49 c3 71 4f 6a 39 50 6b }
        
        // Partial Serial Matches (for fragmented memory or logs)
        $serial_start = { 22 85 26 b0 d1 ef 90 c3 }
        $serial_end = { 49 c3 71 4f 6a 39 50 6b }
        
        // ASCII representation often found in logs or text configs
        $serial_ascii = "228526B0D1EF90C3B8ED568A49C3714F6A39506B" ascii
        $serial_ascii_lower = "228526b0d1ef90c3b8ed568a49c3714f6a39506b" ascii

    condition:
        $serial_full or 
        (all of ($serial_start, $serial_end)) or 
        $serial_ascii or 
        $serial_ascii_lower
}

rule Unisoc_Longcheer_Firmware_Signature {
    meta:
        description = "Universal rule to identify any firmware or APK signed by the compromised Longcheer CA on Unisoc devices"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "HIGH"
        target = "Unisoc T606/T616, Longcheer ODM"
        reference = "Operation Silent Rescue"
    
    strings:
        // Reference to Longcheer in package names or strings
        $longcheer_pkg = "com.longcheer" ascii nocase
        $longcheer_str = "Longcheer" ascii
        
        // Unisoc/Spreadtrum specific strings
        $unisoc_str = "Unisoc" ascii
        $spreadtrum_str = "Spreadtrum" ascii
        $sprd_pkg = "com.spreadtrum" ascii
        
        // Certificate Chain Markers (PKCS#7 / CMS)
        $pkcs7_oid = { 2A 86 48 86 F7 0D 01 07 02 } 
        $x509_seq = { 30 82 } 

        // Specific permissions linked to Longcheer builds
        $perm_ims = "com.spreadtrum.ims.permisson.IMS_COMMON" ascii
        $perm_stk = "android.permission.RECEIVE_STK_COMMANDS" ascii

    condition:
        (any of ($longcheer_pkg, $longcheer_str)) and 
        (any of ($unisoc_str, $spreadtrum_str, $sprd_pkg, $perm_ims, $perm_stk)) and
        (any of ($pkcs7_oid, $x509_seq))
}

rule Operation_Silent_Rescue_Composite_Indicator {
    meta:
        description = "Composite rule detecting the intersection of Longcheer CA, Unisoc OMA CP, and Motorola Adapter Service"
        author = "lexs201992-gif"
        date = "2026-07-10"
        severity = "CRITICAL"
        campaign = "Operation Silent Rescue"
    
    strings:
        // Longcheer Component
        $lc_cert = "CN=Longcheer" ascii
        $lc_serial = "228526B0D1EF90C3" ascii
        
        // Unisoc OMA CP Component
        $omacp_pkg = "com.sprd.omacp" ascii
        $omacp_class = "OtaConfigFactory" ascii
        
        // Motorola Component
        $moto_pkg = "com.motorola.enterprise.adapter.service" ascii
        $moto_domain = "notification.sandclowd.com" ascii
        
        // Attack Artifacts
        $wap_push = "WAP Push" ascii
        $oma_cp = "application/vnd.wap.connman-cp" ascii

    condition:
        // High confidence if Longcheer cert is found with OMA CP and Motorola components
        $lc_cert and 
        $omacp_pkg and 
        $moto_pkg and
        (any of ($moto_domain, $wap_push, $oma_cp))
}   
