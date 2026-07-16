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

// rule Unisoc_Longcheer_VPN_Service_Abuse {
    meta:
        description = "Detects Privileged Apps abusing BIND_VPN_SERVICE to establish covert WireGuard/System tunnels"
        author = "lexs201992-gif"
        date = "2026-07-16"
        severity = "CRITICAL"
        reference = "Addendum 82-F / VPN Service Hijack Vector"
        technique = "Detection of VpnService.Builder and WireGuard initialization in Privileged Context"
    
    strings:
        // 1. Llamadas críticas a la API de VPN de Android (No ofuscables funcionalmente)
        $vpn_service_builder = "Landroid/net/VpnService$Builder;" ascii wide
        $vpn_add_route = "addRoute" ascii wide
        $vpn_add_dns = "addDnsServer" ascii wide
        $vpn_establish = "establish" ascii wide
        
        // 2. Cadenas específicas de WireGuard o Túneles (Incluso si la librería es nativa, la carga se referencia)
        $wg_interface = "wg0" ascii wide
        $wg_config = "[Interface]" ascii wide
        $wg_private_key = "PrivateKey" ascii wide
        $tunnel_svc = "TunnelService" ascii wide
        
        // 3. Invocaciones de permisos privilegiados (El "gatillo" del abuso)
        $bind_vpn_perm = "android.permission.BIND_VPN_SERVICE" ascii wide
        $network_stack = "Landroid/net/ConnectivityManager;" ascii wide
        $set_global_proxy = "setGlobalProxy" ascii wide
        
        // 4. Patrones Hex de invocación (OpCodes Dalvik para llamadas a métodos VPN)
        // invoke-virtual {v0}, Landroid/net/VpnService$Builder;->establish()
        $dalvik_vpn_establish = { 6E ?? ?? ?? ?? ?? } "establish" ascii wide

    condition:
        // Lógica de Detección:
        // Debe construir una VPN (Builder) Y establecerla (establish) O configurar rutas DNS
        ( $vpn_service_builder and $vpn_establish )
        
        // O debe tener el permiso Y configurar servidores DNS/Rutas (Típico de túneles C2)
        or ( $bind_vpn_perm and ( $vpn_add_dns or $vpn_add_route ) )
        
        // O referencia directa a configuración WireGuard en una App de Sistema
        or ( $wg_config and $wg_private_key )
})   
