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

// Agrega aquí el resto de tus reglas (Kernel Panic, VPN Abuse, etc.)   
