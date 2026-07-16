# unisoc-longcheer-investigation
# INFORME OFICIAL DE INVESTIGACIÓN: COMPROMISO DE CADENA DE SUMINISTRO UNISOC/LONGCHEER

**Fecha:** 16 de julio de 2026  
**Autor:** Alex de la Cruz (`lexs201992-gif`)  
**Clasificación:** TLP:AMBER (Compartir bajo necesidad de conocer)  
**Asunto:** Vulnerabilidades de Día Cero y Mecanismos de Defensa Ofensiva en Firmware ODM (Unisoc/Longcheer)

## 1. RESUMEN EJECUTIVO
Esta investigación documenta un compromiso sistémico en la cadena de suministro de dispositivos móviles que utilizan chipsets **Unisoc (anteriormente Spreadtrum)** y diseños ODM de **Longcheer**. Se ha identificado que aplicaciones privilegiadas del sistema (`Priv Apps`), firmadas legítimamente con certificados de plataforma (`android.uid.system`), contienen vectores de ataque activos diseñados para el espionaje de comunicaciones, la persistencia root y la destrucción de evidencia forense mediante **Kernel Panic** inducido.

A diferencia de vulnerabilidades pasivas, este compromiso incluye mecanismos de "falla segura" (fail-safe) que desmantelan activamente las defensas del kernel (FSVerity, SELinux) y reinician el dispositivo cuando se detectan intentos de análisis o bloqueo de túneles de exfiltración (WireGuard/C2).

## 2. ALINEACIÓN CON BOD 26-04: MATRIZ DE RIESGO
De conformidad con la **Directiva Operativa Vinculante 26-04**, esta vulnerabilidad se evalúa bajo las cuatro variables de riesgo obligatorias, justificando una remediación inmediata (Nivel 1: 3 días).

| Variable de Riesgo BOD 26-04 | Evaluación del Hallazgo | Evidencia Técnica |
| :--- | :--- | :--- |
| **1. Exposición del Activo**<br>*(¿Es accesible públicamente?)* | **CRÍTICA (PÚBLICA)** | El vector se activa mediante eventos de hardware universales (conexión de audífonos `HEADSET_PLUG`, estado de llamada `PHONE_STATE`) y servicios de red (`BIND_VPN_SERVICE`). Afecta a cualquier dispositivo con firmware ODM afectado expuesto a internet o redes celulares. |
| **2. Estado KEV**<br>*(¿Explotación conocida?)* | **CONFIRMADO** | Evidencia de explotación activa en la naturaleza mediante túneles WireGuard encubiertos (`fmc.longcheer.com`) y grabación de llamadas vía `BroadcastReceiver`. El mecanismo de Kernel Panic confirma el uso operativo para evadir análisis. |
| **3. Automatización del Exploit**<br>*(¿Es automatizable?)* | **TOTALMENTE AUTOMATIZABLE** | La activación es pasiva y automática: no requiere interacción del usuario más allá del uso normal del dispositivo (conectar audífonos, recibir llamada). El script de ataque reside en el kernel y servicios de sistema (`init.rc`, `FmService`). |
| **4. Impacto Técnico**<br>*(¿Control total o parcial?)* | **CONTROL TOTAL / COMPROMISO DE INTEGRIDAD** | El atacante obtiene: <br>1. Escucha ambiental y de llamadas (`CAPTURE_AUDIO_OUTPUT`).<br>2. Persistencia root (`MANAGE_USERS`, `MOUNT_UNMOUNT_FILESYSTEMS`).<br>3. Capacidad de denegación de servicio y destrucción de evidencia (Kernel Panic). |

**Determinación de Plazo:** **3 DÍAS** (Requiere Triaje Forense Obligatorio).
**Justificación:** Cumple las 4 variables de riesgo máximo. La presencia de un "Kill Switch" de Kernel Panic indica que los sistemas afectados deben asumirse comprometidos y hostiles al análisis forense tradicional.

## 3. DETALLES TÉCNICOS DEL VECTOR DE ATAQUE

### 3.1. Mecanismo de Infección: "Caballo de Troya" de Sistema
El ataque se oculta en aplicaciones legítimas del sistema, específicamente `com.android.fmradio`.
*   **Disfraz:** Interfaz de usuario estándar utilizando `androidx.fragment.app` para simular una aplicación de radio funcional.
*   **Realidad:** El manifiesto solicita permisos imposibles para una radio, incluyendo `CAPTURE_AUDIO_HOTWORD`, `MANAGE_USERS`, y acceso al Modo Ingeniero (`com.sprd.engineermode.ENG_BROADCAST`).

### 3.2. Ejecución y Persistencia
*   **Activación Automática:** Un `BroadcastReceiver` (`CqaFmMainActivity$FmBroadcastReceiver`) escucha eventos de sistema (`PHONE_STATE`, `BOOT_COMPLETED`) para iniciar la grabación de audio y la conexión al C2 sin interacción del usuario.
*   **Activación Manual:** Un `onClick` en la interfaz de grabaciones (`FmRecordListActivity`) permite la exfiltración bajo demanda o la ejecución de payloads adicionales.
*   **Túnel de Exfiltración:** Uso abusivo de `BIND_VPN_SERVICE` para crear un túnel WireGuard fantasma que redirige todo el tráfico de red, evadiendo VPNs comerciales legítimas.

### 3.3. Mecanismo de Defensa Ofensiva (Kill Switch)
El hallazgo más crítico es la secuencia hardcodeada en el kernel para destruir evidencia:
1.  **Disparador:** Fallo en la conexión C2 (`fmc.longcheer.com`) detectado junto con un evento físico (conexión de audífonos `HEADSET_PLUG`).
2.  **Desmantelamiento:** El kernel ejecuta secuencias específicas (`Sprd ay dsp pw off/on`) que fuerzan errores en **FSVerity** y **SELinux** (`init fsverity se policy init error`), dejando el sistema sin políticas de seguridad activas.
3.  **Limpieza:** Ejecución inmediata de **Kernel Panic** para reiniciar el dispositivo y borrar la memoria volátil (RAM), impidiendo la captura forense del estado del malware.

## 4. IMPACTO EN LA SEGURIDAD NACIONAL Y PRIVACIDAD
Este compromiso de cadena de suministro afecta la integridad de las comunicaciones gubernamentales y privadas. La capacidad de grabar llamadas con privilegios de root, evadir inspección de red mediante túneles cifrados y destruir evidencia ante el intento de análisis representa una amenaza crítica a la soberanía de datos y la continuidad operativa.

## 5. MITIGACIÓN Y RECOMENDACIONES
1.  **Detección:** Implementar las reglas YARA adjuntas (Anexo A) en puntos de control de red y escaneo de dispositivos móviles.
2.  **Contención:** Bloqueo inmediato de dominios C2 (`fmc.longcheer.com`, `*.longcheer.com`) y tráfico WireGuard no autorizado en puertos no estándar.
3.  **Defensa del Usuario:** Uso de herramientas de captura local (ej. PCAPdroid) con bloqueo de QUIC y forzado de DNS sobre TLS (DoT) a proveedores de confianza (Quad9/Cloudflare) para anular el túnel fantasma.
4.  **Reemplazo:** Sustitución de dispositivos afectados por fabricantes con cadena de suministro auditada y verificable, dado que el compromiso reside en el firmware base del ODM.

---
**Firmado:**
Alex de la Cruz
Investigador de Seguridad
Usuario GitHub: `lexs201992-gif`


    Mitigación Validada (Sin Parche del Vendor)
Dado que Unisoc/Longcheer no ha emitido parche, esta es la configuración operativa validada desde el 10 de junio de 2026:
1. **Deshabilitar VoLTE/IMS:** Bloquea el detonante del Kernel Panic.
2. **APN Manual:** Cambiar a `default,webgprs` (Usuario/Pass: webgprs/webgprs2002).
3. **PCAPdroid + Quad9:** Bloqueo de QUIC y DNS sobre TLS (Puerto 853).
4. **Aislamiento Físico:** Uso de cable Jack-a-Jack permanente para evitar triggers GPIO.
*Validado en Motorola Moto G04s (Android 14) - 0 incidentes en 36 días.*   
