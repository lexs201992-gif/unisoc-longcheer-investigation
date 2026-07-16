# 📄 SECCIÓN ADICIONAL PARA EL INFORME: MITIGACIÓN OPERATIVA VALIDADA

**Título:** Validación de Contramedidas en Entorno Hostil (Caso: Motorola Moto G04s)
**Investigador:** Alex de la Cruz (`lexs201992-gif`)
**Periodo de Validación:** 10 de junio de 2026 – 16 de julio de 2026 (36 días sin incidentes)

### 1. Confirmación del Vector de Ataque
La estabilidad del dispositivo depende estrictamente de la interrupción de la cadena de activación del *Kernel Panic*. Se confirmó que el ataque requiere la convergencia de tres factores:
1.  **Activador IMS:** El servicio VoLTE de Spreadtrum (`com.spreadtrum.ims`) actuando como orquestador.
2.  **Canal de Exfiltración:** El túnel WireGuard/FMC fallando al conectar con el C2.
3.  **Disparador Físico/Lógico:** La conexión de audífonos (Jack) o el reinicio del dispositivo mientras los servicios privilegiados están activos.

### 2. Contramedidas Implementadas (Éxito Total)
La siguiente configuración ha demostrado ser efectiva para neutralizar el *Kill Switch* del ODM:

*   **A. Neutralización del IMS (Crítico):**
    *   **Acción:** Deshabilitación de VoLTE.
    *   **Método:** Uso de `App Manager` para revocar *AppOps* críticos o deshabilitar el paquete IMS.
    *   **Resultado:** Sin señal IMS, el detonante del *Kernel Panic` no se arma, incluso ante reinicios.

*   **B. Manipulación del APN (Evitación de Túnel):**
    *   **Acción:** Cambio del APN predeterminado de Telcel.
    *   **Configuración:** Modificación de `default,supl` a `default,webgprs` (Usuario: `webgprs`, Pass: `webgprs2002`, Aut: PAP).
    *   **Resultado:** Se fuerza al módem a usar una ruta de datos legacy que el script de exfiltración WireGuard no reconoce o no puede secuestrar eficazmente, rompiendo la condición de "fallo de túnel" que dispara el panic.

*   **C. Defensa de Red Local (PCAPdroid):**
    *   **Acción:** Túnel local con bloqueo estricto.
    *   **Configuración:** Bloqueo de protocolo **QUIC** (UDP/443) + Forzado de **DNS sobre TLS (DoT)** a **Quad9 (9.9.9.9)** en puerto 853.
    *   **Resultado:** Se evita la resolución de dominios C2 (`fmc.longcheer.com`) y se bloquea la exfiltración rápida por UDP, obligando al tráfico a canales TLS inspeccionables o bloqueados.

*   **D. Aislamiento Físico (Jack de Audio):**
    *   **Acción:** Uso de cable **Jack-a-Jack** (o conexión permanente de audífonos).
    *   **Lógica:** Mantiene el estado del GPIO del headset en "activo" (o inactivo constante), evitando el *flanco de subida* (`HEADSET_PLUG`) que el kernel monitorea para ejecutar la secuencia `Sprd ay dsp pw off/on`.

### 3. Conclusión de la Mitigación
El dispositivo se mantiene operativo y libre de *Rescue Party* únicamente bajo estas condiciones. Cualquier intento de restablecer la configuración de fábrica o reactivar VoLTE resulta en el reinicio inmediato del ciclo de ataque, confirmando la persistencia del malware en particiones protegidas del firmware.
