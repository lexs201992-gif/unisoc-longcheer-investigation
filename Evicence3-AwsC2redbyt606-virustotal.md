
### EVIDENCIA 3 - Unión de Redes a Graphs de APKs de Sistema Moto G04s T606 MX 2025-2026

*Dispositivo:* Motorola Moto G04s - Unisoc T606 (Longcheer ODM) - Firmware LATAM MX Retail 2025-2026  
*Investigador:* Alex992 - Cancún, MX - Análisis papel/lápiz + VirusTotal Graph  
*Graph Público:* `virustotal.com/graph/g3e342c3c22114272a0be56b` - 5:11 AM 36% - 0/8 Filtered Nodes  
*Estado VT:* `0/92 Undetected` - First Seen 2024-07-12 / Last Seen 2026-07-07 - Submissions 7

#### 1. Hallazgo en Sistema
`/vendor/etc/init` contiene 120+ servicios con fecha fake `Dec 31, 2008` nunca auditados en gama media-baja:
- `init.md.rc 50.37 kB` (control de módem/baseband)
- `unisoc.rild.rc, vendor.sprd.gnss-default.rc, connmgr@1.0-service.rc, wcn_chr.rc, yloglite.rc`
- `ai_engine-default.rc 364B + android.hardware.neuralnetworks@aidl-service-armnn-gpu.rc + autotest.rc 1.33kB` - NPU para experimentación AI en real time con robots en armadora

`/vendor/etc/selinux/vendor_mac_permissions.xml`:
<signer signature="3082040f308202f7a0030201020214228526b0d1ef90c3b8ed568a49c3714f6a395..." seinfo="platform" />
`x509 platform` con caducidad *2051*. Cualquier apk firmada con esa key corre como `system` con `BIND_VPN_SERVICE`, `SYSTEM_ALERT_WINDOW`.

#### 2. Método de Autopista
1. Priv-app legacy con `platform` levanta `VpnService.Builder().addDnsServer().establish()` -> `tun0`
2. Inserta `WireGuard [Interface] PrivateKey` -> `wg0`
3. Handshake a `notification.sandclowd.com` con cert `Amazon RSA 2048 MIIE` -> `us-east-1 Virginia` (no bloqueable)
4. Usa `Passpoint / Hotspot 2.0 + captive portal` (`network-default.rc`) para inyectar `CA VPN`
5. Gusano en módem `init.md.rc` ancla redes conectadas
6. Tráfico `QUIC 443/UDP` en real time: `US Virginia -> MX -> Sudamérica / África / Oceanía -> DE Hetzner GmbH / TR -> IN -> Shenzhen/Shanghai Kubernetes`

YARA ancla: `$cert_amazon = "Amazon RSA 2048" + $conn = "notification.sandclowd.com" + $establish = "6E ?? ?? ?? ?? ??"`

#### 3. Unión de Redes en VirusTotal Graph
Este T606 es el que generó *100 graphs + 20 collections + 100+ IOCs* en cuenta `alexis de la cruz Alex992`.

Nodos anclados en `g3e342c` (imagen adjunta 5:11):
- `AW-17486212937` - artefacto AWS
- `www.codex.com` + `https://openai.com/policies` - Codex/OpenAI
- `AUTOMODiFRY.EXE` + `redemer trabajo` + `got any more log's brah` - Builder Longcheer
- `mcp.example.com/server/mcp` - MCP Edge AI
- `Microsoft Entra + Viruses + T2tech CLab C2Labs`
- `GOOGLEEDGEAI.ONMICROSOFT.COM` - *Google Edge AI hosteado en Microsoft - Primera unión Google+Microsoft en un mismo graph de amenaza*

¿Por qué `0/92`? Porque es infra `cryo` privada. Dataset no existe en internet. Oriente privatizó los datos. La AI de occidente no tiene de dónde aprender si todo vive en `init.rc 2008` que nadie lee. Mi método papel/lápiz desde abril con `qogirl + rescue party` lo extrajo.

#### 4. Impacto
Estimado `700-900M` dispositivos desde 2015 con este método:
- Era `SC9863A` (2015-2020) ∼400M
- Era `T606/T616/T618` (2021-2026) ∼350M
- ODM Big 3: Huaqin, Longcheer, Wingtech = 76% mercado ODM global. Unisoc shippeó 8.8M solo en 2021 (+10312% YoY) y 4.1M en Q3 2021.

Todo firmware LATAM sin auditar `xml` ni `priv-apps` permite `1000 apps legacy`. Esto explica el hallazgo de `Microsoft 365 Calendar 2050 Paid Version` - usan eventos lejanos `2050` como dead drop, misma técnica que cert `2051` y fecha `2008`.

*Conclusión:* Un Moto de $89 de Coppel concentra la autopista que une AWS Virginia, Hetzner, Turquía, India y Shenzhen. La evidencia es pública en VirusTotal (Google). Cualquiera puede analizarla.

`Your Security Is First - MX Research - 2025-2026`

## 📸 Photo Evidence

Real screenshots documenting this investigation are collected in the [`evidence-photos/`](evidence-photos/) folder.

| Screenshot | Description |
|---|---|
| ![PCAPdroid capture](evidence-photos/pcapdroid-capture.jpg) | **PCAPdroid capture** — 1.1 GB / 12,972 connections on `Mega_2.4G_93A1` |
| ![VirusTotal graph g3e342c](evidence-photos/virustotal-graph-g3e342c.jpg) | **VirusTotal graph g3e342c** — 0/92 undetected; nodes: `AW-17486212937`, `AUTOMODiFRY.EXE`, `GOOGLEEDGEAI.ONMICROSOFT.COM` |
| ![GitHub Actions Copilot run #8](evidence-photos/github-actions-copilot-run8.jpg) | **GitHub Actions Copilot cloud agent run #8** — ✅ succeeded |

> Placeholder images are currently shown. They will be replaced with real screenshots after merge. See [`evidence-photos/README.md`](evidence-photos/README.md) for full descriptions.<img width="720" height="1612" alt="1000063010" src="https://github.com/user-attachments/assets/05567111-2f12-4a54-ad1c-f5ea74b80b10" />
<img width="720" height="1612" alt="1000063012" src="https://github.com/user-attachments/assets/5e41af78-4556-4318-afa3-b661646656a2" />
<img width="714" height="1599" alt="1000063041" src="https://github.com/user-attachments/assets/e168457c-2448-4cfa-8fe7-ac7c7803a1d1" />
<img width="714" height="1599" alt="1000063038" src="https://github.com/user-attachments/assets/68230d52-4901-4ded-841b-51c5964886b1" />
<img width="714" height="1599" alt="1000063037" src="https://github.com/user-attachments/assets/efd4ee57-98ba-42fd-aa67-924211979362" />
<img width="714" height="1599" alt="1000063039" src="https://github.com/user-attachments/assets/04a6384a-a0e8-4702-ac95-d311cae54b24" />
<img width="714" height="1599" alt="1000063040" src="https://github.com/user-attachments/assets/4da05750-2eff-41cc-9d03-f77ffe39c951" />
<img width="714" height="1599" alt="1000063045" src="https://github.com/user-attachments/assets/7dfc21e5-91c5-485a-9d54-c72cfb8310b4" />
<img width="714" height="1599" alt="1000063046" src="https://github.com/user-attachments/assets/e29f0305-c2e4-4e23-b62a-a8b719c862a5" />
<img width="714" height="1599" alt="1000063047" src="https://github.com/user-attachments/assets/fc0f78a1-31d8-41a5-a05c-2cb6d477bf82" />
<img width="714" height="1599" alt="1000063048" src="https://github.com/user-attachments/assets/9c2f3a65-4eeb-47d0-b7e5-491757823c85" />
<img width="714" height="1599" alt="1000063049" src="https://github.com/user-attachments/assets/8ffdfc45-dacb-4dc5-ad62-9c33fb6ebe38" />
<img width="720" height="1612" alt="1000063028" src="https://github.com/user-attachments/assets/93b19d4b-1689-40b3-8bbc-2fee307d643e" />
<img width="720" height="1612" alt="1000063027" src="https://github.com/user-attachments/assets/54144f45-199a-4bfe-b769-a0416dc57a63" />
<img width="720" height="1612" alt="1000063012" src="https://github.com/user-attachments/assets/8c9e1b46-7211-4f20-9057-47e4bb2d6fa7" />
<img width="720" height="1612" alt="1000063011" src="https://github.com/user-attachments/assets/82053f93-c0d2-447d-81fb-7eb9937402db" />
