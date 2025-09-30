# Escaner-de-puertos-y-Sniffing
Herramienta en linux que realiza un escaneo de los puertos TCP y UDP hacia un objetivo definido por sniffing.

# Proyecto: Escáner híbrido de puertos y sniffing en C++

**Miembros del equipo:** 
- Eduardo Flores Smith | Encargado del modulo de Escaneo y del main
- CASAS CRUZ JORGE LUIS | Encargado del modulo de Sniffing
- FLORES PINAL ANDRES TADEO | Encargado del modulo para el formato JSON

## Descripción general
Herramienta en C++ para Linux que realiza:
- Escaneo real de puertos TCP y UDP (conect() no bloqueante para TCP, sendto() para UDP).
- Captura de la primera trama de respuesta por puerto abierto mediante `libpcap`.
- Generación de un informe JSON con servicios detectados y primeros bytes de cabecera.

## Estructura del proyecto
- `Escaneo.h / Escaneo.cpp` — módulo escaneo (TCP/UDP). 
- `Sniffer.h / Sniffer.cpp` — captura y filtrado con libpcap.
- `JSONGen.h / JSONGen.cpp` — serializa resultados a JSON (usa nlohmann/json).
- `main.cpp` — orquestación, concurrencia y sincronización.

## Requisitos
- Sistema operativo: Linux (Ubuntu/Debian recomendado).
- Compilador: g++ con soporte C++17.
- Dependencias:
  - `libpcap` (devel): `sudo apt install libpcap-dev`
  - `nlohmann/json` (header-only). Instalar por ejemplo: `sudo apt install nlohmann-json3-dev`
- Se recomienda ejecutarse en modo ROOT para que funcione de manera correcta.

## Compilación
g++ -std=c++17 main.cpp Escaneo.cpp Sniffer.cpp JSONGen.cpp -o scanner -lpcap -pthread
El programa pedirá interactivamente:

- **IP objetivo:** (ej. `127.0.1.1`)
- **Puertos:** Rango (`20-1024`) o lista separada por comas (`22,80,443`)
- **Timeout en ms:** (ej. `500`)
- **Archivo JSON de salida:** Nombre de archivo (ej. `resultado.json`)

---

## Lógica y Enfoque Técnico (Resumen)

### Módulo de Escaneo (`Escaneo.cpp`)

- **TCP:** Sockets no bloqueantes y `select()` para timeouts.
  - **Abierto:** Conexión establecida.
  - **Cerrado:** Respuesta RST.
  - **Filtrado:** Timeout sin respuesta.

- **UDP:** Envía datagrama vacío y marca estado provisional como `Filtrado/Cerrado`. El sniffer confirmará estado posteriormente.

- Para rendimiento, se usan hilos: por cada puerto se lanzan dos tareas (TCP y UDP) o un grupo de workers con una cola.

### Módulo de Sniffing (`Sniffer.cpp`)

- Usa `libpcap` y escucha en la interfaz `any` por defecto para capturar tráfico local y externo.
- Aplica un filtro BPF: `host <IP> and (tcp or udp or icmp)`.
- Reglas de interpretación UDP/ICMP:
  - Si se captura un paquete UDP proveniente del puerto objetivo → Puerto **Abierto**.
  - Si se captura ICMP "Port Unreachable" → Puerto **Cerrado**.
  - Si no se captura nada → **Filtrado/Cerrado**.
- Para cada puerto que responda, se guardan los primeros **16 bytes** de la cabecera en hexadecimal.

### Concurrencia

- El sniffer corre en su propio hilo y va informando al orquestador (cola o estructura compartida protegida por mutex) sobre respuestas observadas.
- El escaneo lanza hilos para las sondas (o usa un thread pool) y consulta el estado final en la estructura compartida.

---

## Formato JSON de Salida

El archivo contiene un array de objetos — cada objeto representa el resultado de un puerto.

Ejemplo (`resultado.json`):

```json
[
  {
    "header_bytes": "45 00 00 3C 00 00 40 00 40 06 3B BA 7F 00 01 01",
    "ip": "127.0.1.1",
    "port": 8080,
    "protocol": "TCP",
    "service": "",
    "state": "Abierto"
  },
  {
    "header_bytes": null,
    "ip": "127.0.1.1",
    "port": 80,
    "protocol": "UDP",
    "service": "",
    "state": "Cerrado"
  }
]
```

---


## Seguridad y Consideraciones Legales

- **Solo escanea hosts sobre los que tengas permiso explícito.** El escaneo de puertos y la captura de tráfico pueden considerarse intrusivos y, en muchos lugares, ilegales sin autorización.
- Evita ejecutar esta herramienta en redes corporativas o de terceros sin consentimiento.
---

## Contacto

Para dudas o mejoras, abre un issue en el repositorio o contacta al equipo del proyecto.
