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
- Ejecutar como **root** o con permisos para abrir pcap en modo promiscuo y enviar sockets raw si aplica.

## Compilación
g++ -std=c++17 main.cpp Escaneo.cpp Sniffer.cpp JSONGen.cpp -o scanner -lpcap -pthread

