# CoAP-EAP-v12

Este repositorio contiene la implementación de la última versión (versión 12) del Internet Draft "EAP-based Authentication Service for CoAP" en Python. Para la implementación de CoAP-EAP se ha empleado el modelo pass-through de su arquitectura, caracterizado por la separación de roles, la externalización de la autenticación y la interacción entre tres elementos principales:

- **EAP Peer** → Dispositivo IoT que va a ser autenticado.
- **EAP Authenticator** → Administrador del dominio de seguridad al que se va a unir el EAP Peer. Actúa como intermediario entre el EAP Peer y el EAP Server.
- **EAP Server** → Contiene la lógica para completar la autenticación del dispositivo IoT utilizando el método EAP más adecuado en función de sus características. En este caso se va a utilizar el método **EAP-PSK**.

En esta implementación, el **EAP Server** se instancia en una máquina virtual **Ubuntu** que utiliza **FreeRADIUS 2.0.2** para desarrollar en C un servidor RADIUS (**AAA Server/EAP Server**) con soporte para **EAP-PSK**, gracias a hostapd.

Con CoAP-EAP se espera proporcionar un mecanismo estándar de autenticación que pueda garantizar la seguridad en un entorno tan dinámico y limitado como el IoT, ayudando a conformar un futuro más seguro, interoperable y eficiente para este tipo de redes.

## Índice

1. [Introducción](#introduccion)
2. [Especificaciones de Implementación](#especificaciones-de-implementacion)
3. [Documentación de Referencia](#documentacion-de-referencia)
4. [Requisitos](#requisitos)
5. [Instrucciones de Instalación](#instrucciones-de-instalacion)
6. [Uso](#uso)
7. [Licencia](#licencia)
8. [Contribuciones](#contribuciones)
9. [Contacto](#contacto)

## Introducción

Este Internet Draft aborda el desafío del control de acceso para dispositivos IoT con recursos limitados, desarrollando un servicio de autenticación seguro y eficiente basado en el protocolo **EAP** (Extensible Authentication Protocol), transportado sobre mensajes del protocolo **CoAP** (Constrained Application Protocol). 

Más concretamente, este documento especifica cómo **CoAP** puede usarse como una **EAP lower layer** confiable, independiente de la capa de enlace y para entornos con restricciones. Esta **EAP lower layer** se llama **CoAP-EAP**.

El objetivo principal de **CoAP-EAP** es autenticar un dispositivo IoT habilitado para CoAP (**EAP Peer**) que pretende unirse a un dominio de seguridad gestionado por un Controlador (**EAP Authenticator**). Otro aspecto fundamental es que permite derivar el material criptográfico para proteger los mensajes CoAP intercambiados entre el **EAP Peer** y el **EAP Authenticator**, basándose en **OSCORE** (Object Security for Constrained RESTful Environments).

## Especificaciones de Implementación

La implementación cubre los siguientes aspectos del draft:

- **Integración de EAP con CoAP**: CoAP-EAP como EAP Lower Layer.
- **Negociación de cipher suite** mediante CBOR.
- **Soporte para EAP-PSK**, con generación de claves y canales protegidos.
- **Garantía de orden** en CoAP-EAP mediante URIs y HATEOAS.
- **Protección de mensajes con OSCORE**, incluyendo generación de Common Context, Sender Context y Recipient Context.
- **Cliente RADIUS en el EAP Authenticator**, para la comunicación con el EAP Server.
- **Descifrado de la MSK recibida del EAP Server** mediante MD5 y bloques iterativos.
- **Manejo de diferentes escenarios**, como autenticación fallida, retransmisión y eliminación del estado CoAP-EAP.

## Documentación de Referencia

El proyecto sigue varias especificaciones del IETF y documentos de Internet Draft:

- [RFC 7252](https://tools.ietf.org/html/rfc7252): The Constrained Application Protocol (CoAP).
- [RFC 3748](https://tools.ietf.org/html/rfc3748): Extensible Authentication Protocol (EAP).
- [RFC 4764](https://tools.ietf.org/html/rfc4764): EAP-PSK.
- [RFC 8613](https://tools.ietf.org/html/rfc8613): OSCORE.
- [RFC 2865](https://tools.ietf.org/html/rfc2865): RADIUS.
- [draft-ietf-ace-wg-coap-eap-12](https://datatracker.ietf.org/doc/draft-ietf-ace-wg-coap-eap/12/).

## Requisitos

Para ejecutar esta implementación de EAP sobre CoAP, asegúrate de tener:

- **Python 3.12**.
- **AAA Server** con **FreeRADIUS 2.0.2**.
- **Bibliotecas** detalladas en `requirements.txt`.

## Instrucciones de Instalación

1. Clonar este repositorio:
   ```bash
   git clone https://github.com/daniMGTeleco/CoAP-EAP-v12.git
   cd CoAP-EAP-v12
   ```
2. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```
3. Descargar la máquina virtual con el **EAP Server** desde [este enlace](https://unioviedo-my.sharepoint.com/:u:/g/personal/uo276425_uniovi_es/EZtMQZl93LxDjEpuAKc5piQB-dPKXL7xn5Bzkd_R5I4Fyw?e=AuiR8q).
4. Abrir la máquina virtual en **VMware Workstation 17 Player**.

## Uso

### Ejecución del servicio de autenticación

1. Iniciar el **EAP Server** en la máquina virtual:
   ```bash
   cd /home/student/freeradius-psk/sbin
   export LD_PRELOAD=/home/student/coap-eap-tfg/freeradius-2.0.2-psk/hostapd/eap_example/libeap.so
   ./radiusd -X
   ```
2. Capturar tráfico en **Wireshark** con el filtro:
   ```
   coap or radius
   ```
3. En la máquina host, ejecutar los scripts:
   ```bash
   python controller.py 
   python peer.py
   ```

## Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulte el archivo `LICENSE` para más detalles.

## Contribuciones

¡Las contribuciones son bienvenidas! Si deseas colaborar, por favor sigue estos pasos:

1. Haz un **fork** del repositorio.
2. Crea una rama con tu nueva funcionalidad o corrección de errores: `git checkout -b feature-nueva-funcionalidad`.
3. Realiza tus cambios y haz un commit: `git commit -m "Descripción de los cambios"`.
4. Sube la rama: `git push origin feature-nueva-funcionalidad`.
5. Abre un **Pull Request** en GitHub.

## Contacto

Si tienes alguna duda o sugerencia, puedes contactar a través de:

- **GitHub**: [daniMGTeleco](https://github.com/daniMGTeleco)
- **Correo electrónico**: [tuemail@ejemplo.com](mailto:tuemail@ejemplo.com)
