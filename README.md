# CoAP-EAP-v12

Este repositorio contiene la implementación de la última versión (versión 12) del Internet Draft "EAP-based Authentication Service for CoAP" en Python. Para la implementación de CoAP-EAP se ha empleado el modelo pass-through de su arquitectura, caracterizado por la separación de roles, la externalización de la autenticación y la interacción entre tres elementos principales:

- **EAP Peer** → Dispositivo IoT que va a ser autenticado.
- **EAP Authenticator** → Administrador del dominio de seguridad al que se va a unir el EAP Peer. Actúa como intermediario entre el EAP Peer y el EAP Server.
- **EAP Server** → Contiene la lógica para completar la autenticación del dispositivo IoT utilizando el método EAP más adecuado en función de sus características. En este caso se va a utilizar el método **EAP-PSK**.

En esta implementación, el EAP Server se instancia en una máquina virtual **Ubuntu** que utiliza **FreeRADIUS 2.0.2** para desarrollar en C un servidor RADIUS (AAA Server/EAP Server) con soporte para EAP-PSK (parte del servidor del método EAP-PSK), gracias a **hostapd**.

Con CoAP-EAP se espera proporcionar un mecanismo estándar de autenticación que pueda garantizar la seguridad en un entorno tan dinámico y limitado como el IoT, ayudando a conformar un futuro más seguro, interoperable y eficiente para este tipo de entornos.

## Índice

1. [Introducción](#introduccion)
2. [Especificaciones de Implementación](#especificaciones-de-implementacion)
3. [Documentación de Referencia](#documentacion-de-referencia)
4. [Requisitos](#requisitos)
5. [Instrucciones de Instalación](#instrucciones-de-instalacion)
6. [Uso](#uso)
7. [Reconocimientos](#reconocimientos)
8. [Licencia](#licencia)
9. [Contribuciones](#contribuciones)
10. [Contacto](#contacto)

## Introducción

Este Internet Draft aborda el desafío del control de acceso para dispositivos IoT con recursos limitados, desarrollando un servicio de autenticación seguro y eficiente basado en el protocolo **EAP** (Extensible Authentication Protocol), transportado sobre mensajes del protocolo **CoAP** (Constrained Application Protocol). Más concretamente, este documento especifica cómo CoAP puede usarse como una **EAP lower layer** confiable, independiente de la capa de enlace y para entornos con restricciones. Esta EAP lower layer se llama **CoAP-EAP**.

El objetivo principal de **CoAP-EAP** es autenticar un dispositivo IoT habilitado para CoAP (EAP Peer) que pretende unirse a un dominio de seguridad gestionado por un **Controlador** (EAP Authenticator). Otro aspecto fundamental es que permite derivar el material criptográfico para proteger los mensajes CoAP intercambiados entre el EAP Peer y el EAP Authenticator, basándose en **OSCORE** (Object Security for Constrained RESTful Environments).

## Especificaciones de Implementación

La implementación cubre los siguientes aspectos del draft:

- **Integración de EAP con CoAP**: Adaptación del protocolo EAP a CoAP para autenticación en redes IoT, CoAP-EAP como EAP Lower Layer.
- **Negociación de cipher suite**: Establecimiento de suites criptográficas mediante estructuras CBOR para el cifrado y autenticación de mensajes.
- **Soporte para EAP-PSK**: El protocolo EAP-PSK se utiliza como método de autenticación EAP en esta implementación. Este protocolo ofrece un enfoque seguro y eficiente, adecuado para dispositivos IoT. En la implementación se parsean y se generan los mensajes correspondientes, se hacen comprobaciones, se derivan todas las claves (de sesión y de larga duración) y se calculan campos, como la MAC_S o la MAC_P y los canales protegidos necesarios para el proceso de autenticación estándar. EAP-PSK es uno de los métodos más sencillos a nivel de configuración ya que sólo se requiere una clave precompartida (PSK) para autenticar a un dispositivo o usuario y su proceso de autenticación estándar consta de únicamente 4 mensajes.
- **Garantía de orden**: Mediante URIs, aplicando el principio de HATEOAS, en el contexto del protocolo CoAP-EAP.
- **Protección de mensajes con OSCORE**: Los mensajes CoAP con el mensaje EAP Success y con el código 2.04 Changed se protegen mediante OSCORE (Object Security for Constrained RESTful Environments), lo que permite una capa adicional de seguridad y privacidad. En la implementación se generan y configuran todos los parámetros necesarios para el contexto de seguridad de OSCORE, que incluye el Common Context, el Sender Context y el Recipient Context. También se incluye todo el proceso para la protección y desprotección o verificación de cada mensaje protegido con OSCORE. 
- **Cliente RADIUS integrado en el EAP Authenticator**: Desarrollo de un cliente RADIUS que permite la comunicación con el EAP Server. Este cliente RADIUS está diseñado para cumplir con los requisitos de autenticación EAP, generando todos los mensajes con los atributos requeridos para completar el proceso de autenticación y procesando todos los mensajes recibidos del EAP Server. La integración con RADIUS permite delegar el proceso de autenticación y autorización a un servidor centralizado, mejorando la escalabilidad y la administración del sistema de autenticación.
- **Descifrado de la MSK recibida del EAP Server**: Se ha implementado una función que descifre la MSK enviada por el EAP Server al EAP Authenticator en dos atributos RADIUS (MS-MPPE-Send-Key y MS-MPPE-Recv-Key). Para ello, se utiliza el secreto compartido RADIUS (Shared Secret) y un proceso basado en MD5 que genera bloques iterativos de descifrado. Una vez descifrada, la MSK sirve como base para derivar el contexto de seguridad OSCORE necesario para proteger las comunicaciones posteriores entre el EAP Peer y el Authenticator de manera 
segura y eficiente, garantizando la integridad y confidencialidad de los mensajes. 
- **Manejo de diferentes escenarios**: Autenticación exitosa ideal, petición duplicada o retransmisión tardía, autenticación fallida y eliminación del estado CoAP-EAP tras autenticación exitosa.

## Documentación de Referencia

El proyecto sigue varias especificaciones del IETF y documentos de Internet Draft:

- [RFC 7252](https://tools.ietf.org/html/rfc7252): The Constrained Application Protocol (CoAP).
- [RFC 3748](https://tools.ietf.org/html/rfc3748): Extensible Authentication Protocol (EAP).
- [RFC 4764](https://tools.ietf.org/html/rfc4764): EAP-PSK.
- [RFC 8613](https://tools.ietf.org/html/rfc8613): OSCORE.
- [RFC 2865](https://tools.ietf.org/html/rfc2865): RADIUS.
- [draft-ietf-ace-wg-coap-eap-12](https://datatracker.ietf.org/doc/draft-ietf-ace-wg-coap-eap/12/): Última versión del Internet Draft EAP-based Authentication Service for CoAP.

## Requisitos

Para ejecutar esta implementación de EAP sobre CoAP, asegúrese de tener:

- **Python 3.12**: Este proyecto está diseñado para funcionar en entornos con Python 3.12.
- **AAA Server**: Un servidor RADIUS configurado para gestionar las solicitudes de autenticación y generar las respuestas oportunas (máquina virtual).
- **Bibliotecas y dependencias**: La implementación requiere varias bibliotecas externas, que se detallan en `requirements.txt`.

## Instrucciones de Instalación

1. Clone este repositorio:
   ```bash
   git clone https://github.com/daniMGTeleco/CoAP-EAP-v12.git
   cd CoAP-EAP-v12
   ```
2. Instale las dependencias listadas en el archivo requirements.txt:
   ```bash
   pip install -r requirements.txt
   ```
3. Descargue la máquina virtual con el EAP Server que contiene el EAP Server a través de [este enlace](https://unioviedo-my.sharepoint.com/:u:/g/personal/uo276425_uniovi_es/EZtMQZl93LxDjEpuAKc5piQB-dPKXL7xn5Bzkd_R5I4Fyw?e=AuiR8q) (descomprimir el .zip).
4. Abrir la máquina virtual en **VMware Workstation 17 Player** y comprobar que funciona correctamente al introducir la contraseña (**student**).

## Uso
El proyecto incluye scripts para la ejecución del servicio de autenticación:

- **controller.py**: Inicialmente actúa como un servidor CoAP para recibir y responder a peticiones de autenticación EAP. Una vez que recibe el mensaje de activación, actuará como un cliente CoAP durante el resto del flujo.
- **peer.py**: Inicialmente actúa como un cliente CoAP, realizando una petición POST a la URI especificada y procesando la respuesta. Una vez que envía el mensaje de activación actuará como un servidor CoAP, procesando y respondiendo a los mensajes enviados por el peer durante el resto del flujo.

### Ejecución del servicio de autenticación
Para ejecutar el flujo de autenticación completo:

1. Abra el terminal de la máquina virtual con el EAP Server
1. Dentro del terminal lance estos tres comandos:
   ```bash
   cd /home/student/freeradius-psk/sbin
   export LD_PRELOAD=/home/student/coap-eap-tfg/freeradius-2.0.2-psk/hostapd/eap_example/libeap.so
   ./radiusd -X
   ```
2. Si quiere ver los resultados en **Wireshark**, seleccione las interfaces de red en las que quiere capturar el tráfico y aplique este filtro:
   ```
   coap or radius
   ```
3. A continuación, en la carpeta de la máquina host donde haya clonado este repositorio, abra la cmd y ejecute estos scripts en orden:
   ```bash
   python controller.py 
   python peer.py
   ```

## Reconocimientos
- Universidad de Oviedo
- Proyectos de código abierto: FreeRADIUS, Hostap/WPA_Supplicant
- Christian Amsüss como autor de la biblioteca aiocoap
- Dan García-Carrillo y Rafael Marín-López como autores de este Internet Draft

## Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulte el archivo `LICENSE` para más detalles.

## Contribuciones

¡Las contribuciones son bienvenidas! Si desea colaborar, por favor siga estos pasos:

1. Haga un **fork** del repositorio.
2. Cree una **rama** con su nueva funcionalidad o corrección de errores: `git checkout -b feature-nueva-funcionalidad`.
3. Realice sus cambios y haga un **commit**: `git commit -m "Descripción de los cambios"`.
4. Suba la nueva rama: `git push origin feature-nueva-funcionalidad`.
5. Abra un **Pull Request** en GitHub.

Antes de enviar, asegúrese de revisar los requisitos de estilo y las dependencias, así como de realizar pruebas.

## Contacto

Si tiene alguna duda o sugerencia, puede contactar con el autor (Daniel Menéndez González) a través de:

- **GitHub**: [daniMGTeleco](https://github.com/daniMGTeleco)
- **Correo electrónico**: [danielmenendezglez@gmail.com](mailto:danielmenendezglez@gmail.com)
