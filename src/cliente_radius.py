#!/usr/bin/env python3
# Copyright (c) 2024 Daniel Menéndez González
# SPDX-License-Identifier: MIT

"""El objetivo de este código es implementar un cliente RADIUS que sea capaz de comunicarse con un servidor RADIUS
implementado en C presente en una maquina virtual. El cliente deberá ser capaz de construir y enviar los mensajes
RADIUS al servidor, así como de recibir y procesar los mensajes RADIUS recibidos del servidor. En esta comunicación
el cliente enviará al servidor el EAP Response ID, el segundo y el cuarto mensaje EAP-PSK y recibirá del servidor en
el atributo EAP-Message del mensaje RADIUS el primer y el tercer mensaje EAP-PSK y el mensaje EAP-SUCCESS."""

# Importo la biblioteca base64 para codificar y decodificar datos en Base64
import base64
# Importo la biblioteca binascii para manejar conversiones entre datos binarios y representaciones ASCII
import binascii
# Importo la biblioteca codecs para trabajar con codificaciones de texto y datos binarios
import codecs
# Importo la biblioteca logging para gestionar y registrar mensajes de depuracion e informacion
import logging
# Importo la biblioteca random para generar numeros aleatorios
import random
# Importo la biblioteca time para trabajar con tiempo y retrasos en la ejecucion
import time
# Importo la funcion hexlify de binascii para convertir datos binarios en su representacion hexadecimal
from binascii import hexlify
# Importo la funcion hexdump de scapy.all para mostrar datos en formato hexadecimal, util para depuracion
from scapy.all import hexdump
# Importo el modulo Radius de scapy.layers.radius para manejar mensajes del protocolo RADIUS
from scapy.layers.radius import Radius
# Importo el modulo EAP de scapy.layers.eap para manejar el protocolo Extensible Authentication Protocol (EAP)
from scapy.layers.eap import EAP
# Importo la funcion Radius_Send_Request_PAP desde RADIUSMsgGenerator para generar y enviar una solicitud RADIUS
from RADIUSMsgGenerator import Radius_Build_Request
# Importo el modulo RadiusExt desde radiusext, que maneja los campos de los mensajes RADIUS
from radiusext import RadiusExt
# Importo todas las funciones y clases del modulo socket para realizar comunicaciones de red
from socket import *
# Importo el modulo Enum para definir enumeraciones
from enum import Enum

# Inicializo tres variables globales como cadenas vacías. Al estar definidas fuera de cualquier clase o funcion, estas
# variables pueden ser accedidas y modificadas desde cualquier parte del modulo en el que estan definidas. Esto sera
# util mas adelante, ya que en los bucles if del metodo sendNextMessageToRADIUS de la clase EAP_Authenticator se
# utilizaran estas variables para identificar el estado radius o para obtener las claves MS-MPPE
# para la construccion de las uris de los mensajes POST
datos_radiusResponsePacket_bytes = ""
radiusResponsePacket_state_2 = ""
radiusResponsePacket_state_3 = ""


# Establezco el nivel de logging para los mensajes de runtime de Scapy en ERROR, lo que significa que solo se
# registraran errores y no mensajes de depuracion o advertencias
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# Defino una clase de enumeracion (Enum) para representar los diferentes estados de autenticacion EAP
class EAPAuthState(Enum):
    # Defino el estado REQ_ID_FIX con el valor 1, el cual maneja el bug que se produce cuando se envia al servidor
    # RADIUS el EAP Response ID (el servidor responde con un Access-Challenge solicitando de nuevo la identidad del par
    # EAP en lugar de responder ya con el mensaje EAP-PSK-1, por lo que hay que enviar de nuevo el EAP Response ID)
    REQ_ID_FIX = 1
    # Defino el estado EAP_PSK_1 con el valor 2, el cual maneja la recepcion del mensaje EAP-PSK-1
    EAP_PSK_1 = 2
    # Defino el estado EAP_PSK_3 con el valor 3, el cual maneja la recepcion del mensaje EAP-PSK-3
    EAP_PSK_3 = 3
    # Defino el estado EAP_SUCCESS con el valor 4, el cual maneja la recepcion del mensaje EAP-SUCCESS
    # (representa el exito en la autenticacion EAP)
    EAP_SUCCESS = 4


# Defino una clase EAPAuth_AAA_connection que representa una conexion AAA (Authentication, Authorization, Accounting) 
# para EAP
class EAPAuth_AAA_connection:
    # Defino el metodo constructor __init__, que se ejecuta al crear una instancia de la clase
    def __init__(self):
        # Inicializo el atributo src_port, que representa el puerto de origen de la conexion, en 0
        self.src_port = 0
        # Inicializo el atributo dst_port, que representa el puerto de destino de la conexion, en 0
        self.dst_port = 0
        # Inicializo el atributo dst_ip, que representa la direccion IP de destino, como una cadena vacia
        self.dst_ip = ""


# Defino la clase RadiusState para configurar los parametros de una conexion RADIUS y los atributos de una solicitud de
# autenticacion, permitiendo mantener el estado. Es decir, a traves de esta clase puedo almacenar toda la informacion
# relevante para la conexion y enviar los mensajes de autenticacion adecuados
class RadiusState (EAPAuth_AAA_connection):
    # Defino el metodo constructor __init__, que inicializa los atributos necesarios para la conexion RADIUS
    def __init__(self):
        # Esto inicializa src_port, dst_port, y dst_ip desde la clase padre (EAPAuth_AAA_connection)
        super().__init__()
        # Inicializo el atributo host con la direccion IP del servidor RADIUS
        self.dst_ip = "192.168.124.128"
        # Inicializo el atributo password como una cadena vacia, que almacenara la contraseña del usuario
        self.password = ""
        # Inicializo el atributo username con el nombre de usuario (peer)
        self.username = "usera"
        # Inicializo el atributo secret como una cadena vacia, que almacenara el secreto compartido
        self.secret = "testing123"
        # Inicializo el atributo nasipaddr con la direccion IP del NAS (Network Access Server)
        self.nasipaddr = "127.0.0.1"
        # Inicializo el atributo src_port con un puerto de origen aleatorio entre 1024 y 65535
        self.src_port = random.randint(1024, 65535)
        # Inicializo el atributo dst_port con el puerto de destino por defecto para RADIUS (1812)
        self.dst_port = 1812
        # Inicializo el atributo timeout en 5 segundos, que es el maximo tiempo de espera para respuestas
        self.timeout = 5
        # Inicializo el atributo packet_num en 1, que cuenta el numero de paquetes enviados
        self.packet_num = 1
        # Inicializo el atributo service_type como una cadena vacia (define el tipo de servicio)
        self.service_type = ""
        # Inicializo el atributo nas_port_type con "wireless", indicando el tipo de puerto del NAS
        self.nas_port_type = "wireless"
        # Inicializo el atributo called_station_id como una cadena vacia (almacenar el ID de la estacion que llama)
        self.called_station_id = ""
        # Inicializo el atributo calling_station_id con una direccion MAC por defecto (alamcena el ID de la estacion llamada)
        self.calling_station_id = "00-00-00-00-00-00"
        # Inicializo el atributo vsa_id como una cadena vacia (almacena el identificador de un atributo especifico)
        self.vsa_id = ""
        # Inicializo el atributo vsa_type como una cadena vacia (define el tipo del atributo VSA)
        self.vsa_type = ""
        # Inicializo el atributo vsa_value como una cadena vacia (almacena el valor del atributo VSA)
        self.vsa_value = ""
        # Inicializo el atributo vsa_coding con "string" (define la codificacion del valor VSA)
        self.vsa_coding = "string"
        # Inicializo el atributo vsa_trim como una cadena vacia (define si se debe recortar el valor VSA)
        self.vsa_trim = ""
        # Inicializo el atributo framed_ip como una cadena vacia (almacena una direccion IP enmarcada)
        self.framed_ip = ""
        # Inicializo el atributo radiusid en 0 (identifica la transaccion RADIUS)
        self.radiusid = 0
        # Inicializo el atributo state como una cadena vacia (almacenar el estado de la conexion)
        self.state = ""
        # Inicializo el atributo eap con un valor el hexadecimal del mensaje EAP-Response ID (representa un mensaje EAP)
        self.eap = "0237000a017573657261"

    # Defino el metodo genRADIUSMessageFromState, que genera un mensaje RADIUS basado en el estado actual
    def genRADIUSMessageFromState(self):
        # Retorno un mensaje RADIUS creado con los atributos de la clase usando la funcion Radius_Build_Request
        return Radius_Build_Request(
            self.dst_ip,  # Direccion IP del servidor RADIUS
            self.dst_port,  # Puerto de destino para el mensaje
            self.src_port,  # Puerto de origen para el mensaje
            self.password,  # Contrasena del usuario
            self.username,  # Nombre de usuario
            RadiusExt.Generate_Authenticator(),  # Genero un autenticador usando una funcion de RadiusExt
            self.secret,  # Secreto compartido
            self.radiusid,  # Identificador de la transaccion RADIUS
            self.nasipaddr,  # Direccion IP del NAS
            self.service_type,  # Tipo de servicio
            self.nas_port_type,  # Tipo de puerto del NAS
            self.calling_station_id,  # ID de la estacion que llama
            self.called_station_id,  # ID de la estacion llamada
            self.eap,  # Mensaje EAP
            self.vsa_id,  # Identificador de atributo VSA
            self.vsa_type,  # Tipo de atributo VSA
            self.vsa_value,  # Valor del atributo VSA
            self.vsa_coding,  # Codificacion del atributo VSA
            self.vsa_trim,  # Indica si el valor VSA debe ser recortado
            self.framed_ip,  # Direccion IP enmarcada
            self.state  # Estado de la conexion
        )


# Defino la clase EAP_Authenticator, que maneja la autenticacion EAP y la extraccion, generacion y envio de mensajes RADIUS
class EAP_Authenticator:
    # Defino el metodo constructor __init__, que inicializa los atributos necesarios para el autenticador EAP
    def __init__(self):
        # Inicializo el estado en REQ_ID_FIX_1, que es el primer estado de autenticacion
        self._state = EAPAuthState.REQ_ID_FIX
        # Inicializo una lista para almacenar los paquetes recibidos
        self.receivedPackets = []
        # Inicializo una lista para almacenar los paquetes enviados
        self.sentPackets = []
        # Inicializo el paquete RADIUS actual como None
        self.currentRADIUSPacket = None
        # Inicializo el estado RADIUS usando la clase RadiusState
        self._radiusState = RadiusState()
        # Genero el siguiente mensaje RADIUS basado en el estado actual
        self.genNextRadiusMessageFromState()
        # Inicializo un contador en 0
        self.contador = 0
        # Inicializo otro contador en 0
        self.contador2 = 0
        # Inicializo una variable req_auth como una cadena vacia
        self.req_auth = ""

    # Defino el metodo genNextRadiusMessageFromState, que genera el siguiente mensaje RADIUS
    def genNextRadiusMessageFromState(self):
        # Genero un nuevo paquete RADIUS usando el estado actual
        self.currentRADIUSPacket = self._radiusState.genRADIUSMessageFromState()

    # Defino el metodo extractEAPMessage, que extrae el mensaje EAP de un mensaje RADIUS
    def extractEAPMessage(self, radius_msg, raw_eap_msg):
        # Extraigo la longitud del mensaje EAP del mensaje en crudo, tomando los bytes 4 a 8
        EAP_len_str = raw_eap_msg[4:8]
        # Convierto la longitud EAP de hexadecimal a entero
        EAP_len = int(EAP_len_str, 16)
        # Encuentro la posicion inicial del mensaje EAP en el mensaje RADIUS
        init_possition = radius_msg.find(raw_eap_msg)
        # Calculo la posicion final del mensaje EAP en el mensaje RADIUS
        final_possition = init_possition + (EAP_len * 2)
        # Extraigo el mensaje EAP del mensaje RADIUS
        EAP_msg = radius_msg[init_possition:final_possition]
        # Retorno el mensaje EAP extraido
        return EAP_msg

    # Defino el metodo set_state, que permite fijar el estado de autenticacion EAP
    def set_state(self, new_state):
        """Fijar el estado de autenticacion EAP."""
        self._state = new_state

    # Defino el metodo set_eap_message, que permite fijar el mensaje EAP que se va a enviar
    def set_eap_message(self, eap_message):
        """Fijar el mensaje EAP que se va a enviar."""
        self._radiusState.eap = eap_message

    # Defino el metodo sendNextMessageToRADIUS, que envía el mensaje RADIUS y recibe la respuesta
    def sendNextMessageToRADIUS(self):
        # Declaro que las variables datos_radiusResponsePacket_bin, radiusResponsePacket_state_2 y
        # radiusResponsePacket_state_3 son globales,lo que permite acceder a ellas y modificarlas dentro de esta funcion
        global datos_radiusResponsePacket_bytes, radiusResponsePacket_state_2, radiusResponsePacket_state_3
        # Creo un socket UDP para la comunicacion con el servidor RADIUS
        clientSocket = socket(AF_INET, SOCK_DGRAM)
        # Establezco un tiempo de espera de 1 segundo para el socket
        clientSocket.settimeout(1)
        # Enlazo el socket a todas las interfaces en el puerto de origen
        clientSocket.bind(('0.0.0.0', self._radiusState.src_port))
        # Defino la direccion del servidor RADIUS al que voy a enviar el mensaje
        addr = ("192.168.124.128", self._radiusState.dst_port)
        # Inicio el cronometro para medir el tiempo de envío
        start = time.time()
        # Conviero el paquete RADIUS a un mensaje en formato base64
        b64 = codecs.encode(self.currentRADIUSPacket.build(), 'base64').decode().strip()
        # Decodifico el mensaje base64 a bytes
        message = base64.b64decode(b64)
        # Si ya he enviado tres peticiones Access-Request
        if self.contador2 == 3:
            # Obtengo el campo Authenticator de la cuarta peticion Access-Request y lo asigno a la varibale interna
            # req_auth. Esta variable la empleara el EAP Authenticator para descifrar las claves MS y poder obtener la MSK
            self.req_auth = message.hex()[8:40]
            # Imprimo su valor para comprobar que es correcto
            print("Request Authenticator previo al Access_Accept:", self.req_auth)
        # Envio el mensaje a la direccion del servidor RADIUS
        clientSocket.sendto(message, addr)
        # Incremento el contador2 en 1 para llevar un registro de cuantas peticiones he enviado
        self.contador2 += 1
        # Inicializo la variable radiusResponsePacket como None para almacenar la respuesta del servidor RADIUS
        radiusResponsePacket = None
        # Inicializo la variable response_state como None para almacenar el estado de la respuesta
        response_state = None
        # Inicializo la variable response_eap_msg como None para almacenar el mensaje EAP de la respuesta
        response_eap_msg = None
        # Inicializo la variable raw_eap_msg como None para almacenar el mensaje EAP en su formato crudo
        raw_eap_msg = None
        # Intento recibir un paquete de respuesta del servidor RADIUS
        try:
            # Recibo los datos y la direccion del servidor usando el socket
            data, server = clientSocket.recvfrom(self._radiusState.src_port)
            # Indico que estoy procesando el mensaje recibido
            print("Procesando el mensaje recibido")
            # Muestro el contenido del paquete recibido en formato hexadecimal
            print(hexdump(data))
            # Creo un objeto Radius a partir de los bytes recibidos
            radiusResponsePacket = Radius(bytes(data))
            # Muestro el contenido del paquete RADIUS en formato legible
            print(radiusResponsePacket.show())
            # Construyo el paquete RADIUS de nuevo en formato bytes
            datos_radiusResponsePacket_bytes = radiusResponsePacket.build()
            # Conviero el mensaje RADIUS recibido a hexadecimal y lo decodifico a cadena
            radiusResponsePacketHex = binascii.hexlify(datos_radiusResponsePacket_bytes).decode('utf-8')
            # Muestro el mensaje RADIUS recibido en hexadecimal
            print("MENSAJE RADIUS RECIBIDO HEXADECIMAL:", radiusResponsePacketHex)
            print("Ahora los atributos del paquete recibido:")
            # Obtengo la lista de atributos del paquete RADIUS
            attlist = radiusResponsePacket.attributes
            # Recorro cada atributo de la lista
            for att in attlist:
                # Muestro cada atributo en formato legible
                print(att.show())
                # Separador
                print("--")
                # Muestro el tipo del atributo
                print(att.type)
                # Si el tipo del atributo es 24, indica el estado
                if att.type == 24:
                    # Almaceno el valor del atributo convertido a hexadecimal y decodificado a
                    # cadena como el estado de respuesta
                    response_state = hexlify(att.value).decode('utf-8')
                    # Muestro el valor del estado del primer mensaje de respuesta
                    print("Este es el estado (state): ", response_state)
                # Si el tipo del atributo es 79, indica un mensaje EAP
                if att.type == 79:
                    # Almaceno el mensaje EAP
                    response_eap_msg = att.value
                    # Almaceno el atributo crudo
                    raw_eap_msg = att
        # Capturo la excepcion de tiempo de espera si no se recibe respuesta
        except timeout:
            # Indico que se ha agotado el tiempo de espera para la solicitud
            print("SE AGOTÓ EL TIEMPO DE ESPERA PARA LA SOLICITUD")
        # Incremento el contador en 1 para llevar un registro de cuantas respuestas he procesado
        self.contador += 1
        # Si es la primera respuesta, almaceno el estado recuperado directamente
        if self.contador == 1:
            # Almaceno el estado recuperado
            self._radiusState.state = response_state
            # Muestro el estado recuperado
            print("El estado (state) recuperado es:", response_state)
        # Si es la segunda respuesta, almaceno el estado desde el paquete RADIUS
        if self.contador == 2:
            # Extraigo el estado de la segunda respuesta RADIUS desde el paquete en bytes, tomando los bytes
            # desde la posición 53 hasta la 69
            radiusResponsePacket_state_2 = datos_radiusResponsePacket_bytes[53:69]
            # Indico que ahora voy a mostrar los atributos del paquete RADIUS recibido
            # Almaceno el estado de la variable radiusResponsePacket_state_2 en hexadecimal
            self._radiusState.state = hexlify(radiusResponsePacket_state_2).decode('utf-8')
            # Muestro el estado en hexadecimal
            print("Este es el estado (state):", hexlify(radiusResponsePacket_state_2).decode('utf-8'))
            # Muestro el estado recuperado
            print("El estado (state) recuperado es:", hexlify(radiusResponsePacket_state_2).decode('utf-8'))
        # Si es la tercera respuesta, almaceno el estado desde el paquete RADIUS
        if self.contador == 3:
            # Extraigo el estado de la tercera respuesta RADIUS desde el paquete en bytes, tomando los bytes
            # desde la posición 83 hasta la 99
            radiusResponsePacket_state_3 = datos_radiusResponsePacket_bytes[83:99]
            # Almaceno el estado de la variable radiusResponsePacket_state_3 en hexadecimal
            self._radiusState.state = hexlify(radiusResponsePacket_state_3).decode('utf-8')
            # Muestro el estado en hexadecimal
            print("Este es el estado (state):", hexlify(radiusResponsePacket_state_3).decode('utf-8'))
            # Muestro el estado recuperado
            print("El estado (state) recuperado es:", hexlify(radiusResponsePacket_state_3).decode('utf-8'))
        # Incremento el identificador RADIUS para la siguiente solicitud
        self._radiusState.radiusid += 1
        # Creo un paquete EAP utilizando el mensaje EAP de respuesta
        radiusEAPPacket = EAP(response_eap_msg)
        # Muestro el contenido del paquete EAP
        radiusEAPPacket.show()
        # Verifico si el estado actual es REQ_ID_FIX
        if self._state == EAPAuthState.REQ_ID_FIX:
            # Convierto el paquete EAP recibido en hexadecimal
            paq_hex = str(radiusEAPPacket.build().hex())
            # Imprimo el paquete en formato hexadecimal
            print(paq_hex)
            # Defino el codigo (2 ya que es una respuesta) y la longitud (se que la longitud del EAP Response ID es 10)
            # que deben ser reemplazados ya que tengo que "replicar" el primer mensaje RADIUS que contenia el
            # EAP-Response ID pero con el ID del mensaje (Access-Challenge con codigo 1 y longitud 5) recibido
            cod = "02"  # Reemplazo la parte correspondiente a "01"
            lon = "000a"  # Reemplazo la parte correspondiente a "0005"
            # Realizo las modificaciones al paquete hexadecimal
            # El paquete hexadecimal a enviar estara formado por el codigo (2), el ID de la respuesta, la longitud (10),
            # el type (Identity (1)) y la cadena hexadecimal "7573657261" ("usera") que es el ID del par EAP
            paq_hex_mod = cod + paq_hex[2:4] + lon + paq_hex[8:] + "7573657261"
            # Muestro el paquete modificado en formato hexadecimal
            print(paq_hex_mod)
            # Almaceno el paquete EAP modificado en el atributo EAP de la clase RadiusState
            self._radiusState.eap = paq_hex_mod
            # Cambio el estado de autenticacion a EAP_PSK_1
            self._state = EAPAuthState.EAP_PSK_1
        # Verifico si el estado actual es EAP_PSK_1
        if self._state == EAPAuthState.EAP_PSK_1:
            # Imprimo el mensaje EAP recibido indicando que se esta mostrando el mensaje EAP en crudo
            print("Mensaje EAP en crudo (RAW)")
            # Me aseguro de que raw_eap_msg sea un objeto que pueda ser convertido a bytes
            if isinstance(raw_eap_msg, bytes):
                # Si raw_eap_msg es de tipo bytes, lo imprimo en hexadecimal
                print(raw_eap_msg.hex())
            else:
                # Si raw_eap_msg no es de tipo bytes, lo convierto a bytes y luego imprimo en hexadecimal
                print(str(raw_eap_msg).encode('utf-8').hex())
            # Imprimo una línea vacia para separar el contenido
            print("")
            # Construyo el paquete EAP de respuesta en bytes utilizando el metodo build() del objeto radiusEAPPacket y
            # lo codifico a hexadecimal
            radius_eap_packet_hex = radiusEAPPacket.build().hex()
            # Imprimo un mensaje indicando que se esta mostrando el contenido del metodo EAP (el paquete EAP en formato
            # hexadecimal)
            print("Contenido del metodo EAP:", radius_eap_packet_hex)
            # Construyo el paquete RADIUS de respuesta en bytes utilizando el metodo build() del objeto
            # radiusResponsePacket y lo codifico a hexadecimal
            radius_response_packet_hex = radiusResponsePacket.build().hex()
            # Extraigo el mensaje EAP-PSK-1 utilizando el metodo extractEAPMessage
            EAP_PSK_MSG_1 = self.extractEAPMessage(radius_response_packet_hex, radius_eap_packet_hex)
            # Imprimo el mensaje EAP-PSK-1 extraido
            print("Mensaje EAP-PSK-1:", EAP_PSK_MSG_1)
            # Retorno el mensaje EAP-PSK-1
            return EAP_PSK_MSG_1
        # Verifico si el estado actual es EAP_PSK_3
        if self._state == EAPAuthState.EAP_PSK_3:
            # Imprimo el mensaje EAP recibido indicando que se esta mostrando el mensaje EAP en crudo
            print("Mensaje EAP en crudo (RAW)")
            # Me aseguro de que raw_eap_msg sea un objeto que pueda ser convertido a bytes
            if isinstance(raw_eap_msg, bytes):
                # Si raw_eap_msg es de tipo bytes, lo imprimo en hexadecimal
                print(raw_eap_msg.hex())
            else:
                # Si raw_eap_msg no es de tipo bytes, lo convierto a bytes y luego imprimo en hexadecimal
                print(str(raw_eap_msg).encode('utf-8').hex())
            # Imprimo una línea vacia para separar el contenido
            print("")
            # Construyo el paquete EAP de respuesta en bytes utilizando el metodo build() del objeto radiusEAPPacket y
            # lo codifico a hexadecimal
            radius_eap_packet_hex = radiusEAPPacket.build().hex()
            # Imprimo un mensaje indicando que se esta mostrando el contenido del metodo EAP (el paquete EAP en formato
            # hexadecimal)
            print("Contenido del metodo EAP:", radius_eap_packet_hex)
            # Construyo el paquete RADIUS de respuesta en bytes utilizando el método build() del objeto
            # radiusResponsePacket y lo codifico a hexadecimal
            radius_response_packet_hex = radiusResponsePacket.build().hex()
            # Extraigo el mensaje EAP-PSK-3 utilizando el metodo extractEAPMessage
            EAP_PSK_MSG_3 = self.extractEAPMessage(radius_response_packet_hex, radius_eap_packet_hex)
            # Imprimo el mensaje EAP-PSK-3 extraido
            print("Mensaje EAP-PSK-3:", EAP_PSK_MSG_3)
            # Retorno el mensaje EAP-PSK-3
            return EAP_PSK_MSG_3
        # Verifico si el estado actual es EAP_SUCCESS
        if self._state == EAPAuthState.EAP_SUCCESS:
            # Imprimo el mensaje EAP recibido indicando que se esta mostrando el mensaje EAP en crudo
            print("Mensaje EAP en crudo (RAW)")
            # Me aseguro de que raw_eap_msg sea un objeto que pueda ser convertido a bytes
            if isinstance(raw_eap_msg, bytes):
                # Si raw_eap_msg es de tipo bytes, lo imprimo en hexadecimal
                print(raw_eap_msg.hex())
            else:
                # Si raw_eap_msg no es de tipo bytes, lo convierto a bytes y luego imprimo en hexadecimal
                print(str(raw_eap_msg).encode('utf-8').hex())
            # Imprimo una línea vacia para separar el contenido
            print("")
            # Construyo el paquete EAP de respuesta en bytes utilizando el metodo build() del objeto radiusEAPPacket y
            # lo codifico a hexadecimal
            radius_eap_packet_hex = radiusEAPPacket.build().hex()
            # Imprimo un mensaje indicando que se esta mostrando el contenido del metodo EAP (el paquete EAP en formato
            # hexadecimal)
            print("Contenido del metodo EAP:", radius_eap_packet_hex)
            # Construyo el paquete RADIUS de respuesta en bytes utilizando el metodo build() del objeto
            # radiusResponsePacket y lo codifico a hexadecimal
            radius_response_packet_hex = radiusResponsePacket.build().hex()
            # Extraigo el mensaje EAP-SUCCESS utilizando el metodo extractEAPMessage
            EAP_PSK_MSG_SUCCESS = self.extractEAPMessage(radius_response_packet_hex, radius_eap_packet_hex)
            # Imprimo el mensaje EAP-SUCCESS extraido
            print("Mensaje EAP-SUCCESS:", EAP_PSK_MSG_SUCCESS)
            # Extraigo la clave MS-MPPE-Recv-Key que comprende de los bytes 28 al 78 del paquete RADIUS
            radiusResponsePacket_MPPE_RecKey = datos_radiusResponsePacket_bytes[28:78]
            # Convierto la clave MS-MPPE-Recv-Key a formato hexadecimal
            MPPE_RecKey_hex = binascii.hexlify(radiusResponsePacket_MPPE_RecKey).decode('utf-8')
            # Imprimo la clave MS-MPPE-Recv-Key en formato hexadecimal
            print("MPPE_RecKey cifrada:", MPPE_RecKey_hex)
            # Extraigo la clave MS-MPPE-Send-Key que comprende de los bytes 86 al 136 del paquete RADIUS
            radiusResponsePacket_MPPE_SendKey = datos_radiusResponsePacket_bytes[86:136]
            # Convierto la clave MS-MPPE-Send-Key a formato hexadecimal
            MPPE_SendKey_hex = binascii.hexlify(radiusResponsePacket_MPPE_SendKey).decode('utf-8')
            # Imprimo la clave MS-MPPE-Send-Key en formato hexadecimal
            print("MPPE_SendKey cifrada:", MPPE_SendKey_hex)
            # Retorno el mensaje de exito EAP-PSK y las claves MS-MPPE-Recv-Key y MS-MPPE-Send-Key
            # en formato hexadecimal
            return EAP_PSK_MSG_SUCCESS, MPPE_RecKey_hex, MPPE_SendKey_hex
