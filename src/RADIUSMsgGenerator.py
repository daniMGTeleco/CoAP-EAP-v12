#!/usr/bin/env python3
# Copyright (c) 2024 Daniel Menéndez González
# SPDX-License-Identifier: MIT

"""El objetivo de este código es construir y enviar solicitudes de autenticación RADIUS, manejando la creación de
atributos, la generación del Message-Authenticator y comprobando que el formato de los paquetes sea correcto."""

# Realizo los imports de las bibliotecas necesarias
from scapy.all import *
from radiusattr import RadiusAttr
from radiusext import RadiusExt
from hashlib import md5
import base64
import codecs
import logging
import socket

# Establezco el nivel de logging para los mensajes de runtime de Scapy en ERROR, lo que significa que solo se
# registraran errores y no mensajes de depuracion o advertencias
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# Establezco la configuracion de scapy para no mostrar los paquetes enviados
conf.verb = 0
# Creo una tabla de traduccion XOR con 0x5C para todos los bytes de 0 a 255
trans_5C = bytes([x ^ 0x5C for x in range(256)])
# Creo una tabla de traduccion XOR con 0x36 para todos los bytes de 0 a 255
trans_36 = bytes([x ^ 0x36 for x in range(256)])
# Obtengo el tamaño de bloque para el algoritmo MD5
blocksize = md5().block_size


# Esta funcion calcula el HMAC utilizando el algoritmo MD5 dada una clave y un mensaje
def hmac_md5(key, msg):
    # Verifico si la longitud de la clave es mayor que el tamaño del bloque
    if len(key) > blocksize:
        # Si es mayor, aplico MD5 a la clave
        key = md5(key).digest()
    # Relleno la clave con ceros hasta alcanzar el tamaño del bloque
    key += b'\x00' * (blocksize - len(key))
    # Creo el padding externo usando XOR con 0x5C
    o_key_pad = bytes(x ^ 0x5C for x in key)
    # Creo el padding interno usando XOR con 0x36
    i_key_pad = bytes(x ^ 0x36 for x in key)
    # Retorno el hash MD5 del padding externo concatenado con el hash MD5 del padding interno y el mensaje
    return md5(o_key_pad + md5(i_key_pad + msg).digest())


# Esta funcion convierte una cadena en formato hexadecimal a bytes utilizando base64 como intermediario
def stringHEXtoHEX(s):
    # Codifico la cadena hexadecimal a base64
    b64 = base64.b64encode(codecs.decode(s, 'hex'))
    # Decodifico el resultado de base64 y lo retorno
    return base64.b64decode(b64)


################################ GENERIC FUNCTIONS ######################################3

# Esta funcion calcula el Message-Authenticator para un paquete RADIUS usando HMAC con MD5 y un conjunto de atributos
def CalcRADIUS_MessageAuthenticator(RadiusPacket, avp):
    # Defino una clave de 32 caracteres en hexadecimal
    key = "00000000000000000000000000000000"
    # Decodifico la clave de hexadecimal a bytes y luego a base64
    message = base64.b64decode(codecs.encode(codecs.decode(key, 'hex'), 'base64'))
    # Creo un atributo RADIUS para el Message-Authenticator con el mensaje decodificado
    avp5 = RadiusAttr(type="Message-Authenticator", value=message)
    # Agrego el nuevo atributo al conjunto de atributos
    avp += bytes(avp5)
    # Combino el paquete RADIUS con los atributos y lo convierto a bytes
    radius_msg = bytes_hex(RadiusPacket / avp)
    print("Mensaje en bytes:", radius_msg)
    # Codifico el mensaje RADIUS a base64
    b64 = base64.b64encode(codecs.decode(radius_msg, 'hex'))
    print("Mensaje en base64:", b64.decode())
    # Defino una nueva clave para el HMAC
    key = "testing123"
    # Decodifico el mensaje de base64 a bytes
    message = base64.b64decode(b64)
    # Calculo el HMAC utilizando MD5
    h = hmac_md5(key.encode(), message)
    # Retorno el valor hexadecimal del HMAC
    return h.hexdigest()


################################ RADIUS FUNCTIONS ##############################

# Esta funcion construye un paquete RADIUS para la autenticacion
def Radius_Build_Request(dst_ip, dst_port, src_port, password, username, authenticator, secret, radius_id, nasipaddr,
                         service_type, nas_port_type, calling_station_id, called_station_id, eap, vsa_id, vsa_type,
                         vsa_value, vsa_coding, vsa_trim, framed_ip, state):

    # Creo el atributo de usuario con el nombre de usuario codificado en bytes
    avp1 = RadiusAttr(type="User-Name", value=username.encode())
    # Creo el atributo de direccion IP NAS
    avp3 = RadiusAttr(type="NAS-IP-Address", value=socket.inet_aton(nasipaddr))
    # Combino los atributos en un solo paquete
    avp = bytes(avp1) + bytes(avp3)
    # Si se especifica un Service-Type, lo agrego al paquete
    if service_type == "FRAMED":
        avp_service_type = RadiusAttr(type="Service-Type", value=socket.inet_aton("2"))  # 2 corresponde a FRAMED
        avp += bytes(avp_service_type)
    # Agrego el atributo de Framed-MTU con un tamaño de 1400
    avp += bytes(RadiusAttr(type="Framed-MTU", value=socket.inet_aton("1400")))
    # Si hay una ID de la estacion que recibe la solicitud de conexion, la agrego como atributo
    if called_station_id:
        avp4 = RadiusAttr(type="Called-Station-Id", value=called_station_id.encode())
        avp += bytes(avp4)
    # Si hay una ID de la estacion que inicia la solicitud de conexion, la agrego como atributo
    if calling_station_id:
        avp4 = RadiusAttr(type="Calling-Station-Id", value=calling_station_id.encode())
        avp += bytes(avp4)
    # Dependiendo del tipo de puerto NAS, agrego el atributo correspondiente
    if nas_port_type == "ethernet":
        avp4 = RadiusAttr(type="NAS-Port-Type", value=socket.inet_aton("15"))  # Ethernet
        avp += bytes(avp4)
    elif nas_port_type == "wireless":
        avp4 = RadiusAttr(type="NAS-Port-Type", value=socket.inet_aton("19"))  # Wireless
        avp += bytes(avp4)
    elif nas_port_type == "virtual":
        avp4 = RadiusAttr(type="NAS-Port-Type", value=socket.inet_aton("5"))  # Virtual
        avp += bytes(avp4)
    # Agrego el atributo de informacion de conexion codificado en bytes
    avp += bytes(RadiusAttr(type="Connect-Info", value="CON".encode()))
    # Agrego el mensaje EAP como atributo en bytes
    avp5 = RadiusAttr(type="EAP-Message", value=stringHEXtoHEX(eap))
    avp += bytes(avp5)
    # Imprimo el estado
    print("STATE:", state)
    # Si hay un estado, lo agrego como atributo en bytes
    if state:
        avp5 = RadiusAttr(type="State", value=stringHEXtoHEX(state))
        avp += bytes(avp5)
    # Imprimo el ID del mensaje Radius
    print("RADIUS ID:", radius_id)
    # Creo el paquete RADIUS con el codigo de solicitud de acceso, el autenticador y el ID
    RadiusPacket = RadiusExt(code="Access-Request", authenticator=authenticator, id=radius_id)
    # Guardo los atributos en una variable
    avp2 = avp
    # Calculo el autenticador del mensaje RADIUS
    auth = CalcRADIUS_MessageAuthenticator(RadiusPacket, avp2)
    # Imprimo el Message-Autehticator calculado
    print("Message-Authenticator calculado:", auth)
    print("------")
    # Agrego el atributo de autenticador de mensaje
    avp6 = RadiusAttr(type="Message-Authenticator", value=stringHEXtoHEX(auth))
    avp += bytes(avp6)
    # Muestro el paquete RADIUS que se va a enviar
    print("Enviando Paquete Radius.......")
    print((RadiusPacket / avp).show())
    print(".............................")
    # Retorno el paquete RADIUS combinado con los atributos
    return RadiusPacket / avp
