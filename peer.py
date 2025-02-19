#!/usr/bin/env python3
# Copyright (c) 2024 Daniel Menéndez González
# SPDX-License-Identifier: MIT

"""Este código implementa el par EAP (EAP Peer) del protocolo CoAP-EAP. Se encarga de manejar un intercambio de mensajes
 EAP-PSK (Extensible Authentication Protocol con Pre-Shared Key) utilizando el protocolo CoAP como transporte. Esto
 involucra la creación de respuestas a las solicitudes que llegan a un recurso CoAP, generando y procesando mensajes EAP."""

# Importo los paquetes necesarios, lo que necesito de la biblioteca aiocoap (facilita la creación de aplicaciones de red
# para IoT, tanto del lado del cliente como del servidor, usando CoAP) y las funciones y variables del script EAP_PSK
import asyncio
import aiocoap
import cbor2
from mensajes_EAP_PSK import *
from aiocoap import *
from aiocoap import resource
from aiocoap.numbers.codes import Code
from aiocoap.numbers.contentformat import ContentFormat
from aiocoap.oscore import CanProtect, CanUnprotect, SecurityContextUtils, ReplayWindow
from calculos_oscore import derive_oscore_keys
from redes import get_wifi_ip

# Inicializo cuatro variables globales como cadenas vacías. Al estar definidas fuera de cualquier clase o funcion, estas
# variables pueden ser accedidas y modificadas desde cualquier parte del modulo en el que estan definidas. Esto sera
# util mas adelante, ya que los metodos de las clases usaran estas variables para compartir informacion entre diferentes
# partes del programa.
AK = ""
KDK = ""
ID_S = ""
RAND_P = ""


# Clase FirstResource que manejara el EAP Request ID y generara la EAP Response ID
class FirstResource(resource.Resource):
    # Defino el metodo constructor __init__, que recibe tres parametros: root, uri_to_remove y counter
    def __init__(self, root, uri_to_remove, counter):
        # Llamo al constructor de la clase base para asegurarme de que toda inicializacion en la clase padre 'Resource'
        # se realice correctamente.
        super().__init__()
        # Asigno el recurso raiz 'root' recibido como parametro al atributo de instancia 'self.root'.
        # 'root' representa el recurso principal que actua como contenedor para acceder a todos los recursos en el
        # servidor CoAP.
        self.root = root
        # Asigno la URI que se desea eliminar ('uri_to_remove') recibida como parametro al atributo de instancia
        # 'self.uri_to_remove'. Esta URI representa el recurso específico que se espera eliminar en el contexto de esta
        # instancia.
        self.uri_to_remove = uri_to_remove
        # Asigno el valor del counter recibido como parametro (counter perteneciente a la URI del EAP Request ID) al
        # atributo de instancia 'self.counter'
        self.counter = counter

    # Metodo que maneja los mensajes POST enviados a este recurso
    async def render_post(self, request):
        # Muestro la informacion del mensaje POST recibido con el EAP Request ID
        print("MENSAJE POST CON EL EAP REQUEST ID RECIBIDO CON:")
        # Imprimo el codigo
        print("Código:", request.code)
        # Imprimo el payload en binario
        print("Payload:", request.payload)
        # Imprimo el payload en hexadecimal
        print("Payload hexadecimal:", request.payload.hex())
        # Guardo el payload del mensaje EAP Request ID en la instancia root para que sea accesible desde la clase FourthResource
        self.root.first_resource_payload = request.payload
        # Deserializo la estructura CBOR del payload del EAP Request ID recibido (son los ultimos 11 bytes) para extraer la
        # informacion que necesito para OSCORE
        deserialized_info1 = cbor2.loads(request.payload[-11:])
        # Extraigo el RID_C y lo asigno a la variable rid_c
        rid_c = deserialized_info1[2]
        # Comienzo a obtener los parametros necesarios para construir la respuesta (EAP Response ID)
        # Defino los conjuntos de cifrado en un diccionario, donde la clave es un indice y el valor es una lista que
        # contiene el algoritmo de cifrado y el algoritmo de hash
        conjuntos_cifrado = {
            0: ["AES-CCM-16-64-128", "SHA-256"],  # Este es el conjunto de cifrado predeterminado
            1: ["A128GCM", "SHA-256"],  # Este es el segundo conjunto de cifrado
            2: ["A256GCM", "SHA-384"],  # Este es el tercer conjunto de cifrado
            3: ["ChaCha20/Poly1305", "SHA-256"],  # Este es el cuarto conjunto de cifrado
            4: ["ChaCha20/Poly1305", "SHAKE256"]  # Este es el quinto conjunto de cifrado
        }
        # Defino de forma manual y con tamaño de 1 byte el ID de Destinatario del par EAP
        RID_I = b'\x02'
        # Defino la estructura CoAP-EAP_Info como un diccionario que contiene informacion sobre el conjuntos de
        # cifrado elegido por el par (en este caso el predeterminado, es decir, 0) y el ID de Destinatario del par EAP
        coap_eap_info = {
            # Indice del conjunto de cifrado elegido por el par EAP
            1: [0],
            # RID-I como una cadena binaria
            2: RID_I,
        }
        # Serializo la estructura CoAP-EAP_Info a formato CBOR para su transporte o almacenamiento
        cbor_payload = cbor2.dumps(coap_eap_info)
        # Imprimo la estructura CBOR del EAP Response ID
        print("Estructura CBOR del EAP Response ID:", cbor_payload.hex())
        # Guardo la estructura de datos CBOR en la instancia root para que sea accesible desde la clase FourthResource
        self.root.cbor_payload = cbor_payload
        # Establezco el payload de la respuesta (cadena hexadecimal fija + identidad del dispositivo IoT ("usera")
        # codificado a hexadecimal + estructura de datos CBOR codificada a hexadecimal)
        payload = "0237000a01" + "usera".encode('utf-8').hex() + cbor_payload.hex()
        # Imprimo el payload de la respuesta en hexadecimal
        print("Payload del EAP Response ID:", payload)
        # Deserializo la estructura CBOR del payload del EAP Response ID para extraer la informacion que necesito para OSCORE
        deserialized_info2 = cbor2.loads(cbor_payload)
        # Extraigo la lista de indices de los conjuntos de cifrado y la asigno a la variable cifrado_indices
        cifrado_indices = deserialized_info2[1]
        # Extraigo el primer indice de la lista de conjuntos de cifrado (en este caso el indice 0)
        indice_cifrado = cifrado_indices[0]
        # Asigno el nombre del algoritmo de cifrado AEAD correspondiente al indice extraido
        algoritmo_AEAD = conjuntos_cifrado[indice_cifrado][0]
        # Asigno el nombre del algoritmo hash correspondiente al indice extraido
        algoritmo_hash = conjuntos_cifrado[indice_cifrado][1]
        # Imprimo el nombre del algoritmo de cifrado correspondiente al índice extraído
        print("Algoritmo de cifrado AEAD elegido:", algoritmo_AEAD)
        # Imprimo el nombre del algoritmo hash correspondiente al índice extraído
        print("Algoritmo hash elegido:", algoritmo_hash)
        # Imprimo el RID-C extraído (ID de Destinatario del autenticador EAP)
        print("RID-C:", rid_c)
        # Imprimo el RID-I (ID de Destinatario del par EAP)
        print("RID-I:", RID_I)
        # Guardo el algoritmo AEAD en la instancia root para que sea accesible desde la clase FourthResource
        self.root.algoritmo_AEAD = algoritmo_AEAD
        # Guardo el algoritmo hash en la instancia root para que sea accesible desde la clase FourthResource
        self.root.algoritmo_hash = algoritmo_hash
        # Guardo el RID_I en la instancia root para que sea accesible desde la clase FourthResource
        self.root.rid_i = RID_I
        # Guardo el RID_C en la instancia root para que sea accesible desde la clase FourthResource
        self.root.rid_c = rid_c
        # Establezco el formato del contenido a OCTETSTREAM para que se muestre el contenido del mensaje (payload) en
        # Wireshark en hexadecimal. Debería de ser COAP-EAP, esta opcion la añadi dentro del script contentformat.py de
        # la biblioteca aiocoap de forma que se pueda seleccionar también, pero al ser muy reciente Wireshark no la
        # tiene implementada y por tanto no muestra el contenido de los mensajes ya que no conoce este formato
        content = ContentFormat.OCTETSTREAM
        # Construyo el mensaje de respuesta con codigo CREATED y con el payload y el content_format establecidos anteriormente
        resp = aiocoap.Message(code=Code.CREATED, payload=bytes.fromhex(payload), content_format=content)
        # Incremento el valor de la variable counter en 1
        counter = self.counter+1
        # Creo una nueva URI concatenando 'auth/eap/' con el nuevo valor de counter (sera la que se utilizara para enviar
        # el POST con el mensaje EAP-PSK-1)
        URI = 'auth/eap/' + str(counter)
        # Divido la nueva URI en partes separadas por el caracter '/'
        URI_partes = URI.split('/')
        # Añado la URI creada a la opcion location_path del mensaje de respuesta
        resp.opt.location_path = [URI_partes[0], URI_partes[1], URI_partes[2]]
        # Indico que estoy enviando la respuesta al autenticador EAP
        print("Enviando EAP Response ID al controlador...")
        # Asocio la URI creada anteriormente con un recurso (SecondResource) que manejara las peticiones que lleguen a esa ruta
        self.root.add_resource([URI_partes[0], URI_partes[1], URI_partes[2]], SecondResource(self.root, URI, counter))
        # Indico que se ha agregado un nuevo recurso asociado a la uri generada
        print("Nuevo recurso agregado con URI:", URI)
        # Divido la URI que se necesita eliminar en partes separadas por el caracter '/'
        uri_to_remove_partes = self.uri_to_remove.split('/')
        # Indico que se va a eliminar el recurso FirstResource una vez que envio la respuesta y añado el nuevo recurso
        print(f"Eliminando recurso con URI: {uri_to_remove_partes[0] + '/' + uri_to_remove_partes[1] + '/' + uri_to_remove_partes[2]}")
        # Elimino el recurso con la uri asociada a este primer recurso (FirstResource)
        self.root.remove_resource([uri_to_remove_partes[0], uri_to_remove_partes[1], uri_to_remove_partes[2]])
        print("")
        # Retorno el mensaje de respuesta
        return resp


# Clase SecondResource que manejara el mensaje EAP-PSK-1 y generara como respuesta el mensaje EAP-PSK-2
class SecondResource(resource.Resource):
    # Defino el metodo constructor __init__, que recibe tres parametros: root, uri_to_remove y counter
    def __init__(self, root, uri_to_remove, counter):
        # Llamo al constructor de la clase base para asegurarme de que toda inicializacion en la clase padre 'Resource'
        # se realice correctamente.
        super().__init__()
        # Asigno el recurso raiz 'root' recibido como parametro al atributo de instancia 'self.root'.
        # 'root' representa el recurso principal que actua como contenedor para acceder a todos los recursos en el
        # servidor CoAP.
        self.root = root
        # Asigno la URI que se desea eliminar ('uri_to_remove') recibida como parametro al atributo de instancia
        # 'self.uri_to_remove'. Esta URI representa el recurso específico que se espera eliminar en el contexto de esta
        # instancia.
        self.uri_to_remove = uri_to_remove
        # Asigno el valor del counter recibido como parametro (counter perteneciente a la URI del EAP-PSK-1) al
        # atributo de instancia 'self.counter'
        self.counter = counter

    # Metodo que maneja los mensajes POST enviados a este recurso
    async def render_post(self, request):
        # Defino como variables globales la KDK, la AK, el ID_S y el RAND_P para almacenar sus valores
        global AK, KDK, ID_S, RAND_P
        # Muestro la información del mensaje POST recibido con el EAP-PSK-1
        print("MENSAJE POST CON EL EAP-PSK-1 RECIBIDO CON:")
        # Imprimo el codigo
        print("Código:", request.code)
        # Imprimo el payload en binario
        print("Payload:", request.payload)
        # Imprimo el payload en hexadecimal
        print("Payload hexadecimal:", request.payload.hex())
        # Asigno a la variable EAP_PSK_MSG_1 el valor hexadecimal del payload del mensaje recibido
        EAP_PSK_MSG_1 = request.payload.hex()
        # Compruebo que la cabecera del mensaje EAP-PSK-1 sea correcta
        payload1, payload_len1 = eap_hdr_validate(EAP_VENDOR_IETF, EAP_PSK_TYPE, binascii.unhexlify(EAP_PSK_MSG_1))
        # Si es correcta muestro su payload en hexadecimal (datos a partir de la cabecera) y el tamaño de su payload
        if payload1 is not None:
            print("Cabecera EAP correcta para el mensaje EAP-PSK-1!")
            print("Payload EAP del primer mensaje:", payload1.hex())
            print("Longitud del primer mensaje EAP:", payload_len1)
        else:
            print("Cabecera EAP inválida para el mensaje EAP-PSK-1")
        # Parseo el primer mensaje EAP-PSK para obtener los campos que me interesan (el ID, el flag, el RAND_S y el ID_S)
        ID_1, T_1, RAND_S, ID_S = parser_mensaje1(EAP_PSK_MSG_1)
        print("")
        # Imprimo los valores devueltos por la funcion parser_mensaje1
        print("Valores resultantes de parsear el mensaje EAP-PSK-1:")
        print("ID_1:", ID_1)
        print("T_1:", T_1)
        print("RAND_S:", RAND_S)
        print("ID_S:", ID_S)
        # Si alguna variable es None, imprimo un mensaje de error y regreso
        if None in (ID_1, T_1, RAND_S, ID_S):
            print("Error: Una o mas variables devueltas son None.")
            return
        # Compruebo que el flag es el correcto (T1 debe de ser igual a 0)
        if T_1 != 0:
            print("El flag recibido es incorrecto, se esperaba que T=0")
        else:
            print("Flag correcto, se trata del primer mensaje EAP-PSK")
        # Derivo la PSK para obtener la AK y la KDK
        AK, KDK = eap_psk_key_setup(bytes.fromhex(PSK))
        # Imprimo la AK y la KDK
        print("AK:", AK)
        print("KDK:", KDK)
        # Construccion del segundo mensaje EAP-PSK
        # Defino el codigo que va a ser 2 ya que es un respuesta
        Code_2 = "02"
        # Defino el ID que va a ser el mismo que el del primer mensaje EAP-PSK
        ID_2 = ID_1
        # Defino el tipo que va a tener el mensaje (EAP-PSK) y elimino el prefijo "0x" que se añade automaticamente en Python
        Type = hex(EAP_PSK_TYPE)[2:]
        # Defino el flag de este mensaje que debe ser 1
        T_2 = 1
        # Establezco ese flag empleando la función EAP_PSK_FLAGS_SET_T
        set_t_result_2 = EAP_PSK_FLAGS_SET_T(T_2)
        # Convierto a hexadecimal el flag y elimino el prefijo "0x" que se añade automaticamente en Python
        Flag_2 = hex(set_t_result_2)[2:]
        # Imprimo el flag para que tras el paso anterior se muestre en este caso así (T_2:40)
        print("Flag_2:", Flag_2)
        # Calculo el RAND_P en hexadecimal de forma aleatoria con un tamaño de 16 bytes
        RAND_P = os.urandom(16).hex()
        # Imprimo el RAND_P
        print("RAND_P:", RAND_P)
        # Defino el ID_P (se que es "client") y lo convierto a hexadecimal
        ID_P = binascii.hexlify("client".encode()).decode()
        # Imprimo el ID_P
        print("ID_P:", ID_P)
        # Concateno todos los campos que compondran los datos necesarios para calcular la MAC_P
        data_macp = bytes.fromhex(ID_P + ID_S + RAND_S + RAND_P)
        # Calculo la MAC_P con la funcion omac1_aes_128 pasando como parametros la AK y los datos
        MAC_P = omac1_aes_128(bytes.fromhex(AK), data_macp)
        # Imprimo el MAC_P
        print("MAC_P:", MAC_P)
        # Obtengo el tamaño total del mensaje (campo Length de la cabecera de un mensaje EAP)
        Length_2 = calcular_tamano_total_hexadecimal(Code_2, ID_2, Type, Flag_2, RAND_S, RAND_P, MAC_P, ID_P)
        # Imprimo el tamaño total del mensaje
        print("Campo Length de EAP-PSK-2:", Length_2)
        # Convierto Length_2 a hexadecimal y me aseguro de que ocupe 2 bytes (4 caracteres hexadecimales)
        Length_2_hex = f'{Length_2:04x}'
        print("Campo Length de EAP-PSK-2 hexadecimal:", Length_2_hex)
        # Concateno todos los campos (en hexadecimal) para formar el mensaje completo EAP-PSK 2
        EAP_PSK_MSG_2 = Code_2 + convertir_a_hexadecimal(ID_2) + Length_2_hex + Type + Flag_2 + RAND_S + RAND_P + MAC_P + ID_P
        # Imprimo el mensaje EAP-PSK-2
        print("Mensaje EAP-PSK-2:", EAP_PSK_MSG_2)
        # Asigno el payload de la respuesta al valor del mensaje EAP-PSK-2 en hexadecimal
        payload = EAP_PSK_MSG_2
        # Establezco el formato del contenido a OCTETSTREAM (deberia de ser COAP-EAP)
        content = ContentFormat.OCTETSTREAM
        # Construyo el mensaje de respuesta con codigo CREATED y con el payload y el content_format establecidos anteriormente
        resp = aiocoap.Message(code=Code.CREATED, payload=bytes.fromhex(payload), content_format=content)
        # Incremento el valor de la variable counter en 1
        counter = self.counter + 1
        # Creo una nueva URI concatenando 'auth/eap/' con el nuevo valor de counter (sera la que se utilizara para enviar
        # el POST con el mensaje EAP-PSK-3)
        URI = 'auth/eap/' + str(counter)
        # Divido la nueva URI en partes separadas por el caracter '/'
        URI_partes = URI.split('/')
        # Añado la URI creada a la opcion location_path del mensaje de respuesta
        resp.opt.location_path = [URI_partes[0], URI_partes[1], URI_partes[2]]
        # Indico que estoy enviando la respuesta al autenticador EAP
        print("Enviando respuesta con el segundo mensaje del metodo EAP (EAP-PSK-2) al controlador...")
        # Asocio la URI creada anteriormente con un recurso (ThirdResource) que manejara las peticiones que lleguen a esa ruta
        self.root.add_resource([URI_partes[0], URI_partes[1], URI_partes[2]], ThirdResource(self.root, URI, counter))
        # Indico que se ha agregado un nuevo recurso asociado a la uri generada
        print("Nuevo recurso agregado con URI:", URI)
        # Divido la URI que se necesita eliminar en partes separadas por el caracter '/'
        uri_to_remove_partes = self.uri_to_remove.split('/')
        # Indico que se va a eliminar el recurso SecondResource una vez que envio la respuesta y añado el nuevo recurso
        print(f"Eliminando recurso con URI: {uri_to_remove_partes[0] + '/' + uri_to_remove_partes[1] + '/' + uri_to_remove_partes[2]}")
        # Elimino el recurso con la uri asociada a este segundo recurso (SecondResource)
        self.root.remove_resource([uri_to_remove_partes[0], uri_to_remove_partes[1], uri_to_remove_partes[2]])
        print("")
        # Retorno el mensaje de respuesta
        return resp


# Clase SecondResource que manejara el mensaje EAP-PSK-3 y generara como respuesta el mensaje EAP-PSK-4
class ThirdResource(resource.Resource):
    # Defino el metodo constructor __init__, que recibe tres parametros: root, uri_to_remove y counter
    def __init__(self, root, uri_to_remove, counter):
        # Llamo al constructor de la clase base para asegurarme de que toda inicializacion en la clase padre 'Resource'
        # se realice correctamente
        super().__init__()
        # Asigno el recurso raiz 'root' recibido como parametro al atributo de instancia 'self.root'.
        # 'root' representa el recurso principal que actua como contenedor para acceder a todos los recursos en el
        # servidor CoAP.
        self.root = root
        # Asigno la URI que se desea eliminar ('uri_to_remove') recibida como parametro al atributo de instancia
        # 'self.uri_to_remove'. Esta URI representa el recurso específico que se espera eliminar en el contexto de esta
        # instancia.
        self.uri_to_remove = uri_to_remove
        # Asigno el valor del counter recibido como parametro (counter perteneciente a la URI del EAP-PSK-3) al
        # atributo de instancia 'self.counter'
        self.counter = counter

    # Metodo que maneja los mensajes POST enviados a este recurso
    async def render_post(self, request):
        # Variables globales KDK, AK, ID_S y RAND_P que me permiten utilizar sus valores almacenados
        global AK, KDK, ID_S, RAND_P
        # Muestro la informacion del mensaje POST recibido con el EAP-PSK-3
        print("MENSAJE POST CON EL EAP-PSK-3 RECIBIDO CON:")
        # Imprimo el codigo
        print("Código:", request.code)
        # Imprimo el payload en binario
        print("Payload:", request.payload)
        # Imprimo el payload en hexadecimal
        print("Payload hexadecimal:", request.payload.hex())
        # Asigno a la variable EAP_PSK_MSG_3 el valor hexadecimal del payload del mensaje recibido
        EAP_PSK_MSG_3 = request.payload.hex()
        # Compruebo que la cabecera del mensaje EAP-PSK-3 sea correcta
        payload3, payload_len3 = eap_hdr_validate(EAP_VENDOR_IETF, EAP_PSK_TYPE, bytes.fromhex(EAP_PSK_MSG_3))
        # Si es correcta muestro su payload en hexadecimal (datos a partir de la cabecera) y el tamaño de su payload
        if payload3 is not None:
            print("Cabecera EAP correcta para el mensaje EAP-PSK-3!")
            print("Payload EAP del tercer mensaje:", payload3.hex())
            print("Longitud del tercer mensaje EAP:", payload_len3)
        else:
            print("Cabecera EAP inválida para el mensaje EAP-PSK 3")
        # Parseo el tercer mensaje EAP-PSK para obtener los campos que me interesan (el ID, el flag, el RAND_S,
        # el MAC_S y el Pchannel completo, el nonce, el tag y el bit R del servidor)
        ID_3, T_3, RAND_S, MAC_S, Pchannel_Servidor, Nonce_Servidor, Tag_Servidor, R_Servidor = parser_mensaje3(EAP_PSK_MSG_3)
        print("")
        # Imprimo los valores devueltos por la funcion parser_mensaje3
        print("Valores resultantes de parsear el mensaje EAP-PSK-3:")
        print("ID_3:", ID_3)
        print("T_3:", T_3)
        print("RAND_S:", RAND_S)
        print("MAC_S:", MAC_S)
        print("Pchannel_Servidor:", Pchannel_Servidor)
        print("Nonce_Servidor:", Nonce_Servidor)
        print("Tag_Servidor:", Tag_Servidor)
        print("R_Servidor:", R_Servidor)
        # Si alguna variable es None, imprimo un mensaje de error y regreso
        if None in (ID_3, T_3, RAND_S, MAC_S, Pchannel_Servidor, Nonce_Servidor, Tag_Servidor, R_Servidor):
            print("Error: Una o mas variables devueltas son None.")
            return
        # Compruebo que el flag es el correcto (T3 debe de ser igual a 2)
        if T_3 != 2:
            print("El flag recibido es incorrecto, se esperaba que T=2")
        else:
            print("Flag correcto, se trata del tercer mensaje EAP-PSK")
        # Obtengo la TEK, la MSK y la EMSK a partir de la KDK y del RAND_P
        TEK, MSK, EMSK = eap_psk_derive_keys(bytes.fromhex(KDK), bytes.fromhex(RAND_P))
        print("TEK:", TEK)
        print("MSK:", MSK)
        print("EMSK:", EMSK)
        # Guardo la MSK en la instancia root para que sea accesible desde la clase FourthResource
        self.root.msk = MSK
        # Concateno todos los campos que compondran los datos necesarios para calcular el MAC_S
        data_macs = bytes.fromhex(ID_S + RAND_P)
        # Calculo la MAC_P con la funcion omac1_aes_128 pasando como parametros la AK y los datos
        MAC_S_Calculada = omac1_aes_128(bytes.fromhex(AK), data_macs)
        # Imprimo el MAC_S
        print("MAC_S:", MAC_S)
        # Compruebo que la MAC_S calculada coincide con la recibida
        if MAC_S_Calculada == MAC_S:
            print("La MAC_S calculada y la MAC_S recibida coinciden")
        print("Pchannel Servidor:", Pchannel_Servidor)
        # Compruebo que la longitud del Pchannel del servidor es la adecuada (21 bytes)
        if len(bytes.fromhex(Pchannel_Servidor)) < 21:
            print("La longitud del Pchannel del servidor es incorrecta, es menor de 21 bytes")
        else:
            print("La longitud del Pchannel del servidor es correcta, es de 21 bytes")
        # Obtengo los datos cifrados que son el resultado de realizar el modo EAX (es el ultimo byte del mensaje EAP-PSK-3)
        data3 = bytes.fromhex(EAP_PSK_MSG_3)[-1:]
        # Imprimo en hexadecimal los datos cifrados del Pchannel del servidor
        print("Datos cifrados Pchannel del servidor:", data3.hex())
        # Obtengo el header que son los primeros 22 bytes del mensaje EAP-PSK 3 (todos los campos anteriores al MAC_S)
        hdr3 = bytes.fromhex(EAP_PSK_MSG_3)[:22]
        # Imprimo el header del mensaje EAP-PSK-3
        print("Header EAP-PSK 3:", hdr3.hex())
        # Obtengo los datos (descifrados) que se pasaron para crear el Pchannel del servidor y el tag desencriptando del
        # Pchannel. Para ello defino un nonce que sera un array de bytes de tamaño 16 todos ellos a 0 necesario para los
        # calculos posteriores
        nonce3 = bytes(16)
        # Paso a la funcion aes_128_eax_decrypt en bytes la TEK, el nonce, el header del EAP-PSK-3, los datos cifrados,
        # el tag del Pchannel del servidor y las longitudes del nonce, del header y de los datos cifrados
        decrypted_data = aes_128_eax_decrypt(bytes.fromhex(TEK), nonce3, len(nonce3), hdr3, len(hdr3), data3, len(data3),
                                             bytes.fromhex(Tag_Servidor))
        # Si todos los parametros proporcionados son correctos, el tag del servidor pasado como parametro debera
        # coincidir con el resultante tras ejecutarse la funcion previa
        if decrypted_data == -2:
            print("El tag no coincide.")
        else:
            # De modo que obtengo e imprimo en hexadecimal los datos descifrados
            print("Datos desencriptados:", decrypted_data.hex())
        # Miro a ver si el campo R del Pchannel del servidor es un DONE_SUCCESS o un DONE_FAILURE
        verificar_r_flag(decrypted_data.hex())
        # Por ultimo calculo el Pchannel del servidor
        # Para ello defino un tag que será inicialmente un array de bytes de tamaño 16 todos ellos a 0
        tag3 = bytearray(16)
        # Paso a la funcion aes_128_eax_encrypt en bytes la TEK, el nonce, el header del EAP-PSK-3, los datos
        # descifrados, el tag y las longitudes del nonce, del header y de los datos descifrados para así obtener los
        # datos cifrados de forma calculada
        encrypted_data_calc_serv = aes_128_eax_encrypt(bytes.fromhex(TEK), nonce3, len(nonce3), hdr3, len(hdr3),
                                                       decrypted_data, len(decrypted_data), tag3)
        # Construyo el Pchannel del servidor concatenando los últimos 4 bytes del nonce, los 16 bytes del tag resultante
        # tras ejecutarse la funcion anterior y los datos encriptados
        encrypted_pchannel_calc_serv = nonce3[-4:] + tag3 + encrypted_data_calc_serv
        # Imprimo en hexadecimal los datos encriptados calculados que compondran el Pchannel del servidor
        print("Datos encriptados del Pchannel del servidor calculados:", encrypted_data_calc_serv.hex())
        # Imprimo en hexadecimal el tag calculado que compondra el Pchannel del servidor
        print("Tag del Pchannel del servidor calculado:", tag3.hex())
        # Imprimo en hexadecimal el Pchannel del servidor encriptado calculado
        print("Pchannel del servidor encriptado calculado:", encrypted_pchannel_calc_serv.hex())
        # Compruebo si el Pchannel del servidor calculado coincide con el recibido
        if encrypted_pchannel_calc_serv.hex() == Pchannel_Servidor:
            print("El Pchannel del servidor recibido coincide con el calculado, es correcto!")
        print("")
        # Construcción del cuarto mensaje EAP-PSK
        # Defino el código que va a ser 2 que que es el segundo mensaje
        Code_4 = "02"
        # Defino el ID que va a ser el mismo que el del tercer mensaje EAP-PSK
        ID_4 = ID_3
        # Defino el tipo que va a tener el mensaje (EAP-PSK) y elimino el prefijo "0x" que se añade automáticamente en Python
        Type = hex(EAP_PSK_TYPE)[2:]
        # Defino el flag de este mensaje que debe ser 3
        T_4 = 3
        # Establezco ese flag empleando la funcion EAP_PSK_FLAGS_SET_T
        set_t_result_4 = EAP_PSK_FLAGS_SET_T(T_4)
        # Convierto a hexadecimal el flag y elimino el prefijo "0x" que se añade automaticamente en Python
        Flag_4 = hex(set_t_result_4)[2:]
        print("Flag_4:", Flag_4)
        # Obtengo el tamaño total del mensaje EAP-PSK 4 (tamaño de los campos de la cabecera (Code, ID y Type) + tamaño
        # del Flag_4 + tamaño del RAND_S + tamaño del Pchannel del peer (21 bytes))
        Length_4 = calcular_tamano_total_hexadecimal(Code_4, ID_4, Type, Flag_4, RAND_S) + 21
        # Imprimo el tamaño total del mensaje EAP-PSK-4
        print("Campo Length de EAP-PSK-4:", Length_4)
        # Convierto Length_4 a hexadecimal y me aseguro de que ocupe 2 bytes (4 caracteres hexadecimales)
        Length_4_hex = f'{Length_4:04x}'
        print("Campo Length de EAP-PSK-4 en hexadecimal:", Length_4_hex)
        # Obtengo el header que son los primeros 22 bytes del mensaje EAP-PSK 4 (todos los campos anteriores al Pchannel del par)
        hdr4 = bytes.fromhex(Code_4 + convertir_a_hexadecimal(ID_4) + Length_4_hex + Type + Flag_4 + RAND_S)
        # Imprimo el header del mensaje EAP-PSK-4
        print("Header de EAP-PSK-4:", hdr4.hex())
        # Compruebo si el tamaño de los datos que van a formar parte del Pchannel del peer es de 1 byte o más
        left = Length_4 - 4 - 16 - len(hdr4)
        data_len = 1
        if (decrypted_data[0] & EAP_PSK_E_FLAG) and left > 1:
            data_len += 1
        plen = 4 + 16 + data_len
        # Imprimo el tamaño de los datos del Pchannel del peer
        print("Tamaño de los datos del Pchannel del peer:", data_len)
        # Imprimo el tamaño total del Pchannel del peer
        print("Tamaño del Pchannel del peer:", plen)
        # Obtengo el dato descifrado (texto plano) que va a ir en el Pchannel del peer en funcion de si R es un DONE_SUCCES u otro tipo
        # Inicializo la variable failed para rastrear si ha ocurrido un error durante el proceso
        failed = 0
        # Verifico si el primer byte de los datos desencriptados tiene activada la bandera "E" (extension)
        if decrypted_data[0] & EAP_PSK_E_FLAG:
            # Si la bandera "E" esta activada, imprimo un mensaje de advertencia indicando que no es compatible
            print("EAP-PSK: Flag E (Ext) no soportado")
            # Marco el proceso como fallido
            failed = 1
            # Construyo los datos desencriptados indicando un fallo, desplazando la bandera de fallo 6 bits e incluyendo la bandera "E"
            decrypted_data_ = (EAP_PSK_R_FLAG_DONE_FAILURE << 6) | EAP_PSK_E_FLAG
        # Si no hay una bandera "E", pero hubo un fallo en algun paso anterior
        elif failed:
            # Construyo los datos desencriptados indicando fallo, sin incluir la bandera "E"
            decrypted_data_ = EAP_PSK_R_FLAG_DONE_FAILURE << 6
        # Si no hubo fallos y la bandera "E" no esta activada
        else:
            # Construyo los datos desencriptados indicando exito, desplazando la bandera de exito 6 bits
            decrypted_data_ = EAP_PSK_R_FLAG_DONE_SUCCESS << 6
        # Asigno a la variable data4 el valor de los datos desencriptados en bytes que formaran el Pchannel del par
        data4 = bytes.fromhex(hex(decrypted_data_)[2:])
        # Imprimo si hubo fallo
        print("¿Hubo fallo?:", "Sí" if failed == 1 else "No")
        # Imprimo los datos descifrados del Pchannel del peer
        print("Datos descifrados (texto plano) del Pchannel del peer:", data4.hex())
        # Calculo el Pchannel del peer
        # Para ello defino un nonce que sera un array de bytes de tamaño 16 todos ellos a 0 menos el ultimo bit que sera un 1
        nonce4 = bytearray(16)
        nonce4[-1] = 1
        # Tambien defino un tag que sera inicialmente un array de bytes de tamaño 16 todos ellos a 0
        tag4 = bytearray(16)
        # Paso a la funcion aes_128_eax_encrypt en bytes la TEK, el nonce, el header del EAP-PSK-4, los datos descifrados, el tag
        # y las longitudes del nonce, del header y de los datos descifrados para así calcular los datos cifrados
        encrypted_data_peer = aes_128_eax_encrypt(bytes.fromhex(TEK), nonce4, len(nonce4), hdr4, len(hdr4), data4, len(data4), tag4)
        # Construyo el Pchannel del par EAP concatenando los últimos 4 bytes del nonce, los 16 bytes del tag resultante
        # tras ejecutarse la funcion anterior y los datos encriptados
        Pchannel_Peer = nonce4[-4:] + tag4 + encrypted_data_peer
        # Imprimo los datos encriptados calculados del Pchannel del peer
        print("Datos encriptados del Pchannel del peer:", encrypted_data_peer.hex())
        # Imprimo el Tag calculado del Pchannel del peer
        print("Tag del Pchannel del peer:", tag4.hex())
        # Imprimo en hexadecimal el Pchannel del peer encriptado calculado
        print("Pchannel del peer encriptado calculado:", Pchannel_Peer.hex())
        # Concateno todos los campos (en hexadecimal) para formar el mensaje completo EAP-PSK 4
        EAP_PSK_MSG_4 = Code_4 + convertir_a_hexadecimal(ID_4) + Length_4_hex + Type + Flag_4 + RAND_S + Pchannel_Peer.hex()
        # Imprimo el mensaje EAP-PSK-4
        print("Mensaje EAP-PSK-4:", EAP_PSK_MSG_4)
        # Asigno el payload de la respuesta al valor del mensaje EAP-PSK-4 en hexadecimal
        payload = EAP_PSK_MSG_4
        # Establezco el formato del contenido a OCTETSTREAM (deberia de ser COAP-EAP)
        content = ContentFormat.OCTETSTREAM
        # Construyo el mensaje de respuesta con codigo CREATED y con el payload y el content_format establecidos anteriormente
        resp = aiocoap.Message(code=Code.CREATED, payload=bytes.fromhex(payload), content_format=content)
        # Incremento el valor de la variable counter en 1
        counter = self.counter + 1
        # Creo una nueva URI concatenando 'auth/eap/' con el nuevo valor de counter (sera la que se utilizara para enviar
        # el POST con el mensaje EAP-Success)
        URI = 'auth/eap/' + str(counter)
        # Divido la nueva URI en partes separadas por el caracter '/'
        URI_partes = URI.split('/')
        # Añado la URI creada a la opcion location_path del mensaje de respuesta
        resp.opt.location_path = [URI_partes[0], URI_partes[1], URI_partes[2]]
        # Indico que estoy enviando la respuesta al autenticador EAP
        print("Enviando respuesta con el cuarto mensaje del metodo EAP (EAP-PSK-4) al controlador...")
        # Asocio la URI creada anteriormente con un recurso (FourthResource) que manejara las peticiones que lleguen a esa ruta
        self.root.add_resource([URI_partes[0], URI_partes[1], URI_partes[2]], FourthResource(self.root, URI, counter))
        # Indico que se ha agregado un nuevo recurso asociado a la uri generada
        print("Nuevo recurso agregado con URI:", URI)
        # Divido la URI que se necesita eliminar en partes separadas por el caracter '/'
        uri_to_remove_partes = self.uri_to_remove.split('/')
        # Indico que se va a eliminar el recurso ThirdResource una vez que envio la respuesta y añado el nuevo recurso
        print(f"Eliminando recurso con URI: {uri_to_remove_partes[0] + '/' + uri_to_remove_partes[1] + '/' + uri_to_remove_partes[2]}")
        # Elimino el recurso con la uri asociada a este tercer recurso (ThirdResource)
        self.root.remove_resource([uri_to_remove_partes[0], uri_to_remove_partes[1], uri_to_remove_partes[2]])
        print("")
        # Retorno el mensaje de respuesta
        return resp


# Clase FourthResource que manejara el mensaje EAP-Success y generara como respuesta el mensaje con codigo CHANGED
class FourthResource(resource.Resource):
    # Defino el metodo constructor __init__, que recibe tres parametros: root, uri_to_remove y counter
    def __init__(self, root, uri_to_remove, counter):
        # Llamo al constructor de la clase base para asegurarme de que toda inicializacion en la clase padre 'Resource'
        # se realice correctamente
        super().__init__()
        # Asigno el recurso raiz 'root' recibido como parametro al atributo de instancia 'self.root'.
        # 'root' representa el recurso principal que actua como contenedor para acceder a todos los recursos en el
        # servidor CoAP.
        self.root = root
        # Asigno la URI que se desea eliminar ('uri_to_remove') recibida como parametro al atributo de instancia
        # 'self.uri_to_remove'. Esta URI representa el recurso específico que se espera eliminar en el contexto de esta
        # instancia.
        self.uri_to_remove = uri_to_remove
        # Asigno el valor del counter recibido como parametro (counter perteneciente a la URI del EAP-Success) al
        # atributo de instancia 'self.counter'
        self.counter = counter

    # Metodo que maneja los mensajes POST enviados a este recurso
    async def render_post(self, request):
        try:
            # Muestro el mensaje POST protegido con OSCORE recibido con el EAP-SUCCESS
            print("Mensaje POST con el EAP-SUCCESS protegido con OSCORE recibido:", request.payload.hex())
            print("")
            # Accedo a la MSK guardada en la clase ThirdResource a traves de root
            MSK = bytes.fromhex(self.root.msk)
            # Accedo al payload del EAP Request ID guardado en la clase FirstResource a traves de root
            first_resource_payload = self.root.first_resource_payload
            # Accedo a la estructura CBOR guardada en la clase FirstResource a traves de root
            cbor_payload = self.root.cbor_payload
            # Concateno el contenido de la negociacion del conjunto de cifrado, es decir, la lista de conjuntos de cifrado
            # enviados por el autenticador EAP en el EAP Request ID concatenada a la opcion seleccionada por el par EAP en el
            # EAP Response ID y lo convierto a hexadecimal
            CS = first_resource_payload[-9:-3].hex() + cbor_payload[2:4].hex()
            # Derivo las claves OSCORE (Master Secret y Master Salt) usando la MSK y el CS
            MASTER_SECRET, MASTER_SALT = derive_oscore_keys(MSK, CS)
            # Asigno a la variable SECRET el valor de la Master Secret y a la variable SALT el valor de la Master Salt obtenidos
            # en la derivacion de las claves OSCORE convertidos a bytes
            SECRET = bytes.fromhex(MASTER_SECRET)
            SALT = bytes.fromhex(MASTER_SALT)
            # Defino el ID del contexto OSCORE del par EAP (tiene que ser el mismo que el del autenticador EAP) y lo convierto a bytes
            ID_CTX = bytes.fromhex("37cbf3210017a2d3")
            # Defino el mensaje protegido que quiero desproteger (el mensaje EAP-SUCCESS protegido), convirtiendolo de hexadecimal a bytes
            PROTECTED_MESSAGE = bytes.fromhex(request.payload.hex())
            # Establezco el algoritmo AEAD y el algoritmo hash seleccionados por el par EAP
            default_algorithm = aiocoap.oscore.algorithms[self.root.algoritmo_AEAD]  # Algoritmo AES_CCM
            default_hashfun = aiocoap.oscore.hashfunctions[self.root.algoritmo_hash]  # Funcion hash SHA-256

            # Defino una clase de contexto de seguridad personalizada que hereda de CanProtect (permite proteger los mensajes CoAP),
            # CanUnprotect (maneja la recepción y el procesamiento de mensajes que han sido protegidos, asegurando que se puedan
            # desproteger y validar correctamente) y SecurityContextUtils (ofrece utilidades relacionadas con el contexto de seguridad)
            class OscoreSecurityContext(CanProtect, CanUnprotect, SecurityContextUtils):
                def __init__(self):
                    # Inicializo la clase base
                    super().__init__()
                    # Establezco una ventana de repeticion con un tamaño de 32
                    self.recipient_replay_window = ReplayWindow(32, lambda: None)
                    # Inicializo la recuperacion de eco como None
                    self.echo_recovery = None

                # Metodo que se llama al intentar incrementar el numero de secuencia, pero no hace nada (es necesario
                # definirlo para que la clase funcione ya que post_seqnoincrease esta definido en CanProtect como un metodo
                # abstracto, lo que implica que cualquier clase que herede de CanProtect debe implementar este metodo)
                def post_seqnoincrease(self):
                    pass

            # Creo el contexto de seguridad del par EAP instanciando la clase OscoreSecurityContext
            secctx = OscoreSecurityContext()
            # Establezco el algoritmo AEAD que voy a utilizar en el contexto de seguridad
            secctx.alg_aead = default_algorithm
            # Establezco la funcion hash que voy a utilizar en el contexto de seguridad
            secctx.hashfun = default_hashfun
            # El par EAP utiliza el ID de Destinatario del autenticador EAP (RID-C) como ID de Remitente para su contexto de remitente en OSCORE
            secctx.sender_id = self.root.rid_c
            # El par EAP usa el ID de Destinatario del par EAP (RID-I) como ID de Destinatario para su contexto de destinatario
            secctx.recipient_id = self.root.rid_i
            # Establezco el ID de contexto
            secctx.id_context = ID_CTX
            # Llamo a la funcion derive_keys para obtener la clave de remitente, la clave de destinatario y el IV comun a partir
            # del algoritmo AEAD, la funcion hash y el ID de contexto ya configurados de antemano, y a partir de la Master Secret
            # y de la Master Salt pasadas como parametros
            secctx.derive_keys(SALT, SECRET)
            # Fijo el numero de secuencia del remitente en 20 (tiene que ser el mismo que el del contexto Oscore del autenticador EAP)
            secctx.sender_sequence_number = 20
            # Inicializo la ventana de repeticion como vacia
            secctx.recipient_replay_window.initialize_empty()
            # Imprimo la cadena CS resultante
            print("CS:", CS)
            # Imprimo los parametros del Contexto Comun del contexto de seguridad OSCORE del autenticador EAP
            print("Parámetros del Contexto Común del contexto de seguridad OSCORE del autenticador EAP:")
            print("Algoritmo AEAD:", self.root.algoritmo_AEAD)
            print("Algoritmo HKDF:", self.root.algoritmo_hash)
            print("Secreto Maestro (Master Secret):", MASTER_SECRET)
            print("Sal Maestra (Master Salt):", MASTER_SALT)
            print("ID del Contexto (Context ID):", ID_CTX.hex())
            print("IV Común (Common IV):", secctx.common_iv.hex())
            # Imprimo los parametros del Contexto de Remitente del contexto de seguridad OSCORE del autenticador EAP
            print("Parámetros del Contexto de Remitente del contexto de seguridad OSCORE del autenticador EAP:")
            print("ID del Remitente (Sender ID):", secctx.sender_id.hex())
            print("Clave del Remitente (Sender Key):", secctx.sender_key.hex())
            print("Número de secuencia del Remitente (Sender sequence number):", secctx.sender_sequence_number)
            # Imprimo los parametros del Contexto de Destinatario del contexto de seguridad OSCORE del autenticador EAP
            print("Parámetros del Contexto de Destinatario del contexto de seguridad OSCORE del autenticador EAP:")
            print("ID del Destinatario (Recipient ID):", secctx.recipient_id.hex())
            print("Clave del Destinatario (Recipient Key):", secctx.recipient_key.hex())
            print("Ventana de repetición (Replay Window): Ventana deslizante anti-repetición de tamaño",
                  secctx.recipient_replay_window.get_size(), "mensajes")
            print("")
            # Decodifico el mensaje EAP-SUCCESS protegido desde el formato hexadecimal a un objeto de mensaje CoAP de aiocoap
            outer_message = aiocoap.Message.decode(PROTECTED_MESSAGE)
            # Desprotejo el mensaje protegido usando el contexto de seguridad OSCORE del par EAP
            unprotected_message, _ = secctx.unprotect(outer_message)
            # Asigno el tipo de mensaje del mensaje protegido al mensaje desprotegido
            unprotected_message.mtype = outer_message.mtype
            # Asigno el ID de mensaje del mensaje protegido al mensaje desprotegido
            unprotected_message.mid = outer_message.mid
            # Asigno el token del mensaje protegido al mensaje desprotegido
            unprotected_message.token = outer_message.token
            # Asigno la opcion URI_HOST del mensaje protegido al mensaje desprotegido
            unprotected_message.opt.uri_host = outer_message.opt.uri_host
            # Codifico el mensaje desprotegido a bytes
            encoded_unprotected_message = unprotected_message.encode()
            # Imprimo el mensaje EAP-SUCCESS desprotegido en formato hexadecimal
            print("Mensaje EAP-SUCCESS desprotegido:", encoded_unprotected_message.hex())
            # Muestro la informacion del mensaje POST recibido con el EAP-Success
            print("MENSAJE POST EAP-SUCCESS RECIBIDO (YA DESPROTEGIDO) CON:")
            # Imprimo el codigo
            print("Código:", request.code)
            # Imprimo el payload en binario (son los ultimos 9 bytes del payload ya que el resto son los demas campos del
            # mensaje EAP-SUCCESS desprotegidos)
            print("Payload:", bytes.fromhex(encoded_unprotected_message.hex())[-9:])
            # Imprimo el payload en hexadecimal
            print("Payload hexadecimal:", bytes.fromhex(encoded_unprotected_message.hex())[-9:].hex())
            # Deserializo la estructura CBOR del payload del EAP-Success para extraer el tiempo de vida de la sesion
            deserialized_info = cbor2.loads(bytes.fromhex(encoded_unprotected_message.hex())[-5:])
            # Extraigo el tiempo de vida de la sesion y lo asigno a la variable sesion_lifetime
            sesion_lifetime = deserialized_info[1]
            # Imprimo el tiempo de vida de la sesion extraido
            print("Tiempo de vida de la sesión:", sesion_lifetime, "segundos, es decir, ", sesion_lifetime // 3600, "horas")
            # Establezco el formato del contenido a OCTETSTREAM (deberia de ser COAP-EAP)
            content = ContentFormat.OCTETSTREAM
            # El payload de la respuesta sera la palabra "FIN" codificada en binario
            payload = "FIN".encode()
            # Construyo el mensaje de respuesta con codigo CHANGED y con el payload y el content_format establecidos anteriormente
            resp = aiocoap.Message(code=Code.CHANGED, payload=payload, content_format=content)
            # Asigno el tipo de mensaje para la respuesta, en este caso lo configuro como ACK
            resp.mtype = aiocoap.ACK
            # Asigno el ID de mensaje de la solicitud, es decir, del mensaje EAP-SUCCESS desprotegido para asegurar la unicidad
            resp.mid = unprotected_message.mid
            # Codifico la respuesta a formato hexadecimal
            resp_HEX = resp.encode().hex()
            # Decodifico el mensaje de la respuesta desde el formato hexadecimal a un objeto de mensaje CoAP sin proteccion
            unprotected = aiocoap.Message.decode(bytes.fromhex(resp_HEX))
            # Obtengo el ID del Remitente de la solicitud, es decir, del mensaje EAP-SUCCESS protegido recibido por el par,
            # que coincidira con el ID de Destinatario del contexto de seguridad del par EAP
            request_sender_id = secctx.recipient_id
            # Defino el valor del PIV de la solicitud
            request_piv_short = b"\x14"
            # Construyo el nonce de la solicitud usando el PIV y el ID de Remitente de la solicitud
            request_nonce = secctx._construct_nonce(request_piv_short, request_sender_id)
            # Protejo el mensaje de respuesta usando el contexto de seguridad y la informacion de la solicitud
            protected_message, _ = secctx.protect(
                unprotected,  # Mensaje desprotegido que quiero proteger
                aiocoap.oscore.RequestIdentifiers(
                    request_sender_id,  # ID del remitente
                    request_piv_short,  # Valor corto de PIV
                    request_nonce,  # Nonce generado
                    True,  # Indica si es un mensaje de confirmacion
                    aiocoap.POST  # Metodo de la solicitud (POST)
                ),
            )
            # Asigno el ID de mensaje del mensaje desprotegido al mensaje protegido
            protected_message.mid = unprotected.mid
            # Asigno el token del mensaje desprotegido al mensaje protegido
            protected_message.token = unprotected.token
            # Asigno el tipo de mensaje del mensaje desprotegido al mensaje protegido
            protected_message.mtype = unprotected.mtype
            # Codifico el mensaje protegido a bytes
            encoded_protected_message = protected_message.encode()
            # Imprimo el mensaje CHANGED protegido en formato hexadecimal
            print("Mensaje CHANGED protegido por OSCORE:", encoded_protected_message.hex())
            # Construyo un nuevo mensaje de respuesta CoAP con codigo CHANGED enviando en el payload el mensaje CHANGED
            # protegido con OSCORE y con el content_format establecido anteriormente
            resp_prot = aiocoap.Message(code=Code.CHANGED, payload=bytes.fromhex(encoded_protected_message.hex()), content_format=content)
            # Indico que estoy enviando la respuesta al autenticador EAP y que, tras esto, el dispositivo IOT estara autenticado correctamente
            print("Enviando respuesta CHANGED al controlador...")
            print("Dispositivo IOT autenticado con éxito")
            print("")
            # Retorno el mensaje de respuesta
            return resp_prot
        except Exception as e:
            # Si ocurre un error en la autenticacion, capturo la excepción y respondo con 4.01 Unauthorized
            # Esto asegura que si hay un fallo, el servidor responde de manera controlada.
            print(f"Error al desproteger o procesar el mensaje, el dispositivo IoT no está autorizado: {e}")
            print("")
            # Retorno el mensaje de respuesta
            return Message(code=Code.UNAUTHORIZED, payload=b"Fallo en la autenticacion", content_format=ContentFormat.OCTETSTREAM)

    # Metodo que maneja los mensajes DELETE enviados a este recurso (solo tiene esta funcion este ultimo recurso
    # ya que es al que el autenticador EAP (Controlador) debe enviar el DELETE si considera necesario eliminar
    # el "estado" CoAP-EAP del peer (cliente), es decir, si quiere que el dispositivo IOT deje de estar autenticado
    # antes de que caduque la sesion)
    async def render_delete(self, request):
        # Muestro el mensaje DELETE protegido con OSCORE recibido
        print("Mensaje DELETE al último recurso protegido con OSCORE recibido:", request.payload.hex())
        # Accedo a la MSK guardada en la clase ThirdResource a traves de root
        MSK = bytes.fromhex(self.root.msk)
        # Accedo al payload del EAP Request ID guardado en la clase FirstResource a traves de root
        first_resource_payload = self.root.first_resource_payload
        # Accedo a la estructura CBOR guardada en la clase FirstResource a traves de root
        cbor_payload = self.root.cbor_payload
        # Concateno el contenido de la negociacion del conjunto de cifrado, es decir, la lista de conjuntos de cifrado
        # enviados por el autenticador EAP en el EAP Request ID concatenada a la opcion seleccionada por el par EAP en el
        # EAP Response ID y lo convierto a hexadecimal
        CS = first_resource_payload[-9:-3].hex() + cbor_payload[2:4].hex()
        # Derivo las claves OSCORE (Master Secret y Master Salt) usando la MSK y el CS
        MASTER_SECRET, MASTER_SALT = derive_oscore_keys(MSK, CS)
        # Asigno a la variable SECRET el valor de la Master Secret y a la variable SALT el valor de la Master Salt obtenidos
        # en la derivacion de las claves OSCORE convertidos a bytes
        SECRET = bytes.fromhex(MASTER_SECRET)
        SALT = bytes.fromhex(MASTER_SALT)
        # Defino el ID del contexto OSCORE del par EAP (tiene que ser el mismo que el del autenticador EAP) y lo convierto a bytes
        ID_CTX = bytes.fromhex("37cbf3210017a2d3")
        # Defino el mensaje protegido que quiero desproteger (el mensaje DELETE protegido), convirtiendolo de hexadecimal a bytes
        PROTECTED_MESSAGE = bytes.fromhex(request.payload.hex())
        # Establezco el algoritmo AEAD y el algoritmo hash seleccionados por el par EAP
        default_algorithm = aiocoap.oscore.algorithms[self.root.algoritmo_AEAD]  # Algoritmo AES_CCM
        default_hashfun = aiocoap.oscore.hashfunctions[self.root.algoritmo_hash]  # Funcion hash SHA-256

        # Defino una clase de contexto de seguridad personalizada que hereda de CanProtect (permite proteger los mensajes CoAP),
        # CanUnprotect (maneja la recepción y el procesamiento de mensajes que han sido protegidos, asegurando que se puedan
        # desproteger y validar correctamente) y SecurityContextUtils (ofrece utilidades relacionadas con el contexto de seguridad)
        class OscoreSecurityContext(CanProtect, CanUnprotect, SecurityContextUtils):
            def __init__(self):
                # Inicializo la clase base
                super().__init__()
                # Establezco una ventana de repeticion con un tamaño de 32
                self.recipient_replay_window = ReplayWindow(32, lambda: None)
                # Inicializo la recuperacion de eco como None
                self.echo_recovery = None

            # Metodo que se llama al intentar incrementar el numero de secuencia, pero no hace nada (es necesario
            # definirlo para que la clase funcione ya que post_seqnoincrease esta definido en CanProtect como un metodo
            # abstracto, lo que implica que cualquier clase que herede de CanProtect debe implementar este metodo)
            def post_seqnoincrease(self):
                pass

        # Creo el contexto de seguridad del par EAP instanciando la clase OscoreSecurityContext
        secctx = OscoreSecurityContext()
        # Establezco el algoritmo AEAD que voy a utilizar en el contexto de seguridad
        secctx.alg_aead = default_algorithm
        # Establezco la funcion hash que voy a utilizar en el contexto de seguridad
        secctx.hashfun = default_hashfun
        # El par EAP utiliza el ID de Destinatario del autenticador EAP (RID-C) como ID de Remitente para su contexto de remitente en OSCORE
        secctx.sender_id = self.root.rid_c
        # El par EAP usa el ID de Destinatario del par EAP (RID-I) como ID de Destinatario para su contexto de destinatario
        secctx.recipient_id = self.root.rid_i
        # Establezco el ID de contexto
        secctx.id_context = ID_CTX
        # Llamo a la funcion derive_keys para obtener la clave de remitente, la clave de destinatario y el IV comun a partir
        # del algoritmo AEAD, la funcion hash y el ID de contexto ya configurados de antemano, y a partir de la Master Secret
        # y de la Master Salt pasadas como parametros
        secctx.derive_keys(SALT, SECRET)
        # Fijo el numero de secuencia del remitente en 20 (tiene que ser el mismo que el del contexto Oscore del autenticador EAP)
        secctx.sender_sequence_number = 20
        # Inicializo la ventana de repeticion como vacia
        secctx.recipient_replay_window.initialize_empty()
        # Decodifico el mensaje DELETE protegido desde el formato hexadecimal a un objeto de mensaje CoAP sin proteccion
        outer_message = aiocoap.Message.decode(PROTECTED_MESSAGE)
        # Desprotejo el mensaje protegido usando el contexto de seguridad OSCORE del par EAP
        unprotected_message, _ = secctx.unprotect(outer_message)
        # Asigno el tipo de mensaje del mensaje protegido al mensaje desprotegido
        unprotected_message.mtype = outer_message.mtype
        # Asigno el ID de mensaje del mensaje protegido al mensaje desprotegido
        unprotected_message.mid = outer_message.mid
        # Asigno el token del mensaje protegido al mensaje desprotegido
        unprotected_message.token = outer_message.token
        # Asigno el atributo URI_HOST del mensaje protegido al mensaje desprotegido
        unprotected_message.opt.uri_host = outer_message.opt.uri_host
        # Codifico el mensaje desprotegido a bytes
        encoded_unprotected_message = unprotected_message.encode()
        # Imprimo el mensaje DELETE desprotegido en formato hexadecimal
        print("Mensaje DELETE al último recurso desprotegido:", encoded_unprotected_message.hex())
        # Muestro la informacion del mensaje DELETE recibido
        print("MENSAJE DELETE AL ÚLTIMO RECURSO RECIBIDO (YA DESPROTEGIDO) CON:")
        # Imprimo el codigo
        print("Código:", request.code)
        # Imprimo el payload en binario (son los ultimos 25 bytes del payload ya que el resto son los demas campos del
        # mensaje DELETE desprotegidos)
        print("Payload:", bytes.fromhex(encoded_unprotected_message.hex())[-25:])
        # Imprimo el payload en hexadecimal
        print("Payload hexadecimal:", bytes.fromhex(encoded_unprotected_message.hex())[-25:].hex())
        # Establezco el formato del contenido a OCTETSTREAM (deberia de ser COAP-EAP)
        content = ContentFormat.OCTETSTREAM
        # El payload de la respuesta sera, por ejemplo, la frase "MENSAJE DELETE RECIBIDO" codificada en binario
        payload = "MENSAJE DELETE RECIBIDO".encode()
        # Construyo el mensaje de respuesta con codigo DELETED y con el payload y el content_format establecidos anteriormente
        resp = aiocoap.Message(code=Code.DELETED, payload=payload, content_format=content)
        # Asigno el tipo de mensaje para la respuesta, en este caso lo configuro como ACK
        resp.mtype = aiocoap.ACK
        # Asigno el ID de mensaje de la solicitud, es decir, del mensaje DELETE desprotegido para asegurar la unicidad
        resp.mid = unprotected_message.mid
        # Codifico la respuesta a formato hexadecimal
        resp_HEX = resp.encode().hex()
        # Decodifico el mensaje de la respuesta desde el formato hexadecimal a un objeto de mensaje CoAP sin proteccion
        unprotected = aiocoap.Message.decode(bytes.fromhex(resp_HEX))
        # Obtengo el ID del Remitente de la solicitud, es decir, del mensaje DELETE protegido recibido por el par,
        # que coincidira con el ID de Destinatario del contexto de seguridad del par EAP
        request_sender_id = secctx.recipient_id
        # Defino un valor corto de PIV (Pseudorandom IV)
        request_piv_short = b"\x14"
        # Construyo un nonce para proteger el mensaje de respuesta usando el PIV y el ID de Remitente de la solicitud
        request_nonce = secctx._construct_nonce(request_piv_short, request_sender_id)
        # Protejo el mensaje usando el contexto de seguridad y la informacion de la solicitud
        protected_message, _ = secctx.protect(
            unprotected,  # Mensaje desprotegido que quiero proteger
            aiocoap.oscore.RequestIdentifiers(
                request_sender_id,  # ID del remitente
                request_piv_short,  # Valor corto de PIV
                request_nonce,  # Nonce generado
                True,  # Indica si es un mensaje de confirmacion
                aiocoap.DELETE  # Metodo de la solicitud (DELETE)
            ),
        )
        # Asigno el ID de mensaje del mensaje desprotegido al mensaje protegido
        protected_message.mid = unprotected.mid
        # Asigno el token del mensaje desprotegido al mensaje protegido
        protected_message.token = unprotected.token
        # Asigno el tipo de mensaje del mensaje desprotegido al mensaje protegido
        protected_message.mtype = unprotected.mtype
        # Codifico el mensaje protegido a bytes
        encoded_protected_message = protected_message.encode()
        # Imprimo el mensaje DELETED protegido en formato hexadecimal
        print("Mensaje DELETED protegido por OSCORE:", encoded_protected_message.hex())
        # Construyo un nuevo mensaje de respuesta CoAP con codigo DELETED enviando en el payload el mensaje DELETED
        # protegido con OSCORE y con el content_format establecido anteriormente
        resp_prot = aiocoap.Message(code=Code.DELETED, payload=bytes.fromhex(encoded_protected_message.hex()), content_format=content)
        # Indico que estoy enviando la respuesta al autenticador EAP y que, tras esto, el dispositivo IOT dejara de estar autenticado
        print("Enviando respuesta DELETED al controlador...")
        print("Dispositivo IOT eliminado del dominio de autenticación con éxito")
        # Divido la URI que se necesita eliminar en partes separadas por el caracter '/'
        uri_to_remove_partes = self.uri_to_remove.split('/')
        # Indico que se va a eliminar el recurso FourthResource una vez que envio la respuesta
        print(f"Eliminando recurso con URI: {uri_to_remove_partes[0] + '/' + uri_to_remove_partes[1] + '/' + uri_to_remove_partes[2]}")
        # Elimino el recurso con la uri asociada a este cuarto recurso (FourthResource)
        self.root.remove_resource([uri_to_remove_partes[0], uri_to_remove_partes[1], uri_to_remove_partes[2]])
        print("")
        # Retorno el mensaje de respuesta
        return resp_prot


# Establezco que, por defecto, solo se registren mensajes de nivel INFO o superior
logging.basicConfig(level=logging.INFO)
# Permito que, específicamente para el logger llamado "coap-server", se registren mensajes de nivel DEBUG
logging.getLogger("coap-server").setLevel(logging.DEBUG)


async def main():
    # El par EAP unicamente actuara como cliente para enviar el primer mensaje a la uri ".well-known/coap-eap"
    # Creo un contexto de cliente CoAP que me permitira enviar peticiones CoAP al controller
    context = await Context.create_client_context()
    # Establezco el formato del primer mensaje a LINKFORMAT (cumpliendo con lo establecido en el Draft)
    content_format = ContentFormat.LINKFORMAT
    # Genero un numero entero aleatorio entre 1 y 100
    counter = random.randint(1, 100)
    # Creo una URI concatenando el valor aleatorio generado con 'auth/eap/'. 'auth' es la ruta local del dispositivo IoT
    # que hace que la ruta sea unica, 'eap' indica que la URI es para el par EAP y counter es un numero unico que se
    # incrementara con cada nueva solicitud EAP
    URI_aleatoria = 'auth/eap/' + str(counter)
    # Imprimo la URI generada para ver el resultado
    print(URI_aleatoria)
    # Divido la URI en partes separadas por el caracter '/'
    URI_aleatoria_partes = URI_aleatoria.split('/')
    # El payload en este primer mensaje sera la URI creada en el paso anterior
    payload_hex = URI_aleatoria.encode('utf-8').hex()
    # Imprimo el payload del mensaje well-known/coap-eap
    print("Payload del mensaje well-known/coap-eap:", payload_hex)
    # Convierto a bytes el payload
    payload = bytes.fromhex(payload_hex)
    # Construyo el mensaje de solicitud con codigo POST a la uri indicada, con el payload y el content_format establecidos anteriormente
    # La uri indicada contiene la direccion IPv4 del Adaptador de LAN inalambrica Wi-Fi 2, que se obtiene llamando a la
    # funcion get_wipi_ip del script redes.py, para vincularlo con el contexto del servidor del controller ya que
    # escucha en esa direccion
    wifi = get_wifi_ip()
    request = Message(code=Code.POST, payload=payload, uri="coap://" + wifi + "/.well-known/coap-eap", content_format=content_format)
    # Marco la opción no_response a true para que no sea necesario recibir una respuesta a este primer mensaje
    # (por motivos de la implementacion de la biblioteca es necesario de todas formas que se reciba una respuesta)
    request.opt.no_response = True
    # Indico que voy a enviar el mensaje well-known/coap-eap al autenticador EAP
    print("Enviando mensaje well-known/coap-eap al controlador...")
    # Recibo la respuesta del controlador a este mensaje
    response = not await context.request(request).response
    # Creo el recurso raiz del servidor CoAP. Este objeto es el que luego se pasa a create_server_context para manejar las solicitudes que lleguen al servidor
    root1 = resource.Site()
    # Agrego un recurso (FirstResource) al servidor CoAP en la ruta especificada por la URI aleatoria. Cuando un cliente
    # CoAP realice una peticion a esa URI el servidor usara la logica implementada en FirstResource para procesar la
    # solicitud y responderla
    root1.add_resource([URI_aleatoria_partes[0], URI_aleatoria_partes[1], URI_aleatoria_partes[2]], FirstResource(root1, URI_aleatoria, counter))
    # A partir de este momento el par EAP comenzara a comportarse como un servidor
    # Creo un contexto de servidor CoAP que esta configurando para escuchar en la direccion 'localhost' y el puerto 5683
    # Escuchara las peticiones enviadas por el autenticador EAP (cuando este actua como cliente) al par EAP (cuando este actua como servidor)
    await aiocoap.Context.create_server_context(root1, bind=('localhost', 5683))
    # Bucle infinito que permanece a la espera de recibir peticiones del autenticador EAP
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    # Ejecuto el main del peer
    asyncio.run(main())
