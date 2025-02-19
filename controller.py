#!/usr/bin/env python3
# Copyright (c) 2024 Daniel Menéndez González
# SPDX-License-Identifier: MIT

"""Este código implementa el autenticador EAP (EAP Controller) del protocolo CoAP-EAP. Toma los mensajes EAP-PSK
encapsulados en CoAP desde el cliente (par EAP o EAP Peer), los procesa, y los envía al servidor EAP o AAA
(Authentication, Authorization, and Accounting), que es un servidor RADIUS. A su vez, también recibe mensajes del
servidor EAP y los retransmite al cliente."""

# Importo los paquetes necesarios, lo que necesito de la biblioteca aiocoap (facilita la creación de aplicaciones de red
# para IoT, tanto del lado del cliente como del servidor, usando CoAP) y las clases EAP_Authenticator y EAPAuthState del
# scrip cliente_radius.py (para la generacion, envio y recepcion de mensajes RADIUS)
import logging
import asyncio
import aiocoap
import aiocoap.resource as resource
import cbor2
from aiocoap import *
from aiocoap.numbers.contentformat import ContentFormat
from aiocoap.numbers.codes import Code
from cliente_radius import EAP_Authenticator, EAPAuthState
from aiocoap.oscore import CanProtect, CanUnprotect, SecurityContextUtils
from calculos_oscore import derive_oscore_keys
from redes import get_wifi_ip
from decrypt_ms_key import decrypt_ms_key


# Inicializo tres variables globales como cadenas vacías. Al estar definidas fuera de cualquier clase o funcion, estas
# variables pueden ser accedidas y modificadas desde cualquier parte del modulo en el que estan definidas. Esto sera
# util mas adelante, ya que los bucles if del main utilizaran estas variables para la construccion de las uris de los
# mensajes POST
uri_eappsk1 = ""
uri_eappsk3 = ""
uri_eapsuccess = ""


# Clase WellKnownResource que manejara el mensaje POST a la uri well-known/coap-eap y generara la respuesta a ese mensaje.
# Como ya comente, no debería ser necesario responderlo, pero la implementacion de la biblioteca lo requiere para que no haya error
class WellKnownResource(resource.Resource):
    # Defino el metodo constructor __init__, que inicializa una nueva instancia de la clase
    def __init__(self):
        # Llamo al constructor de la clase base usando super() para asegurar que cualquier inicializacion de
        # la clase padre se ejecute correctamente
        super().__init__()
        # Inicializo el atributo p como una cadena de bytes vacia para almacenar el payload del mensaje recibido
        self.p = b""

    # Funcion que maneja los mensajes POST enviados a este recurso
    async def render_post(self, request):
        # Muestro la informacion del mensaje POST recibido
        print("MENSAJE POST DE ACTIVACIÓN RECIBIDO CON:")
        # Imprimo el codigo
        print("Código:", request.code)
        # Asigno la variable p al payload del mensaje recibido
        self.p = request.payload
        # Imprimo el payload en binario
        print("Payload:", request.payload)
        # Imprimo el payload en hexadecimal
        print("Payload hexadecimal:", request.payload.hex())
        # Indico que recibi el mensaje POST well-known/coap-eap
        print("Confirmo recepción del mensaje de activación...")
        # Establezco el formato del contenido a OCTETSTREAM (deberia de ser COAP-EAP)
        content = ContentFormat.OCTETSTREAM
        # El payload de la respuesta sera la frase "Mensaje de activacion recibido correctamente" en binario
        payload = b"Mensaje de activacion recibido correctamente"
        # Indico que estoy enviando la respuesta para contentar al par EAP
        print("Enviando respuesta CONTINUE al dispositivo IoT...")
        print("")
        # Construyo el mensaje de respuesta con codigo CONTINUE y con el payload y el content_format establecidos anteriormente
        return aiocoap.Message(code=Code.CONTINUE, payload=payload, content_format=content)


# Establezco que, por defecto, solo se registren mensajes de nivel INFO o superior
logging.basicConfig(level=logging.INFO)
# Permito que, específicamente para el logger llamado "coap-server", se registren mensajes de nivel DEBUG
logging.getLogger("coap-server").setLevel(logging.DEBUG)


async def main():
    # Defino las variables globales uri_eappsk1, uri_eappsk3, uri_eapsuccess para almacenar y modificar sus valores
    global uri_eappsk1, uri_eappsk3, uri_eapsuccess
    # Creo un objeto de tipo `Site`, que actua como el contenedor principal para los recursos del servidor CoAP
    root = resource.Site()
    # Creo una instancia de la clase WellKnownResource, que representa un recurso en el servidor CoAP.
    well_known_resource = WellKnownResource()
    # Agrego un recurso al sitio raíz que maneja la URI '.well-known/core', que devuelve un encabezado con enlaces a los recursos disponibles
    root.add_resource(['.well-known', 'core'], resource.WKCResource(root.get_resources_as_linkheader))
    # Agrego un recurso al sitio raíz que maneja la URI '.well-known/coap-eap', que se refiere a la instancia de `well_known_resource`
    root.add_resource(['.well-known', 'coap-eap'], well_known_resource)
    # Creo un contexto de servidor CoAP que está configurando para escuchar por ejemplo en la dirección IPv4 del
    # adaptador de LAN inalambrica WIFI-2 (la direccion se obtiene mediante la funcion get_wifi_ip del script redes.py)
    # y en el puerto 5683.
    # Escuchara las peticiones enviadas por el par EAP (cuando este actua como cliente) al autenticador EAP (cuando este actua como servidor)
    # El par EAP unicamente actuara como servidor para recibir el mensaje a la uri ".well-known/coap-eap" y responder con el mensaje CONTINUE
    wifi_ip = get_wifi_ip()
    server_context = await aiocoap.Context.create_server_context(root, bind=(wifi_ip, 5683))
    # Espero de manera asíncrona durante 5 segundos, permitiendo la generacion y el envio de la respuesta CONTINUE durante ese tiempo
    await asyncio.sleep(5)
    # Cierro el contexto del servidor CoAP de manera asincrona, liberando recursos y finalizando conexiones
    await server_context.shutdown()
    # Espero de manera asincrona durante 3 segundos a que el contexto del servidor se cierre correctamente
    await asyncio.sleep(3)
    # A partir de este momento el controller comenzara a comportarse como un cliente
    # Creo un contexto de cliente CoAP que me permitira enviar peticiones CoAP al par EAP
    context = await Context.create_client_context()
    # Defino los conjuntos de cifrado en un diccionario, donde la clave es un indice y el valor es una lista que
    # contiene el algoritmo de cifrado AEAD y el algoritmo de hash
    conjuntos_cifrado = {
        # Este es el conjunto de cifrado predeterminado, usando AES en modo CCM con SHA-256
        0: ["AES-CCM-16-64-128", "SHA-256"],
        # Este es el segundo conjunto de cifrado, usando A128GCM con SHA-256
        1: ["A128GCM", "SHA-256"],
        # Este es el tercer conjunto de cifrado, usando A256GCM con SHA-384
        2: ["A256GCM", "SHA-384"],
        # Este es el cuarto conjunto de cifrado, usando ChaCha20 con Poly1305 y SHA-256
        3: ["ChaCha20/Poly1305", "SHA-256"],
        # Este es el quinto conjunto de cifrado, usando ChaCha20 con Poly1305 y SHAKE256
        4: ["ChaCha20/Poly1305", "SHAKE256"]
    }
    # Defino de forma manual y con tamaño de 1 byte el ID de Destinatario del autenticador EAP
    RID_C = b'\x01'
    # Defino la estructura CoAP-EAP_Info1 como un diccionario que contiene informacion sobre los posibles conjuntos de
    # cifrado (lo elegira el peer) en orden decreciente de preferencia y el ID de Destinatario del autenticador EAP
    coap_eap_info1 = {
        # Lista de indices de los conjuntos de cifrado habilitados (incluyendo todos los definidos)
        1: [0, 1, 2, 3, 4],
        # RID-C como una cadena binaria
        2: RID_C,
    }
    # Serializo la estructura CoAP-EAP_Info a formato CBOR para su transporte o almacenamiento
    cbor_payload1 = cbor2.dumps(coap_eap_info1)
    # Imprimo la estructura CBOR del EAP Response ID
    print("Estructura CBOR del EAP Request ID:", cbor_payload1.hex())
    # El payload del mensaje Request ID sera la cadena hexadecimal fija por defecto "010700050183000102" concatenado con
    # la estructura de datos CBOR utilizada para la negociacion de cryptosuite
    payload1 = "010700050183000102" + cbor_payload1.hex()
    # Imprimo el payload del EAP Request ID en hexadecimal
    print("Payload del EAP Request ID:", payload1)
    # Establezco el formato del contenido a OCTETSTREAM (deberia de ser COAP-EAP)
    content_format = ContentFormat.OCTETSTREAM
    # Accedo al atributo p (payload del mensaje well-known/coap-eap) de la instancia well_known_resource ya que su contenido
    # es la URI a la que tengo que enviar el mensaje EAP Request ID, lo convierto a bytes y luego lo decodifico en una cadena de texto
    uri_reqid = bytes.fromhex(well_known_resource.p.hex()).decode('utf-8')
    # Imprimo cual va a ser la URI del mensaje Request ID para ver si coincide con la generada en el par EAP
    print("URI del mensaje EAP Request ID:", uri_reqid)
    # Construyo el mensaje RequestID con codigo POST a la uri indicada y con el payload y el content_format establecidos anteriormente
    # La uri indicada contiene la direccion localhost para vincularlo con el contexto del servidor del par EAP ya que escucha en esa direccion
    RequestId = aiocoap.Message(code=Code.POST, payload=bytes.fromhex(payload1), uri="coap://localhost/"+uri_reqid, content_format=content_format)
    # Indico que estoy enviando la peticion POST con el EAP Request ID al par EAP
    print("Enviando una petición POST con el EAP Request ID al dispositivo IoT...")
    # Envio una solicitud (Request ID) a través del contexto del cliente CoAP y espero la respuesta (Response ID)
    ResponseId = await context.request(RequestId).response
    # Muestro la informacion del mensaje CREATED recibido con el Response ID
    print("MENSAJE CREATED CON EL EAP RESPONSE ID RECIBIDO CON:")
    # Imprimo el codigo
    print("Codigo:", ResponseId.code)
    # Imprimo el payload en binario
    print("Payload:", ResponseId.payload)
    # Imprimo el payload en hexadecimal
    print("Payload hexadecimal:", ResponseId.payload.hex())
    print("")
    # Deserializo la estructura CBOR del payload del EAP Response-ID recibido para extraer la informacion que necesito para OSCORE
    deserialized_info = cbor2.loads(ResponseId.payload[-7:])
    # Extraigo la lista de indices de los conjuntos de cifrado y la asigno a la variable cifrado_indices
    cifrado_indices = deserialized_info[1]
    # Extraigo el primer indice de la lista de conjuntos de cifrado (en este caso el indice 0)
    indice_cifrado = cifrado_indices[0]
    # Asigno el nombre del algoritmo de cifrado AEAD correspondiente al indice extraido
    algoritmo_AEAD = conjuntos_cifrado[indice_cifrado][0]
    # Asigno el nombre del algoritmo hash correspondiente al indice extraido
    algoritmo_hash = conjuntos_cifrado[indice_cifrado][1]
    # Extraigo el RID_I y lo asigno a la variable rid_i
    rid_i = deserialized_info[2]
    # Imprimo el nombre del algoritmo de cifrado correspondiente al índice extraído
    print("Algoritmo de cifrado AEAD elegido por el par EAP:", algoritmo_AEAD)
    # Imprimo el nombre del algoritmo hash correspondiente al índice extraído
    print("Algoritmo hash elegido por el par EAP:", algoritmo_hash)
    # Imprimo el RID-C extraído (ID de Destinatario del autenticador EAP)
    print("RID-C:", RID_C)
    # Imprimo el RID-I (ID de Destinatario del par EAP)
    print("RID-I:", rid_i)
    print("")
    # Obtengo el valor de LOCATION_PATH de las opciones del mensaje POST con el EAP Response ID
    location_path1 = ResponseId.opt.location_path
    # Me aseguro de que location_path1 no es None y que es una tupla ('auth', 'eap', 'counter')
    if location_path1 and isinstance(location_path1, tuple):
        # Obtengo el primer elemento de la tupla ('auth') y lo almaceno en val1
        val1 = location_path1[0]
        # Obtengo el segundo elemento de la tupla ('eap') y lo almaceno en val2
        val2 = location_path1[1]
        # Obtengo el tercer elemento de la tupla ('counter') y lo almaceno en val3
        val3 = location_path1[2]
        # Concateno los valores obtenidos con '/' para formar la URI completa
        uri_eappsk1 = val1 + '/' + val2 + '/' + val3
        # Imprimo la URI extraida, que sera la URI del mensaje POST con EAP-PSK-1 que se enviara a continuacion
        print("URI del mensaje EAP-PSK-1:", uri_eappsk1)
        print("")
    # Si location_path1 es None o no tiene el formato esperado, imprimo un mensaje de error
    else:
        print("No se ha encontrado la opción LOCATION_PATH o el formato no es el esperado")
    # Hago las llamadas necesarias al script cliente_radius.py que actua como cliente RADIUS hasta obtener el mensaje EAP-PSK-1
    # Creo una instancia de la clase EAP_Authenticator, que gestiona el proceso de autenticacion EAP
    eap_auth = EAP_Authenticator()
    # Imprimo un mensaje indicando que se va a actualizar el estado
    print("Update State")
    # Imprimo las variables del estado actual de RADIUS dentro del objeto eap_auth
    print(vars(eap_auth._radiusState))
    # Envio un mensaje RADIUS cuyo atributo EAP-Message contiene el payload del Response ID al servidor RADIUS a partir del estado actual
    eap_auth.sendNextMessageToRADIUS()
    # Ahora estaria dentro del estado REQ_ID_FIX
    # Imprimo nuevamente las variables del estado de RADIUS despues de enviar el mensaje
    print(vars(eap_auth._radiusState))
    # Genero el siguiente mensaje RADIUS a partir del estado actual. El atributo EAP-Message de este mensaje es
    # practicamente una replica del que acaba de enviar al servidor RADIUS, solo cambia el ID, que debe ser el mismo que
    # el del Access-Challenge que recibe como respuesta del servidor RADIUS
    # Este es el mensaje que se manda para solucionar la especie de bug que presenta la implementacion del servidor RADIUS
    eap_auth.genNextRadiusMessageFromState()
    # Envio el mensaje RADIUS generado en el paso anterior al servidor RADIUS
    # Ya estoy dentro del estado EAP_PSK_1 y puedo guardar el mensaje EAP-PSK-1 en la variable payload2 ya que es lo que me retorna ese estado
    payload2 = eap_auth.sendNextMessageToRADIUS()
    # Imprimo el mensaje EAP-PSK-1
    print("El payload de la petición CoAP que contiene el mensaje EAP-PSK-1 es este:", payload2)
    print("URI del mensaje EAP-PSK-1:", uri_eappsk1)
    # Construyo el mensaje EAP-PSK-1 con codigo POST a la uri indicada y con el payload y el content_format establecidos anteriormente
    EAP1 = aiocoap.Message(code=Code.POST, payload=bytes.fromhex(payload2), uri="coap://localhost/"+uri_eappsk1, content_format=content_format)
    # Indico que estoy enviando la peticion POST con el mensaje EAP-PSK-1 al par EAP
    print("Enviando POST con el primer mensaje del protocolo EAP (EAP-PSK-1) al dispositivo IOT...")
    # Envio una solicitud (EAP-PSK-1) a traves del contexto del cliente CoAP y espero la respuesta (EAP-PSK-2)
    REAP1 = await context.request(EAP1).response
    # Muestro la informacion del mensaje CREATED recibido con el EAP-PSK-2
    print("MENSAJE CREATED CON EL MENSAJE EAP-PSK-2 RECIBIDO CON:")
    # Imprimo el codigo
    print("Codigo:", REAP1.code)
    # Imprimo el payload en binario
    print("Payload:", REAP1.payload)
    # Imprimo el payload en hexadecimal
    print("Payload hexadecimal:", REAP1.payload.hex())
    print("")
    # Obtengo el valor de LOCATION_PATH de las opciones del mensaje POST con el EAP-PSK-2
    location_path2 = REAP1.opt.location_path
    # Me aseguro de que location_path1 no es None y que es una tupla ('auth', 'eap', 'counter')
    if location_path2 and isinstance(location_path2, tuple):
        # Obtengo el primer elemento de la tupla ('auth') y lo almaceno en val4
        val4 = location_path2[0]
        # Obtengo el segundo elemento de la tupla ('eap') y lo almaceno en val5
        val5 = location_path2[1]
        # Obtengo el tercer elemento de la tupla ('counter') y lo almaceno en val6
        val6 = location_path2[2]
        # Concateno los valores obtenidos con '/' para formar la URI completa
        uri_eappsk3 = val4 + '/' + val5 + '/' + val6
        # Imprimo la URI extraida, que sera la URI del mensaje POST con EAP-PSK-3 que se enviara a continuacion
        print("URI del mensaje EAP-PSK-3:", uri_eappsk3)
        print("")
    # Si location_path1 es None o no tiene el formato esperado, imprimo un mensaje de error
    else:
        print("No se ha encontrado la opción LOCATION_PATH o el formato no es el esperado")
    # Fijo que el mensaje EAP que va en el atributo EAP-Message sea EAP-PSK-2 para que la proxima vez que haga una
    # llamada al cliente RADIUS, el mensaje RADIUS a enviar al servidor RADIUS se construya con ese contenido
    eap_auth.set_eap_message(REAP1.payload.hex())
    # Fijo el estado a EAP_PSK_3 para que la proxima vez que haga una llamada al cliente RADIUS se ejecute el codigo de dicho estado
    eap_auth.set_state(EAPAuthState.EAP_PSK_3)
    # Hago las llamadas necesarias al scrip cliente_radius.py que actua como cliente RADIUS hasta obtener el mensaje EAP-PSK-1
    # Imprimo las variables del estado actual de RADIUS dentro del objeto eap_auth
    print(vars(eap_auth._radiusState))
    # Genero el siguiente mensaje RADIUS a partir del estado actual (EAP_PSK_3). Es decir, ahora estoy generando el mensaje
    # RADIUS que contiene el EAP-PSK-2 que acabo de recibir del peer
    eap_auth.genNextRadiusMessageFromState()
    # Como ya estoy dentro del estado EAP_PSK_3, puedo guardar el mensaje EAP-PSK-3 en la variable payload3 ya que es lo
    # que me retorna ese estado
    payload3 = eap_auth.sendNextMessageToRADIUS()
    # Imprimo el mensaje EAP-PSK-3
    print("El payload de la petición CoAP que contiene el mensaje EAP-PSK-3 es este:", payload3)
    print("URI del mensaje EAP-PSK-3:", uri_eappsk3)
    # Construyo el mensaje EAP-PSK-3 con codigo POST a la uri indicada y con el payload y el content_format establecidos anteriormente
    EAP3 = aiocoap.Message(code=Code.POST, payload=bytes.fromhex(payload3), uri="coap://localhost/" + uri_eappsk3, content_format=content_format)
    # Indico que estoy enviando la peticion POST con el mensaje EAP-PSK-3 al par EAP
    print("Enviando POST con el tercer mensaje del protocolo EAP (EAP-PSK-3) al dispositivo IOT...")
    # Envio una solicitud (EAP-PSK-3) a traves del contexto del cliente CoAP y espero la respuesta (EAP-PSK-4)
    REAP3 = await context.request(EAP3).response
    # Guardo el valor del ID de mensaje del cuarto mensaje del metodo EAP (EAP-PSK-4)
    ID1 = REAP3.mid
    # Muestro la informacion del mensaje CREATED recibido con el EAP-PSK-2
    print("MENSAJE CREATED CON EL MENSAJE EAP-PSK-4 RECIBIDO CON:")
    # Imprimo el codigo
    print("Codigo:", REAP3.code)
    # Imprimo el payload en binario
    print("Payload:", REAP3.payload)
    # Imprimo el payload en hexadecimal
    print("Response payload hexadecimal:", REAP3.payload.hex())
    print("")
    # Obtengo el valor de LOCATION_PATH de las opciones del mensaje POST con el EAP-PSK-4
    location_path3 = REAP3.opt.location_path
    # Me aseguro de que location_path1 no es None y que es una tupla ('auth', 'eap', 'counter')
    if location_path3 and isinstance(location_path3, tuple):
        # Obtengo el primer elemento de la tupla ('auth') y lo almaceno en val1
        val7 = location_path3[0]
        # Obtengo el segundo elemento de la tupla ('eap') y lo almaceno en val2
        val8 = location_path3[1]
        # Obtengo el tercer elemento de la tupla ('counter') y lo almaceno en val3
        val9 = location_path3[2]
        # Concateno los valores obtenidos con '/' para formar la URI completa
        uri_eapsuccess = val7 + '/' + val8 + '/' + val9
        # Imprimo la URI extraida, que sera la URI del mensaje POST con EAP-PSK-1 que se enviara a continuacion
        print("URI del mensaje EAP-SUCCESS:", uri_eapsuccess)
        print("")
    # Si location_path1 es None o no tiene el formato esperado, imprimo un mensaje de error
    else:
        print("No se ha encontrado la opción LOCATION_PATH o el formato no es el esperado")
    # Fijo que el mensaje EAP que va en el atributo EAP-Message sea EAP_PSK_MSG_4 para que la proxima vez que haga una
    # llamada al cliente RADIUS, el mensaje RADIUS a enviar al servidor RADIUS se construya con ese contenido
    eap_auth.set_eap_message(REAP3.payload.hex())
    # Fijo el estado a EAP_SUCCESS para que la proxima vez que haga una llamada al cliente RADIUS se ejecute el codigo de dicho estado
    eap_auth.set_state(EAPAuthState.EAP_SUCCESS)
    # Imprimo las variables del estado actual de RADIUS dentro del objeto eap_auth
    print(vars(eap_auth._radiusState))
    # Genero el siguiente mensaje RADIUS a partir del estado actual (EAP_SUCCESS). Es decir, ahora estoy generando el mensaje
    # RADIUS que contiene el EAP-PSK-4 que acabo de recibir del par EAP
    eap_auth.genNextRadiusMessageFromState()
    # Como ya estoy dentro del estado EAP_SUCCESS, puedo guardar el mensaje EAP-SUCCESS en la variable payload4, asi
    # como las claves MS-MPPE-Recv-Key y MS-MPPE-Send-Key ya que es lo que me retorna ese estado
    payload4, MPPE_REC_KEY, MPPE_SEND_KEY = eap_auth.sendNextMessageToRADIUS()
    # Obtengo el campo Authenticator del mensaje Access-Accept previo al Access-Accept. El EAP Authenticator la usara
    # para descifrar las claves MS y asi poder calcular la MSK necesaria para crear su contexto de seguridad OSCORE
    req_authenticator = bytes.fromhex(eap_auth.req_auth)
    # Defino el valor de secret (es el Shared Secret  compartido entre el cliente y el servidor RADIUS)
    secret = b"testing123"
    # Descifro la MS-MPPE-Recv-Key (seran los primeros 32 bytes de la MSK)
    print("")
    print("Proceso de descifrado de la MS-MPPE-Recv-Key:")
    decrypted_recv_key = decrypt_ms_key(bytes.fromhex(MPPE_REC_KEY), req_authenticator, secret)
    # Descifro la MS-MPPE-Send-Key (seran los ultimos 32 bytes de la MSK)
    print("Proceso de descifrado de la MS-MPPE-Send-Key:")
    decrypted_send_key = decrypt_ms_key(bytes.fromhex(MPPE_SEND_KEY), req_authenticator, secret)
    # Calculo la MSK concatendo la MS-MPPE-Recv-Key descifrada con la MS-MPPE-Send-Key descifrada (64 bytes en total)
    MSK = bytes.fromhex(decrypted_recv_key.hex() + decrypted_send_key.hex())
    # Imprimo su valor en hexadecimal para comprobar que es correcto
    print("\nMSK obtenida tras descifrar las claves MS:", MSK.hex())
    # La MSK recibida del servidor RADIUS sera la concatenacion de la MS-MPPE-Recv-Key y de la MS-MPPE-Send-Key descifradas
    # Imprimo la MSK recibida del servidor RADIUS
    # print("MSK recibida del servidor:", MPPE_REC_KEY + MPPE_SEND_KEY)
    # Defino la estructura CoAP-EAP_Info2 como un diccionario que contiene informacion sobre el tiempo de vida de la sesion
    coap_eap_info2 = {
        # Tiempo de vida de la sesion en segundos (8 horas que es el tiempo predeterminado establecido en el Draft)
        1: 28800
    }
    # Serializo la estructura CoAP-EAP_Info a formato CBOR para su transporte o almacenamiento
    cbor_payload2 = cbor2.dumps(coap_eap_info2)
    # Imprimo la estructura CBOR del mensaje EAP-SUCCESS
    print("Estructura CBOR del mensaje EAP-SUCCESS:", cbor_payload2.hex())
    # Concateno el payload del mensaje EAP-Success recibido del servidor EAP con la estructura CBOR que contiene el tiempo de vida de la sesion
    payload_eap_success = payload4 + cbor_payload2.hex()
    # Imprimo el mensaje EAP-SUCCESS con la estructura CBOR ya concatenada
    print("El payload completo con el mensaje EAP-SUCCESS es este:", payload_eap_success)
    print("URI del mensaje EAP-SUCCESS:", uri_eapsuccess)
    print("")
    # Construyo el mensaje EAP-SUCCESS con codigo POST a la uri indicada y con el payload y el content_format establecidos anteriormente
    EAPSUCCESS = aiocoap.Message(code=Code.POST, payload=bytes.fromhex(payload_eap_success), uri="coap://localhost/" + uri_eapsuccess,
                                 content_format=content_format)
    # Asigno el tipo de mensaje para EAP-SUCCESS, en este caso lo configuro como Confirmable (CON)
    EAPSUCCESS.mtype = aiocoap.CON
    # Asigno un ID unico para el mensaje EAP-SUCCESS usando el ID de mensaje del EAP-PSK-4 incrementado en 1
    EAPSUCCESS.mid = ID1 + 1
    # Codifico el mensaje EAP-SUCCESS en hexadecimal
    EAPSUCCESS_HEX = EAPSUCCESS.encode().hex()
    # Concateno el contenido de la negociacion del conjunto de cifrado, es decir, la lista de conjuntos de cifrado
    # enviados por el autenticador EAP en el EAP Request ID concatenada a la opcion seleccionada por el par EAP en el
    # EAP Response ID y lo convierto a hexadecimal
    CS = cbor_payload1[2:8].hex() + ResponseId.payload[12:14].hex()
    # Imprimo la cadena CS resultante
    print("CS:", CS)
    # Derivo las claves OSCORE (Master Secret y Master Salt) usando la MSK y el CS
    MASTER_SECRET, MASTER_SALT = derive_oscore_keys(MSK, CS)
    # Asigno a la variable SECRET el valor de la Master Secret y a la variable SALT el valor de la Master Salt obtenidos
    # en la derivacion de las claves OSCORE convertidos a bytes
    SECRET = bytes.fromhex(MASTER_SECRET)
    SALT = bytes.fromhex(MASTER_SALT)
    # Defino el ID del contexto OSCORE del autenticador EAP y lo convierto a bytes
    ID_CTX = bytes.fromhex("37cbf3210017a2d3")
    # Establezco el algoritmo AEAD y el algoritmo hash seleccionados por el par EAP
    aead_algorithm = aiocoap.oscore.algorithms[algoritmo_AEAD]  # Algoritmo AES_CCM
    fun_hash = aiocoap.oscore.hashfunctions[algoritmo_hash]  # Funcion hash SHA-256

    # Defino una clase de contexto de seguridad personalizada que hereda de CanProtect (permite proteger los mensajes CoAP),
    # CanUnprotect (maneja la recepción y el procesamiento de mensajes que han sido protegidos, asegurando que se puedan
    # desproteger y validar correctamente) y SecurityContextUtils (ofrece utilidades relacionadas con el contexto de seguridad)
    class OscoreSecurityContext(CanProtect, CanUnprotect, SecurityContextUtils):
        # Metodo que se llama al intentar incrementar el numero de secuencia, pero no hace nada (es necesario
        # definirlo para que la clase funcione ya que post_seqnoincrease esta definido en CanProtect como un metodo
        # abstracto, lo que implica que cualquier clase que herede de CanProtect debe implementar este metodo)
        def post_seqnoincrease(self):
            pass

    # Creo el contexto de seguridad del autenticador EAP instanciando la clase OscoreSecurityContext
    secctx = OscoreSecurityContext()
    # Establezco el algoritmo AEAD que voy a utilizar en el contexto de seguridad
    secctx.alg_aead = aead_algorithm
    # Establezco la funcion hash que voy a utilizar en el contexto de seguridad
    secctx.hashfun = fun_hash
    # El autenticador EAP utiliza el ID de Destinatario del par EAP (RID-I) como ID de Remitente para su contexto de remitente en OSCORE
    secctx.sender_id = rid_i
    # El autenticador EAP usa el ID de Destinatario del autenticador EAP (RID-C) como ID de Destinatario para su contexto de destinatario
    secctx.recipient_id = RID_C
    # Establezco el ID de contexto
    secctx.id_context = ID_CTX
    # Llamo a la funcion derive_keys para obtener la clave de remitente, la clave de destinatario y el IV comun a partir
    # del algoritmo AEAD, la funcion hash y el ID de contexto ya configurados de antemano, y a partir de la Master Secret
    # y de la Master Salt pasadas como parametros
    secctx.derive_keys(SALT, SECRET)
    # Fijo el numero de secuencia del remitente en 20
    secctx.sender_sequence_number = 20
    # Imprimo los parametros del Contexto Comun del contexto de seguridad OSCORE del autenticador EAP
    print("Parámetros del Contexto Común del contexto de seguridad OSCORE del autenticador EAP:")
    print("Algoritmo AEAD:", algoritmo_AEAD)
    print("Algoritmo HKDF:", algoritmo_hash)
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
    print("")
    # Decodifico el mensaje EAP-SUCCESS desde el formato hexadecimal a un objeto de mensaje CoAP sin proteccion
    unprotected = aiocoap.Message.decode(bytes.fromhex(EAPSUCCESS_HEX))
    # Protejo el mensaje sin proteccion usando el contexto de seguridad OSCORE del autenticador EAP
    protected_message, _ = secctx.protect(unprotected)
    # Asigno el ID de mensaje del mensaje desprotegido al mensaje protegido
    protected_message.mid = unprotected.mid
    # Asigno el token del mensaje desprotegido al mensaje protegido
    protected_message.token = unprotected.token
    # Asigno el tipo de mensaje del mensaje desprotegido al mensaje protegido
    protected_message.mtype = unprotected.mtype
    # Codifico el mensaje protegido a bytes
    encoded_protected_message = protected_message.encode()
    # Imprimo el mensaje EAP-SUCCESS protegido en formato hexadecimal
    print("Mensaje EAP-SUCCESS protegido por OSCORE:", encoded_protected_message.hex())
    # Construyo un nuevo mensaje CoAP para enviar en el payload el EAP-SUCCESS protegido con OSCORE a la uri indicada y
    # el content_format establecido anteriormente
    EAPSUCCESS_PROT = aiocoap.Message(code=Code.POST, payload=bytes.fromhex(encoded_protected_message.hex()),
                                      uri="coap://localhost/" + uri_eapsuccess, content_format=content_format)
    # Indico que estoy enviando la peticion POST con el mensaje EAP-SUCCESS al par EAP
    print("Enviando POST con el mensaje SUCCESS del protocolo EAP protegido con OSCORE al dispositivo IOT...")
    # Envio una solicitud (EAP-SUCCESS) a traves del contexto del cliente CoAP y espero la respuesta final
    REAPSUCCESS = await context.request(EAPSUCCESS_PROT).response
    # Guardo el valor del ID de mensaje del mensaje CHANGED recibido
    ID2 = REAPSUCCESS.mid
    if str(REAPSUCCESS.code) == "2.04 Changed":
        # Muestro la informacion del mensaje CHANGED protegido con OSCORE recibido
        print("MENSAJE CHANGED PROTEGIDO CON OSCORE RECIBIDO CON:")
        # Imprimo el codigo
        print("Codigo:", REAPSUCCESS.code)
        # Imprimo el payload en binario
        print("Payload binario que contiene el mensaje CHANGED protegido:", REAPSUCCESS.payload)
        # Imprimo el payload en hexadecimal
        print("Payload hexadecimal que contiene el mensaje CHANGED protegido:", REAPSUCCESS.payload.hex())
        print("")
    else:
        # Muestro la informacion del mensaje UNAUTHORIZED recibido
        print("MENSAJE UNAUTHORIZED RECIBIDO CON:")
        # Imprimo el codigo
        print("Codigo:", REAPSUCCESS.code)
        # Imprimo el payload en binario
        print("Payload:", REAPSUCCESS.payload)
        # Imprimo el payload en hexadecimal
        print("Payload hexadecimal:", REAPSUCCESS.payload.hex())
        print("")

    
    # Este es un ejemplo de mensaje POST al segundo recurso (SecondResource) para comprobar si los recursos se van eliminando correctamente
    # El par EAP me debería responder con un mensaje con codigo 4.04 NOT FOUND
    # Construyo de nuevo la peticion CoAP con el mensaje EAP-PSK-1 como si fuera una solicitud duplicada enviada tras un periodo de tiempo
    EAP_REP = aiocoap.Message(code=Code.POST, payload=bytes.fromhex(payload2), uri="coap://localhost/" + uri_eappsk1, content_format=content_format)
    # Indico que estoy enviando al par EAP la peticion POST al segundo recurso
    print("Enviando POST con URI REPETIDA al dispositivo IOT...")
    # Envio la solicitud (POST a la uri repetida) a través del contexto del cliente CoAP y espero la respuesta 4.04 NOT FOUND
    RES_EAP_REP = await context.request(EAP_REP).response
    # Muestro la informacion del mensaje 4.04 NOT FOUND recibido
    print("MENSAJE NOT FOUND RECIBIDO CON:")
    # Imprimo el codigo
    print("Codigo:", RES_EAP_REP.code)
    # Imprimo el payload en hexadecimal (vacio)
    print("Payload hexadecimal:", RES_EAP_REP.payload.hex())
    print("")

    # Este es un ejemplo de mensaje DELETE al ultimo recurso para comprobar si el par EAP responde adecuadamente
    # El peer me debería responder con un mensaje con codigo 2.02 DELETED
    # Construyo el mensaje de prueba con codigo DELETE a la uri indicada, con un payload aleatorio y el content_format establecido anteriormente
    PET_DELETE = aiocoap.Message(code=Code.DELETE, payload="Menssaje DELETE de prueba".encode(),
                                 uri="coap://localhost/" + uri_eapsuccess, content_format=content_format)
    # Asigno el tipo de mensaje para el mensaje DELETE, en este caso lo configuro como Confirmable (CON)
    PET_DELETE.mtype = aiocoap.CON
    # Asigno un ID unico para el mensaje DELETE usando el ID de mensaje del mensaje CHANGED incrementado en 2
    PET_DELETE.mid = ID2 + 1
    # Codifico el mensaje DELETE en hexadecimal
    PET_DELETE_HEX = PET_DELETE.encode().hex()
    # Decodifico el mensaje DELETE desde el formato hexadecimal a un objeto de mensaje CoAP sin proteccion
    unprotected_del = aiocoap.Message.decode(bytes.fromhex(PET_DELETE_HEX))
    # Protejo el mensaje sin proteccion usando el contexto de seguridad OSCORE del autenticador EAP
    protected_del, _ = secctx.protect(unprotected_del)
    # Asigno el ID de mensaje del mensaje desprotegido al mensaje protegido
    protected_del.mid = unprotected_del.mid
    # Asigno el token del mensaje desprotegido al mensaje protegido
    protected_del.token = unprotected_del.token
    # Asigno el tipo de mensaje del mensaje desprotegido al mensaje protegido
    protected_del.mtype = unprotected_del.mtype
    # Codifico el mensaje protegido a bytes
    encoded_protected_del = protected_del.encode()
    # Imprimo el mensaje EAP-SUCCESS protegido en formato hexadecimal
    print("Mensaje DELETE protegido por OSCORE:", encoded_protected_del.hex())
    # Construyo un nuevo mensaje CoAP para enviar en el payload el mensaje DELETE protegido con OSCORE a la uri indicada
    # y el content_format establecido anteriormente
    PET_DELETE_PROT = aiocoap.Message(code=Code.DELETE, payload=bytes.fromhex(encoded_protected_del.hex()),
                                  uri="coap://localhost/" + uri_eapsuccess, content_format=content_format)
    # Indico que estoy enviando al peer la peticion DELETE protegida por OSCORE al ultimo recurso
    print("Enviando el mensaje DELETE protegido con OSCORE al dispositivo IOT...")
    # Envio la solicitud (DELETE a la ultima uri) a través del contexto del cliente CoAP y espero la respuesta 2.02 DELETED
    RES_PET_DELETE = await context.request(PET_DELETE_PROT).response
    # Muestro la informacion del mensaje 2.02 DELETED recibido
    print("MENSAJE DELETED PROTEGIDO CON OSCORE RECIBIDO CON:")
    # Imprimo el codigo
    print("Codigo:", RES_PET_DELETE.code)
    # Imprimo el payload en binario
    print("Payload binario que contiene el mensaje DELETED protegido:", RES_PET_DELETE.payload)
    # Imprimo el payload en hexadecimal (vacio)
    print("Payload hexadecimal que contiene el mensaje DELETED protegido:", RES_PET_DELETE.payload.hex())
    

    # Bucle infinito que permanece a la espera de recibir peticiones del autenticador EAP
    # await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    # Ejecuto el main del controller
    asyncio.run(main())
