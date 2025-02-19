#!/usr/bin/env python3
# Copyright (c) 2024 Daniel Menéndez González
# SPDX-License-Identifier: MIT

"""Este codigo inicializa todas las variables e implementa todas las funciones necesarias relacionadas con EAP-PSK"""

# Importo los paquetes necesarios, lo que necesito de la biblioteca scapy (para manipular y analizar paquetes de red,
# como Ethernet, EAP, y HTTP) y la parte algoritmica necesaria de las bibliotecas PyCryptodome y Cryptography
# (para operaciones criptograficas como cifrado AES y autenticacion CMAC)
import binascii
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.backends import default_backend
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.eap import EAP

# Inicializo varias variables importantes para EAP-PSK que se van a utilizar en las siguientes funciones y en el script peer.py
# Tamaño de bloque en bytes utilizado por el algoritmo AES (16 bytes = 128 bits)
AES_BLOCK_SIZE = 16
# Flag que se utiliza para controlar el estado de las respuestas EAP-PSK (continuacion de mensaje)
EAP_PSK_R_FLAG_CONT = 1
# Flag que indica que la operacion EAP-PSK se completo con exito
EAP_PSK_R_FLAG_DONE_SUCCESS = 2
# Flag que indica que la operacion EAP-PSK se completo con fallo
EAP_PSK_R_FLAG_DONE_FAILURE = 3
# Longitud de la Master Session Key (MSK) para EAP-PSK (64 bytes)
EAP_MSK_LEN = 64
# Longitud de la Extended Master Session Key (EMSK) para EAP-PSK (64 bytes)
EAP_EMSK_LEN = 64
# Flag "E" que se utiliza en el protocolo EAP-PSK para indicar una extensión (valor en hexadecimal 0x20)
EAP_PSK_E_FLAG = 0x20
# Identificador del proveedor del protocolo EAP, aqui IETF (Internet Engineering Task Force)
EAP_VENDOR_IETF = 0
# Tipo de EAP expandido (valor estandar utilizado para tipos personalizados, 254)
EAP_TYPE_EXPANDED = 254
# Tipo específico para EAP-PSK (identificado con el valor 47)
EAP_PSK_TYPE = 47
# Clave precompartida (PSK) utilizada en el protocolo EAP-PSK, representada como una cadena hexadecimal
PSK = "31323334353637383132333435363738"


def aes_128_encrypt_block_ecb(key, data):
    """
    Esta funcion realiza la encriptacion de un bloque de datos usando el algoritmo AES-128 en modo ECB.
    Inputs:
      - key: La clave de 128 bits (16 bytes) que se usará para la encriptación.
      - data: El bloque de datos (16 bytes) que se va a encriptar.
    Outputs:
      - El bloque encriptado de 16 bytes.
    """
    # Crea un nuevo cifrador AES en modo ECB con la clave proporcionada
    cipher = AES.new(key, AES.MODE_ECB)
    # Encripta el bloque de datos utilizando el cifrador y retornao el resultado
    return cipher.encrypt(data)


def eap_psk_key_setup(psk):
    """
    Esta funcion genera dos claves derivadas (AK y KDK) usando una clave precompartida (PSK) como entrada.
    Utiliza AES-128 en modo ECB para cifrar bloques de datos.

    Inputs:
      - psk: Clave precompartida (PSK) de 16 bytes usada para la generación de AK y KDK.

    Outputs:
      - ak_hex: La clave AK en formato hexadecimal.
      - kdk_hex: La clave KDK en formato hexadecimal.
    """
    # Inicializa la ak como un bloque de ceros del tamaño de un bloque AES
    ak = bytearray(AES_BLOCK_SIZE)
    # Cifra el bloque de ceros utilizando la clave PSK con AES-128 en modo ECB
    ak = aes_128_encrypt_block_ecb(psk, bytes(ak))
    # Clona la ak para la kdk, y convierte la ak y la kdk en bytearrays para permitir modificaciones
    kdk = bytearray(ak)
    ak = bytearray(ak)
    # Modifica el ultimo byte de la ak (operacion XOR con 0x01)
    ak[-1] ^= 0x01
    # Modifica el ultimo byte de la kdk (operacion XOR con 0x02)
    kdk[-1] ^= 0x02
    # Cifra la ak modificada utilizando la clave PSK y convierte el resultado a formato hexadecimal
    ak = aes_128_encrypt_block_ecb(psk, bytes(ak))
    ak_hex = ak.hex()
    # Cifra la kdk modificada utilizando la clave PSK y convierte el resultado a formato hexadecimal
    kdk = aes_128_encrypt_block_ecb(psk, bytes(kdk))
    kdk_hex = kdk.hex()
    # Retorna las claves AK y KDK en formato hexadecimal
    return ak_hex, kdk_hex


def eap_psk_derive_keys(kdk, rand_p):
    """
    Esta funcion deriva tres claves de sesion (TEK, MSK y EMSK) a partir de una clave KDK y un valor aleatorio RAND_P.
    Utiliza AES-128 en modo ECB para cifrar bloques de datos.

    Inputs:
      - kdk: La clave derivada KDK (16 bytes).
      - rand_p: Valor aleatorio (16 bytes) que actua como entrada adicional para la derivacion de las claves.

    Outputs:
      - tek_hex: Clave TEK en formato hexadecimal.
      - msk_hex: Clave MSK en formato hexadecimal.
      - emsk_hex: Clave EMSK en formato hexadecimal.
    """
    # Cifra el valor de rand_p usando la KDK para obtener el valor inicial hash_val
    hash_val = aes_128_encrypt_block_ecb(kdk, rand_p)
    # Inicializa el contador en 1
    counter = 1
    # Convierte hash_val en bytearray para permitir modificaciones
    hash_val = bytearray(hash_val)
    # Realiza la operacion XOR en el ultimo byte de hash_val con el valor de counter
    hash_val[-1] ^= counter
    # Cifra el valor de hash_val modificado usando KDK para generar la clave TEK
    tek = aes_128_encrypt_block_ecb(kdk, bytes(hash_val))
    # Convierte la TEK a formato hexadecimal
    tek_hex = tek.hex()
    # Deshace el XOR en el ultimo byte de hash_val
    hash_val[-1] ^= counter
    # Incrementa el valor del contador
    counter += 1
    # Inicializa el buffer para la MSK (Master Session Key) del tamaño adecuado
    msk = bytearray(EAP_MSK_LEN)
    # Deriva la MSK en bloques del tamaño de AES (16 bytes)
    for i in range(EAP_MSK_LEN // AES_BLOCK_SIZE):
        # Modifica el ultimo byte de hash_val haciendo una operacion XOR con el contador
        hash_val[-1] ^= counter
        # Cifra hash_val para obtener el siguiente bloque de MSK
        msk[i * AES_BLOCK_SIZE:(i + 1) * AES_BLOCK_SIZE] = aes_128_encrypt_block_ecb(kdk, bytes(hash_val))
        # Deshace el XOR en el ultimo byte de hash_val
        hash_val[-1] ^= counter
        # Incrementa el contador
        counter += 1
    # Convierte la MSK a formato hexadecimal
    msk_hex = msk.hex()
    # Inicializa el buffer para la EMSK (Extended Master Session Key) del tamaño adecuado
    emsk = bytearray(EAP_EMSK_LEN)
    # Deriva la EMSK en bloques del tamaño de AES
    for i in range(EAP_EMSK_LEN // AES_BLOCK_SIZE):
        # Modifica el ultimo byte de hash_val haciendo una operacion XOR con el contador
        hash_val[-1] ^= counter
        # Cifra hash_val para obtener el siguiente bloque de EMSK
        emsk[i * AES_BLOCK_SIZE:(i + 1) * AES_BLOCK_SIZE] = aes_128_encrypt_block_ecb(kdk, bytes(hash_val))
        # Deshace el XOR en el ultimo byte de hash_val
        hash_val[-1] ^= counter
        # Incrementa el contador
        counter += 1
    # Convierte la EMSK a formato hexadecimal
    emsk_hex = emsk.hex()
    # Retorna las tres claves de sesion derivadas: TEK, MSK y EMSK en formato hexadecimal
    return tek_hex, msk_hex, emsk_hex


def gf_mulx(block):
    """
    Multiplica un bloque por x en el campo de Galois GF(2^128).
    Esto se utiliza en algunas operaciones criptograficas para realizar una multiplicacion binaria en bloques de datos.

    Inputs:
      - block: Un bloque de bytes (generalmente 16 bytes) que se va a multiplicar por x en GF(2^128).

    Outputs:
      - El bloque resultante despues de la multiplicacion, en formato de bytes.
    """
    # Convierte el bloque a un bytearray para poder modificar sus valores
    block = bytearray(block)
    # Verifica si el bit mas significativo del bloque es 1, lo que indicaria un acarreo
    carry = (block[0] & 0x80) != 0
    # Itera sobre cada byte del bloque
    for i in range(len(block)):
        # Desplaza a la izquierda cada byte del bloque, manteniendo solo los 8 bits menos significativos
        block[i] = ((block[i] << 1) & 0xFF)
        # Si no es el ultimo byte, realiza una operacion OR con el bit mas significativo del siguiente byte
        if i < len(block) - 1:
            block[i] |= (block[i + 1] & 0x80) >> 7
    # Si hubo acarreo, aplica una operacion XOR con el valor 0x87 al ultimo byte
    if carry:
        block[-1] ^= 0x87
    # Convierte el bloque de vuelta a bytes y retorna el resultado
    return bytes(block)


def omac1_aes_128(key, data):
    """
    Calcula OMAC1 (CMAC) usando AES-128 para un solo bloque de datos.

    Inputs:
      - key: La clave de 128 bits (16 bytes) utilizada para la encriptación.
      - data: El bloque de datos a ser autenticado.

    Outputs:
      - El valor MAC en formato hexadecimal.
    """
    # Llama a la función omac1_aes_128_vector con una lista que contiene el bloque de datos
    return omac1_aes_128_vector(key, [data])


def omac1_aes_128_vector(key, data_list):
    """
    Calcula OMAC1 (CMAC) usando AES-128 para una lista de bloques de datos.
    Se utiliza para el calculo de MAC_S y MAC_P

    Inputs:
      - key: La clave de 128 bits (16 bytes) utilizada para la encriptación.
      - data_list: Una lista de bloques de datos a ser autenticados.

    Outputs:
      - El valor MAC en formato hexadecimal.
    """
    global pos
    # Inicializa el cifrador AES en modo ECB
    cipher = AES.new(key, AES.MODE_ECB)
    # Calcula K1 y K2 usando la función gf_mulx
    # Cifra un bloque de ceros
    L = cipher.encrypt(b'\x00' * 16)
    # Multiplica L por x
    K1 = gf_mulx(L)
    # Multiplica K1 por x
    K2 = gf_mulx(K1)
    # Inicializa el bloque CBC-MAC
    cbc = b'\x00' * 16
    # Calcula la longitud total de todos los datos de la lista
    total_len = sum(len(data) for data in data_list)
    # Inicializa la longitud restante como la longitud total
    left = total_len
    # Itera sobre cada bloque de datos de la lista
    for data in data_list:
        # Inicializa la posicion en el bloque de datos
        pos = 0
        # Procesa bloques de 16 bytes mientras haya suficiente longitud restante
        while left >= 16:
            # Obtiene el bloque de datos actual
            block = data[pos:pos + 16]
            # Rellena con ceros hasta el tamaño de bloque si es necesario
            if len(block) < 16:
                # Rellena de ceros
                block += b'\x00' * (16 - len(block))
            # Realiza una operacion XOR entre el bloque actual y el CBC, luego cifra el resultado
            cbc = cipher.encrypt(strxor(cbc, block))
            # Reduce la longitud restante
            left -= 16
            # Avanza a la siguiente posición en los datos
            pos += 16
    # Maneja el ultimo bloque de datos si la longitud total es cero o quedan bytes
    if total_len == 0 or left > 0:
        # Rellena con 0x80 y ceros segun sea necesario para el ultimo bloque
        block = data_list[-1][pos:] + b'\x80' + b'\x00' * (15 - left)
        # Realiza una operacion XOR con el último bloque
        cbc = strxor(cbc, block)
        # Aplica K2 al CBC
        cbc = strxor(cbc, K2)
    else:
        # Si se han procesado todos los bloques, aplica K1 al CBC
        cbc = strxor(cbc, K1)
    # Cifra el bloque final para obtener el valor MAC
    mac = cipher.encrypt(cbc)
    # Convierte el valor MAC a formato hexadecimal
    mac_hex = mac.hex()
    # Retorna el valor MAC en formato hexadecimal
    return mac_hex


def omac1_aes_128_2(key, data):
    """
    Calcula OMAC1 (CMAC) usando AES-128 para un solo bloque de datos.
    Se utiliza dentro de la funcion aes_128_eax_encrypt y aes_128_eax_decrypt

    Inputs:
      - key: La clave de 128 bits (16 bytes) utilizada para la encriptación.
      - data: El bloque de datos a ser autenticado.

    Outputs:
      - El valor MAC en formato de bytes.
    """
    # Crea una instancia del objeto CMAC con el algoritmo AES y la clave proporcionada
    cmac = CMAC(algorithms.AES(key), backend=default_backend())
    # Actualiza el objeto CMAC con el bloque de datos a ser autenticado
    cmac.update(data)
    # Finaliza el calculo y retorna el valor MAC
    return cmac.finalize()


def aes_128_ctr_encrypt(key, nonce, data):
    """
    Cifra datos usando AES-128 en modo CTR.

    Inputs:
      - key: La clave de 128 bits (16 bytes) utilizada para la encriptación.
      - nonce: Un valor único de 128 bits (16 bytes) para el modo CTR.
      - data: Los datos a ser cifrados (bytes).

    Outputs:
      - Los datos cifrados (bytes).
    """
    # Crea una instancia del cifrador AES en modo CTR con la clave y el nonce proporcionados
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    # Crea un objeto para realizar la encriptación
    encryptor = cipher.encryptor()
    # Cifra los datos y retorna el resultado concatenado con el finalizador
    return encryptor.update(data) + encryptor.finalize()


def aes_128_eax_encrypt(key, nonce, nonce_len, hdr, hdr_len, data, data_len, tag):
    """
    Cifra datos usando AES-128 en modo EAX, generando MACs para el nonce, el encabezado y los datos.

    Inputs:
      - key: La clave de 128 bits (16 bytes) utilizada para la encriptacion.
      - nonce: Un valor unico de 128 bits (16 bytes) para el modo EAX.
      - nonce_len: La longitud del nonce en bytes.
      - hdr: El encabezado a ser autenticado (bytes).
      - hdr_len: La longitud del encabezado en bytes.
      - data: Los datos a ser cifrados (bytes).
      - data_len: La longitud de los datos en bytes.
      - tag: Un buffer para almacenar la etiqueta de autenticación (deberia tener al menos 16 bytes).

    Outputs:
      - Los datos cifrados (bytes).
    """
    # Calcula la longitud maxima necesaria para el buffer
    buf_len = max(nonce_len, data_len, hdr_len) + 16
    # Inicializa un buffer de tamaño adecuado
    buf = bytearray(buf_len)
    # Inicializa el buffer con ceros
    buf[:15] = b'\x00' * 15
    # MAC para el nonce
    # Marca el inicio del nonce
    buf[15] = 0
    # Copia el nonce al buffer
    buf[16:16 + nonce_len] = nonce
    # Calcula el MAC del nonce
    nonce_mac = omac1_aes_128_2(key, buf[:16 + nonce_len])
    # MAC para el encabezado
    # Marca el inicio del encabezado
    buf[15] = 1
    # Copia el encabezado al buffer
    buf[16:16 + hdr_len] = hdr
    # Calcula el MAC del encabezado
    hdr_mac = omac1_aes_128_2(key, buf[:16 + hdr_len])
    # Cifrado de los datos
    # Cifra los datos usando el MAC del nonce como nonce para el cifrado
    encrypted_data = aes_128_ctr_encrypt(key, nonce_mac[:16], data)
    # MAC para los datos cifrados
    # Marca el inicio de los datos cifrados
    buf[15] = 2
    # Copia los datos cifrados al buffer
    buf[16:16 + data_len] = encrypted_data
    # Calcula el MAC de los datos cifrados
    data_mac = omac1_aes_128_2(key, buf[:16 + data_len])
    # Calcula la etiqueta de autenticacion combinando los MACs
    for i in range(AES_BLOCK_SIZE):
        # Combina los MACs usando la operacion XOR
        tag[i] = nonce_mac[i] ^ hdr_mac[i] ^ data_mac[i]
    # Retorna los datos cifrados
    return encrypted_data


def aes_128_ctr_decrypt(key, nonce, data):
    """
    Descifra datos usando AES-128 en modo CTR.

    Inputs:
      - key: La clave de 128 bits (16 bytes) utilizada para la encriptacion.
      - nonce: Un valor unico de 128 bits (16 bytes) para el modo CTR.
      - data: Los datos cifrados a ser descifrados (bytes).

    Outputs:
      - Los datos descifrados (bytes).
    """
    # Crea una instancia del cifrador AES en modo CTR con la clave y el nonce proporcionados
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    # Crea un objeto para realizar la desencriptacion
    decryptor = cipher.decryptor()
    # Descifra los datos y retorna el resultado concatenado con el finalizador
    return decryptor.update(data) + decryptor.finalize()


def aes_128_eax_decrypt(key, nonce, nonce_len, hdr, hdr_len, data, data_len, tag):
    """
    Descifra datos usando AES-128 en modo EAX, verificando la autenticidad del nonce,
    el encabezado y los datos a través de MACs.

    Inputs:
      - key: La clave de 128 bits (16 bytes) utilizada para la encriptacion.
      - nonce: Un valor único de 128 bits (16 bytes) para el modo EAX.
      - nonce_len: La longitud del nonce en bytes.
      - hdr: El encabezado a ser autenticado (bytes).
      - hdr_len: La longitud del encabezado en bytes.
      - data: Los datos cifrados a ser descifrados (bytes).
      - data_len: La longitud de los datos en bytes.
      - tag: La etiqueta de autenticación que se debe verificar (debería tener al menos 16 bytes).

    Outputs:
      - Los datos descifrados (bytes) si la verificacion es exitosa.
      - -2 si la verificacion falla.
    """
    # Calcula la longitud maxima necesaria para el buffer
    buf_len = max(nonce_len, data_len, hdr_len) + 16
    # Inicializa un buffer de tamaño adecuado
    buf = bytearray(buf_len)
    # Inicializa el buffer con ceros
    buf[:15] = b'\x00' * 15
    # MAC para el nonce
    # Marca el inicio del nonce
    buf[15] = 0
    # Copia el nonce al buffer
    buf[16:16 + nonce_len] = nonce
    # Calcula el MAC del nonce
    nonce_mac = omac1_aes_128_2(key, buf[:16 + nonce_len])
    # MAC para el encabezado
    # Marca el inicio del encabezado
    buf[15] = 1
    # Copia el encabezado al buffer
    buf[16:16 + hdr_len] = hdr
    # Calcula el MAC del encabezado
    hdr_mac = omac1_aes_128_2(key, buf[:16 + hdr_len])
    # MAC para los datos cifrados
    # Marca el inicio de los datos
    buf[15] = 2
    # Copia los datos cifrados al buffer
    buf[16:16 + data_len] = data
    # Calcula el MAC de los datos
    data_mac = omac1_aes_128_2(key, buf[:16 + data_len])
    # Verifica la etiqueta de autenticacion
    for i in range(AES_BLOCK_SIZE):
        # Compara el tag calculado con el tag recibido
        if tag[i] != (nonce_mac[i] ^ data_mac[i] ^ hdr_mac[i]):
            # Retorna -2 si la verificación falla
            return -2
    # Desencripta los datos usando el MAC del nonce
    decrypted_data = aes_128_ctr_decrypt(key, nonce_mac, data)
    # Retorna los datos descifrados
    return decrypted_data


def EAP_PSK_FLAGS_SET_T(t):
    """
    Ajusta los bits 6 y 7 de la variable 't'.

    Args:
    t (int): El valor que se ajustara.

    Returns:
    int: El valor de 't' desplazado a la izquierda por 6 posiciones.
    """

    # Limita 't' a 2 bits (0x03) y desplaza el resultado a la izquierda por 6 posiciones
    return (t & 0x03) << 6


def parser_mensaje1(hex_packet):
    """
    Parsea el paquete EAP-PSK-1 hexadecimal y extrae su informacion.

    Args:
    hex_packet (str): El paquete en formato hexadecimal.

    Returns:
    ID, T, RAND_S e ID_S en formato hexadecimal. Retorna (None, None, None, None) en caso de error.
    """
    # Intenta convertir el paquete hexadecimal a un bytearray
    try:
        byte_packet = binascii.unhexlify(hex_packet.replace(" ", ""))
    # Maneja errores de conversion
    except binascii.Error as e:
        print("Error al convertir el paquete hexadecimal:", e)
        return None, None, None, None
    # Verifica si el paquete esta vacio
    if not byte_packet:
        print("El paquete hexadecimal está vacío o no es válido.")
        return None, None, None, None
    # Verifica la longitud del paquete
    if len(byte_packet) < 5:
        print("El paquete no contiene suficientes datos.")
        return None, None, None, None
    # Extrae el codigo del mensaje
    code = byte_packet[0]
    # Extrae el ID del mensaje
    id_ = byte_packet[1]
    # Calcula la longitud del mensaje
    length = (byte_packet[2] << 8) + byte_packet[3]
    # Extrae el tipo del mensaje
    type_ = byte_packet[4]
    # Extrae el payload del mensaje (desde el byte 5 en adelante)
    payload = bytes(byte_packet[5:])
    # Imprime la informacion extraida
    print("\nCampos del mensaje EAP:")
    print(f"Code: {code}\nID: {id_}\nLength: {length}\nType: {type_}")
    print(f"Payload: {binascii.hexlify(payload).decode('utf-8')}")
    # Verifica la longitud del payload
    if len(payload) < 17:
        print("Error: El payload no contiene suficientes datos para extraer RAND_S e ID_S.")
        return None, None, None, None
    # Extrae los flags del payload
    flags = payload[0:1]
    # Extrae RAND_S (16 bytes) del payload
    rand_s = payload[1:17]
    # Extrae ID_S del payload
    id_s = payload[17:]
    # Imprime los campos especificos del primer mensaje EAP-PSK
    print("\nCampos específicos del primer mensaje EAP-PSK:")
    print("Flags:", binascii.hexlify(flags).decode('utf-8'))
    print("RAND_S:", binascii.hexlify(rand_s).decode('utf-8'))
    print("ID_S:", id_s.decode('utf-8'))
    print("ID_S (hex):", binascii.hexlify(id_s).decode('utf-8'))
    # Extrae el tipo de emnsaje T de los flags
    T = flags[0] >> 6
    # Extrae el campo reservado de los flags
    Reserved = flags[0] & 0x1F
    # Imprime la informacion de los campos dentro de Flags
    print("\nCampos dentro de Flags:")
    print("T (tipo):", bin(T)[2:])
    print("Reserved:", bin(Reserved)[2:])
    # Retorna los resultados: ID, tipo T, RAND_S y ID_S en formato hexadecimal
    return id_, T, binascii.hexlify(rand_s).decode('utf-8'), binascii.hexlify(id_s).decode('utf-8')


def parser_mensaje3(hex_packet):
    """
    Parsea el paquete EAP-PSK-3 hexadecimal y extrae su informacion.

    Args:
    hex_packet (str): El paquete en formato hexadecimal.

    Returns:
    ID, T, RAND_S e ID_S en formato hexadecimal. Retorna (None, None, None, None) en caso de error.
    """
    # Intenta convertir el paquete hexadecimal a bytes
    try:
        byte_packet = binascii.unhexlify(hex_packet.replace(" ", ""))
    # Maneja errores de conversion
    except binascii.Error as e:
        print("Error al convertir el paquete hexadecimal:", e)
        return None, None, None, None, None, None, None, None
    # Verifica si el paquete esta vacio
    if not byte_packet:
        print("El paquete hexadecimal esta vacio o no es valido.")
        return None, None, None, None, None, None, None, None
    # Extrae los campos del paquete manualmente
    # Codigo del mensaje
    code = byte_packet[0]
    # ID del mensaje
    id_ = byte_packet[1]
    # Longitud del mensaje
    length = (byte_packet[2] << 8) + byte_packet[3]
    # Tipo del mensaje
    type_ = byte_packet[4]
    # Los bytes restantes son el payload del mensaje
    payload = byte_packet[5:]
    # Crea un paquete Scapy desde los bytes
    packet = Ether() / EAP(code=code, id=id_, len=length, type=type_) / Raw(payload)
    # Extrae y muestra los campos EAP relevantes
    if EAP in packet:
        # Obtiene el paquete EAP
        eap_packet = packet[EAP]
        print("\nCampos del mensaje EAP:")
        # Imprime el codigo
        print("Code:", eap_packet.code)
        # Imprime la identificación
        print("ID:", eap_packet.id)
        # Imprime la longitud
        print("Length:", eap_packet.len)
        # Imprime el tipo
        print("Type:", eap_packet.type)
        print("Payload", payload.hex())
        # Extrae los campos especificos del EAP-PSK
        if eap_packet.haslayer(Raw):
            # Carga el payload en crudo
            raw_payload = eap_packet[Raw].load
            # Extrae los flags
            flags = raw_payload[0:1]
            # Extrae RAND_S (16 bytes)
            rand_s = raw_payload[1:17]
            # Extrae MAC_S (16 bytes)
            mac_s = raw_payload[17:33]
            # Extrae PCHANNEL
            pchannel_data = raw_payload[33:]
            # Verifica la longitud de los datos del PCHANNEL
            if len(pchannel_data) < 21:
                print("Error: Los datos PCHANNEL son demasiado cortos")
                return id_, None, None, None, None, None, None, None
            # Imprime los campos específicos del tercer mensaje EAP-PSK
            print("\nCampos específicos del tercer mensaje EAP-PSK:")
            # Imprime flags en formato hexadecimal
            print("Flags:", binascii.hexlify(flags).decode('utf-8'))
            # Imprime RAND_S en formato hexadecimal
            print("RAND_S:", binascii.hexlify(rand_s).decode('utf-8'))
            # Imprime MAC_S en formato hexadecimal
            print("MAC_S:", binascii.hexlify(mac_s).decode('utf-8'))
            # Imprime el PCHANNEL en formato hexadecimal
            print("PCHANNEL:", binascii.hexlify(pchannel_data).decode('utf-8'))
            # Extrae la informacion de los flags
            print("\nCampos dentro de Flags:")
            # Extrae el tipo de mensaje T
            T = flags[0] >> 6
            # Imprime el tipo T en binario
            print("T (tipo):", bin(T)[2:])
            # Extrae el campo reservado
            Reserved = flags[0] & 0x1F
            # Imprime el campo reservado en binario
            print("Reserved:", bin(Reserved)[2:])
            # Extrae los campos dentro del PCHANNEL
            # Extrae el nonce
            nonce = pchannel_data[0:4]
            # Extrae la etiqueta
            etiqueta = pchannel_data[4:20]
            # Extrae R
            r = (pchannel_data[20] >> 6)
            # Extrae E
            e = (pchannel_data[20] >> 5) & 0x01
            # Extrae el campo reservado
            reservado = pchannel_data[20] & 0x1F
            # Imprime la información del PCHANNEL
            print("\nCampos dentro de PCHANNEL:")
            # Imprime el nonce en formato hexadecimal
            print("Nonce:", binascii.hexlify(nonce).decode('utf-8'))
            # Imprime la etiqueta en formato hexadecimal
            print("Etiqueta:", binascii.hexlify(etiqueta).decode('utf-8'))
            # Imprime R en binario omitiendo el prefijo que indica que es binario
            print("R (resultado):", bin(r)[2:])
            # Imprime E
            print("E:", e)
            # Imprime el campo reservado
            print("Reservado:", reservado)
            # Retorna los resultados extraidos
            return id_, T, binascii.hexlify(rand_s).decode('utf-8'), binascii.hexlify(mac_s).decode('utf-8'), \
                binascii.hexlify(pchannel_data).decode('utf-8'), binascii.hexlify(nonce).decode('utf-8'), \
                binascii.hexlify(etiqueta).decode('utf-8'), r
    else:
        # Maneja el caso donde no se encuentra la capa EAP
        print("No se encontró capa EAP en el paquete.")
        return id_, None, None, None, None, None, None, None


def calcular_tamano_total_hexadecimal(*args):
    """
    Calcula el tamaño total de un mensaje EAP sumando el tamaño de los campos dados en hexadecimal.

    Args:
        *args (str | int): Tamaños de los campos en formato hexadecimal o enteros.

    Returns:
        int: Tamaño total del mensaje EAP en bytes.

    Raises:
        ValueError: Si alguno de los campos no es un hexadecimal valido o un entero.
    """
    # Inicializa el tamaño total con 2, ya que el campo length ocupa dos bytes
    tamano_total = 2
    # Itera sobre los argumentos recibidos
    for campo in args:
        # Verifica si el campo es un entero
        if isinstance(campo, int):
            # Convierte el entero a su representacion hexadecimal sin prefijo '0x'
            campo_hex = format(campo, 'x')
        # Verifica si el campo es una cadena
        elif isinstance(campo, str):
            # Asigna el campo directamente
            campo_hex = campo
        else:
            # Lanza un error si el tipo no es valido
            raise ValueError(f"El campo '{campo}' no es un tipo válido (debe ser str o int).")
        # Intenta calcular el tamaño del campo en bytes
        try:
            # Calcula el tamaño del campo en bytes a partir de su representacion hexadecimal
            tamano_campo = len(bytes.fromhex(campo_hex))
            # Suma el tamaño del campo al tamaño total
            tamano_total += tamano_campo
        except ValueError:
            # Lanza un error si el campo no es un hexadecimal valido
            raise ValueError(f"El campo '{campo_hex}' no es un hexadecimal válido.")
    # Retorna el tamaño total calculado
    return tamano_total


def convertir_a_hexadecimal(campo):
    """
    Convierte un campo a su representacion hexadecimal.

    Args:
        campo (int | str): El campo a convertir, puede ser un entero o una cadena.

    Returns:
        str: Representacion en hexadecimal del campo.

    Raises:
        ValueError: Si la cadena no esta en formato hexadecimal.
        TypeError: Si el campo no es un int o str.
    """
    # Verifica si el campo es un entero
    if isinstance(campo, int):
        # Convierte el entero a hexadecimal, asegurando que tenga al menos 2 digitos con ceros a la izquierda
        return '{:02x}'.format(campo)
    # Verifica si el campo es una cadena
    elif isinstance(campo, str):
        # Intenta verificar si la cadena ya esta en formato hexadecimal
        try:
            # Intenta decodificar la cadena para verificar que es una cadena hexadecimal valida
            binascii.unhexlify(campo)
            # Si es valida, simplemente la devuelve sin modificar
            return campo
        except (TypeError, binascii.Error):
            # Si no es valida, lanza una excepcion indicando que no es hexadecimal
            raise ValueError("La cadena no está en formato hexadecimal: {}".format(campo))
    # Si el campo no es ni entero ni cadena, lanza una excepcion de tipo
    else:
        raise TypeError("El campo debe ser int o str, no {}".format(type(campo)))


def verificar_r_flag(decrypted_hex):
    """
    Verifica el valor del flag R en el mensaje desencriptado.

    Args:
        decrypted_hex (str): El valor desencriptado en formato hexadecimal.

    Returns:
        None
    """
    # Convierte la cadena hexadecimal a una secuencia de bytes
    decrypted = bytes.fromhex(decrypted_hex)
    # Obtiene el primer byte y lo desplaza 6 bits a la derecha para extraer el flag R
    r_flag = decrypted[0] >> 6
    # Verifica si el valor del flag R coincide con alguna de las constantes definidas
    if r_flag == EAP_PSK_R_FLAG_CONT:
        # Si el valor del flag es CONT, lo imprime como no soportado
        print("EAP-PSK: R flag - CONT - unsupported")
    elif r_flag == EAP_PSK_R_FLAG_DONE_SUCCESS:
        # Si el valor del flag es DONE_SUCCESS, lo imprime
        print("EAP-PSK: R flag - DONE_SUCCESS")
    elif r_flag == EAP_PSK_R_FLAG_DONE_FAILURE:
        # Si el valor del flag es DONE_FAILURE, lo imprime y advierte que la autenticación fue rechazada
        print("EAP-PSK: R flag - DONE_FAILURE")
        print("EAP-PSK: Authentication server rejected authentication")
    else:
        # Si el valor del flag es desconocido, lo imprime como un valor desconocido
        print("EAP-PSK: R flag - unknown value")


def be_to_host16(val):
    """
    Convierte un valor de 16 bits de big-endian a formato host.

    Args:
        val (bytes): Un valor de 2 bytes en formato big-endian.

    Returns:
        int: El valor convertido en formato de la arquitectura del host.
    """
    # Desempaqueta los 2 bytes (big-endian) en un entero de 16 bits sin signo
    return struct.unpack('!H', val)[0]


def WPA_GET_BE24(val):
    """
    Convierte un valor de 24 bits de big-endian a formato host.

    Args:
        val (bytes): Un valor de 3 bytes en formato big-endian.

    Returns:
        int: El valor convertido en formato de la arquitectura del host.
    """
    # Añade un byte nulo al principio para convertir 24 bits a 32 bits, y desempaqueta como entero de 32 bits sin signo
    return struct.unpack('!I', b'\x00' + val)[0]


def WPA_GET_BE32(val):
    """
    Convierte un valor de 32 bits de big-endian a formato host.

    Args:
        val (bytes): Un valor de 4 bytes en formato big-endian.

    Returns:
        int: El valor convertido en formato de la arquitectura del host.
    """
    # Desempaqueta los 4 bytes (big-endian) en un entero de 32 bits sin signo
    return struct.unpack('!I', val)[0]


def eap_hdr_validate(vendor, eap_type, msg):
    """
    Valida el encabezado EAP (EAP header) y, si es valido, retorna el mensaje restante y la longitud del payload.

    Args:
        vendor (int): El identificador del proveedor (vendor ID) esperado.
        eap_type (int): El tipo de EAP esperado.
        msg (bytes): El mensaje EAP a validar.

    Returns:
        El mensaje restante despues del encabezado EAP y la longitud del payload. Devuelve None si hay algun error.
    """
    # Inicializa el tamaño del payload a 0
    plen = 0
    # Verifica si el mensaje es lo suficientemente largo para contener un encabezado EAP (mínimo 4 bytes)
    if len(msg) < 4:
        # Imprime un error si el mensaje es muy corto
        print("EAP: Too short EAP frame")
        # Retorna None ya que el mensaje no es valido
        return None, plen
    # Extrae los primeros 4 bytes del mensaje como el encabezado EAP
    hdr = msg[:4]
    # Obtiene el campo de longitud del encabezado (bytes 2 y 3) en formato big-endian y lo convierte a entero
    length = be_to_host16(hdr[2:4])
    # Verifica si el valor de la longitud es valido (mínimo 5 bytes y no mayor que el mensaje completo)
    if length < 5 or length > len(msg):
        # Imprime un mensaje de error si la longitud es invalida
        print("EAP: Invalid EAP length")
        # Retorna None si el valor de la longitud no es correcto
        return None, plen
    # Define la posicion actual dentro del mensaje, comenzando despues del encabezado (byte 4)
    pos = 4
    # Verifica si el tipo de EAP es el tipo expandido (indicado por el valor especial EAP_TYPE_EXPANDED)
    if msg[pos] == EAP_TYPE_EXPANDED:
        # Verifica si la longitud es suficiente para un mensaje EAP expandido (mínimo 12 bytes)
        if length < 12:
            # Imprime un error si la longitud es menor a lo necesario para un mensaje expandido
            print("EAP: Invalid expanded EAP length")
            # Retorna None si no es valido
            return None, plen
        # Avanza la posicion en el mensaje (1 byte por el tipo de EAP expandido)
        pos += 1
        # Extrae el campo del proveedor expandido (vendor) de 3 bytes y lo convierte a entero big-endian
        exp_vendor = WPA_GET_BE24(msg[pos:pos + 3])
        # Avanza la posicion otros 3 bytes (por el campo del proveedor)
        pos += 3
        # Extrae el campo de tipo expandido de 4 bytes y lo convierte a entero big-endian
        exp_type = WPA_GET_BE32(msg[pos:pos + 4])
        # Avanza la posicion otros 4 bytes (por el campo del tipo)
        pos += 4
        # Verifica si el proveedor expandido y el tipo coinciden con los valores esperados
        if exp_vendor != vendor or exp_type != eap_type:
            # Imprime un mensaje de error si el tipo o proveedor expandido no coinciden
            print("EAP: Invalid expanded frame type")
            # Retorna None si no son correctos
            return None, plen
        # Calcula el tamaño del payload restando los 12 bytes del encabezado expandido del valor de la longitud
        plen = length - 12
        # Retorna el mensaje restante (sin el encabezado) y el tamaño del payload
        return msg[pos:], plen
    else:
        # Verifica si el proveedor y el tipo EAP no expandido coinciden con los esperados
        if vendor != EAP_VENDOR_IETF or msg[pos] != eap_type:
            # Imprime un mensaje de error si no coinciden el tipo o proveedor
            print("EAP: Invalid frame type")
            # Retorna None si no es valido
            return None, plen
        # Calcula el tamaño del payload restando los 5 bytes del encabezado estandar
        plen = length - 5
        # Retorna el mensaje restante (sin encabezado) y el tamaño del payload
        return msg[pos + 1:], plen
