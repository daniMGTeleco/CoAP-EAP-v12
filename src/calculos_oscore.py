#!/usr/bin/env python3
# Copyright (c) 2024 Daniel Menéndez González
# SPDX-License-Identifier: MIT

"""Este código implementa una función deriva las claves necesarias para OSCORE a partir de un secreto maestro (MSK)
y una cadena opcional (CSO) en formato hexadecimal. La cadena CSO son los valores concatenados de la negociación de
CryptoSuite tanto del Controlador (autenticador EAP) como la respuesta del dispositivo IoT (par EAP). Devuelve la
Master Secret y la Master Salt."""

# Importo la funcion HKDF (Key Derivation Function) del modulo de criptografia
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# Importo el modulo de hash para utilizar el algoritmo SHA256
from cryptography.hazmat.primitives import hashes
# Importo el backend predeterminado para las operaciones de criptografia
from cryptography.hazmat.backends import default_backend


def derive_oscore_keys(msk, cs_hex=None):
    # Defino constantes que se usaran en la derivacion de claves para OSCORE
    # Esta es la cadena para la Master Secret
    OSCORE_MASTER_SECRET_STR = b"COAP-EAP OSCORE Master Secret"
    # Esta es la cadena para el Master Salt
    OSCORE_MASTER_SALT_STR = b"COAP-EAP OSCORE Master Salt"
    # Esta es la cadena para el ID del remitente
    OSCORE_SENDER_ID_STR = b"OSCORE SENDER ID"
    # Esta es la cadena para el ID del receptor
    OSCORE_RECIPIENT_ID_STR = b"OSCORE RECIPIENT ID"

    # Si se proporciona un CS hexadecimal, lo convierto en bytes; de lo contrario, uso una cadena vacia
    if cs_hex:
        # Convierto el CSO hexadecimal a bytes
        CS = bytes.fromhex(cs_hex)
    else:
        # Si no se proporciona el CS, el valor utilizado para generar CS sera el mismo que si los algoritmos
        # predeterminados se hubieran enviado explícitamente en CS-C o CS-I (es decir, un array CBOR con la cipher
        # suite 0)
        CS = bytes.fromhex("85008100")

    # Defino las longitudes de las claves derivadas en bytes
    # Establezco 16 bytes para la Master Secret
    length_secret = 16
    # Establezco 8 bytes para el Master Salt
    length_salt = 8
    # Establezco 1 byte para el ID (ajustable según las necesidades)
    length_id = 1

    # Derivo la Master Secret
    # Concateno el CSO y la cadena para la Master Secret
    info_secret = CS + OSCORE_MASTER_SECRET_STR
    # Creo una instancia de HKDF para derivar la Master Secret
    hkdf_master_secret = HKDF(
        # Especifico el algoritmo de hash a usar (SHA256)
        algorithm=hashes.SHA256(),
        # Establezco la longitud deseada de la clave derivada (Master Secret)
        length=length_secret,
        # No utilizo sal en este caso
        salt=None,
        # Proporciono informacion adicional para HKDF
        info=info_secret,
        # Uso el backend predeterminado
        backend=default_backend()
    )
    # Derivo la Master Secret a partir de la MSK
    master_secret = hkdf_master_secret.derive(msk)

    # Derivo el Master Salt
    # Concateno el CSO y la cadena para el Master Salt
    info_salt = CS + OSCORE_MASTER_SALT_STR
    # Creo una instancia de HKDF para derivar el Master Salt
    hkdf_master_salt = HKDF(
        # Uso SHA256 como algoritmo de hash
        algorithm=hashes.SHA256(),
        # Establezco la longitud deseada de la clave derivada (Master Salt)
        length=length_salt,
        # Sin sal
        salt=None,
        # Proporciono informacion adicional para HKDF
        info=info_salt,
        # Uso el backend predeterminado
        backend=default_backend()
    )
    # Derivo la Master Salt a partir de la MSK
    master_salt = hkdf_master_salt.derive(msk)

    # Derivo el ID del remitente
    # Creo una instancia de HKDF para derivar el ID del remitente
    hkdf_sender_id = HKDF(
        # Uso SHA256 como algoritmo de hash
        algorithm=hashes.SHA256(),
        # Establezco la longitud deseada del ID (1 byte)
        length=length_id,
        # Sin sal
        salt=None,
        # Proporciono informacion adicional para derivar el ID del remitente
        info=OSCORE_SENDER_ID_STR,
        # Uso el backend predeterminado
        backend=default_backend()
    )
    # Derivo el ID del remitente a partir de la MSK
    sender_id = hkdf_sender_id.derive(msk)

    # Derivo el ID del destinatario
    # Creo una instancia de HKDF para derivar el ID del receptor
    hkdf_recipient_id = HKDF(
        # Uso SHA256 como algoritmo de hash
        algorithm=hashes.SHA256(),
        # Establezco la longitud deseada del ID (1 byte)
        length=length_id,
        # Sin sal
        salt=None,
        # Proporciono informacion adicional para derivar el ID del receptor
        info=OSCORE_RECIPIENT_ID_STR,
        # Uso el backend predeterminado
        backend=default_backend()
    )
    # Derivo el ID del destinatario a partir de la MSK
    recipient_id = hkdf_recipient_id.derive(msk)

    # Devuelvo los valores derivados en formato hexadecimal
    # Solo voy a retornar la Master Secret y la Master Salt ya que en este TFG se van a proporcionar el ID de Remitente
    # y el ID  de Destinatario de forma manual. Para obtener ambos IDs de la forma recomendada se necesita la MSK y
    # esta se obtiene en el paso 7, pero el uso de ambos IDs se requiere mucho antes, es decir, en los pasos 2 y 3 para
    # ser enviados en la estructura CBOR del EAP Request ID y del EAP Response ID, por lo que hacerlo correctamente
    # conllevaria un lógica bastante compleja que queda fuera del alcance de este TFG
    return master_secret.hex(), master_salt.hex()
