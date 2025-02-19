#!/usr/bin/env python3
# Copyright (c) 2024 Daniel Menéndez González
# SPDX-License-Identifier: MIT

"""Este código implementa una función que descifra las claves MS contenidas en los atributos Vendor Specific con
vendor ID de Microsoft del mensaje Access-Accept enviado por el EAP Server. Si se concatena la MS-MPPE-Recv-Key
descifrada con la MS-MPPE-Send-Key descifrada se obtiene la MSK necesaria para que el EAP Authenticator cree su contexto
de seguridad OSCORE."""

# Importo la biblioteca hashlib para usar el algoritmo MD5
import hashlib
# Importo Optional para definir tipos que pueden ser None
from typing import Optional


# Defino una función para generar el hash MD5 de una lista de datos concatenados
def md5_vector(data_list):
    """Genera el hash MD5 de una lista de datos concatenados"""
    # Inicializo el algoritmo MD5
    md5 = hashlib.md5()
    # Itero sobre cada elemento en la lista de datos
    for data in data_list:
        # Actualizo el cálculo de MD5 con los datos
        md5.update(data)
    # Devuelvo el hash MD5 resultante
    return md5.digest()


# Defino la función para desencriptar la clave MS utilizando MD5 y la operación XOR en bloques de 16 bytes
def decrypt_ms_key(key: bytes, req_authenticator: bytes, secret: bytes) -> Optional[bytes]:
    """Desencripta la clave MS usando MD5 y XOR en bloques de 16 bytes."""

    # Compruebo que la longitud de la clave es al menos de 18 bytes (2 bytes de salt + 16 bytes de datos cifrados)
    if len(key) < 2 + 16:
        # Si el tamaño de key es menor de 18 bytes, no se puede desencriptar correctamente y muestro un mensaje de error
        print("Key is too short")
        # Termino la función y retorno None
        return None

    # Obtengo la Salt: los primeros 2 bytes de la clave MS
    salt = key[:2]
    # Obtengo los bloques cifrados: el resto de bytes despues de la Salt
    encrypted_blocks = key[2:]

    # Compruebo que los datos cifrados son múltiplos de 16
    if len(encrypted_blocks) % 16 != 0:
        # Si el tamaño de los bloques cifrados no es múltiplo de 16 muestro un mensaje de error
        print("Invalid MS key length")
        # Termino la funcion y retorno None
        return None

    # Inicializo estas variables:
    # Un array de bytes vacio para almacenar los bloques descifrados
    decrypted_data = bytearray()
    # Una variable para controlar si es la primera iteracion
    first = True
    # La cantidad de bytes cifrados restantes
    left = len(encrypted_blocks)
    # Un puntero para recorrer el bloque cifrado actual
    currentblock_pos = 0
    # Un puntero para recorrer el bloque cifrado anterior
    previousblock_pos = 0

    # Proceso de descifrado en bloques de 16 bytes
    # Contador de iteraciones (lo inicio en 1)
    iteration = 1
    # Mientras haya bloques cifrados por procesar
    while left > 0:
        # Si es la primera iteracion
        if first:
            # Para b(1): MD5(Secret + Request-Authenticator + Salt)
            # Concateno Secret, Request-Authenticator y Salt
            data_to_hash = [secret, req_authenticator, salt]
            # Marco que ya no es la primera iteracion
            first = False
        # Para las siguientes iteraciones
        else:
            # Para b(i) (i > 1): MD5(Secret + c(i - 1))
            # Tomo el bloque cifrado anterior (para la segunda iteracion seran los primeros 16 bytes despues de Salt y
            # para la tercera iteracion seran los segundos 16 bytes despues de Salt)
            previous_encrypted_block = encrypted_blocks[previousblock_pos:previousblock_pos + 16]
            # Avanzo el puntero del bloque cifrado anterior
            previousblock_pos += 16
            # Concateno Secret y el bloque cifrado anterior
            data_to_hash = [secret, previous_encrypted_block]
            # Imprimo la parte de la MS Key que ha sido descifrada en cada iteracion
            print(f"  Bloque descifrado: {decrypted_data[-16:].hex()}\n")
            # Verifico el bloque cifrado anterior (c(1) para la segunda iteracion o c(2) para la tercera iteracion)
            # mostrando su valor en hexadecimal
            print(f"  Bloque cifrado anterior (c({iteration - 1})): {previous_encrypted_block.hex()}")

        # Genero el hash MD5 con los datos concatenados (Secret + algo mas) y calculo el hash MD5 (b(i))
        md5_hash = md5_vector(data_to_hash)

        # Muestro el numero de iteracion
        print(f"Iteración {iteration}:")
        # Muestro los datos que seran usados para calcular MD5
        print("  Datos para MD5:")
        # Para cada bloque de datos en `data_to_hash`
        for data in data_to_hash:
            # Muestro los datos en hexadecimal
            print(f"    {data.hex()}")
        # Muestro el hash MD5 calculado en hexadecimal
        print(f"  Hash MD5 (b({iteration})): {md5_hash.hex()}")

        # Tomo el bloque cifrado actual (tamaño de 16 bytes)
        current_block = encrypted_blocks[currentblock_pos:currentblock_pos + 16]
        # Realizo la operacion XOR entre cada byte del bloque cifrado actual y del hash MD5
        decrypted_block = bytes([current_block[i] ^ md5_hash[i] for i in range(16)])

        # Imprimo el bloque cifrado actual y el resultado de la operación XOR
        print(f"  Bloque cifrado actual: {current_block.hex()}")  # Muestro el bloque cifrado actual en hexadecimal
        print(f"  Resultado de XOR: {decrypted_block.hex()}")  # Muestro el resultado de la XOR en hexadecimal

        # Añado el bloque descifrado al array de datos descifrados
        decrypted_data.extend(decrypted_block)

        # Actualizo los punteros y la longitud restante
        # Avanzo el puntero del bloque cifrado actual
        currentblock_pos += 16
        # Reduzco la cantidad de bytes restantes por procesar
        left -= 16
        # Incremento el contador de iteraciones
        iteration += 1

    # Valido que el primer byte indica el tamaño correcto
    if decrypted_data[0] == 0 or decrypted_data[0] > len(decrypted_data) - 1:
        # Si el primer byte es 0 o mayor que la longitud del array, hay un error y muestro un mensaje indicandolo
        print("Failed to decrypt MPPE key")
        # Termino la funcion y retorno None
        return None

    # La MS Key descifrada empieza en el segundo byte y tiene el tamaño indicado por el primer byte
    decrypted_key = decrypted_data[1:1 + decrypted_data[0]]

    # Imprimo la clave descifrada final en hexadecimal
    print("Decrypted MS Key (hex):", decrypted_key.hex())

    # Retorno la clave descifrada
    return decrypted_key
