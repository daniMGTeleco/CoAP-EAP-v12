#!/usr/bin/env python3
# Copyright (c) 2013 Michal Garcarz
# Modificado por Daniel Menéndez González, 2024
# Licensed under the Open Software License version 3.0
# Nota: Este archivo ha sido modificado a partir de la biblioteca radiustest.

"""Este código es el script radiusattr.py de la biblioteca radiustest. El objetivo de este código es definir, construir
y manejar atributos de un paquete RADIUS. El único cambio que he realizado, ha sido estabalecer el valor por defecto del
atributo a una cadena de bytes vacía, en lugar de a una cadena str vacía para eliminar un warning."""

# Se realizan los imports de las bibliotecas necesarias
from scapy.fields import *
from scapy.packet import *
from hashlib import *
import struct


# Defino una clase que representa un atributo RADIUS como un paquete
class RadiusAttr(Packet):
    # Defino el nombre del paquete
    name = "RadiusAttr"
    # Defino los campos del paquete, donde 'type' es un ByteEnumField que mapea valores enteros a tipos de atributos RADIUS
    fields_desc = [ByteEnumField("type", 1,
                                 {1: "User-Name",
                                  2: "User-Password",
                                  4: "NAS-IP-Address",
                                  5: "NAS-Port",
                                  6: "Service-Type",
                                  7: "Framed-Protocol",
                                  8: "Framed-IP-Address",
                                  9: "Framed-IP-Netmask",
                                  11: "Filter-id",
                                  12: "Framed-MTU",
                                  13: "Framed-Compression",
                                  24: "State",
                                  26: "Vendor-Specific",
                                  30: "Called-Station-Id",
                                  31: "Calling-Station-Id",
                                  40: "Acct-Status-Type",
                                  44: "Acct-Session-Id",
                                  61: "NAS-Port-Type",
                                  77: "Connect-Info",
                                  79: "EAP-Message",
                                  80: "Message-Authenticator",
                                  87: "NAS-Port-Id",
                                  255: "Reserved"}),
                   # Campo de longitud para los datos del atributo
                   ByteField("len", None),
                   # Campo que contiene el valor del atributo, su longitud es dinamica
                   StrLenField("value", b"")]

    # Defino un metodo 'post_build' que se ejecuta despues de que el paquete se construya. Este metodo recibe dos
    # argumentos: 'p' (paquete construido hasta este punto) y 'pay' (payload adicional).
    def post_build(self, p, pay):
        # Añado la carga util (payload) 'pay' al paquete 'p'
        p += pay
        # Asigno el valor de 'self.len' a 'l'
        l = self.len
        # Si la longitud es 'None', calculo la longitud real del paquete
        if l is None:
            # Asigno 'l' a la longitud total del paquete 'p'
            l = len(p)
            # Reemplazo el segundo byte del paquete 'p' por la longitud 'l' empaquetada en un byte
            # 'p[:1]' toma la totalidad del contenido del paquete antes del segundo byte
            # 'struct.pack("!B", l)' convierte la longitud 'l' en un unico byte en formato big-endian
            # 'p[2:]' toma el contenido restante del paquete despues del segundo byte, sin modificarlo
            # El resultado es un paquete 'p' con el segundo byte actualizado con el valor de la longitud
            p = p[:1] + struct.pack("!B", l) + p[2:]
        # Devuelvo el paquete modificado
        return p

    # Metodo que realiza una operacion XOR entre dos cadenas de bytes
    def xor_strings(self, xs, ys):
        # Con x ^ y aplico la operacion XOR entre los bytes x e y
        # Con chr() convierto el resultado de XOR de nuevo a caracter
        # Con zip(xs, ys) combino los elementos de 'xs' y 'ys' en pares
        # Retorno la cadena resultante de aplicar XOR entre cada par de bytes de xs e ys
        return "".join(chr(x ^ y) for x, y in zip(xs, ys))

    # Metodo estatico que cifra una contraseña con el autenticador y un secreto compartido usando MD5
    @staticmethod
    def Encrypt_Pass(password, authenticator, secret):
        # Inicializo el hash MD5
        m = md5()
        # Actualizo el hash con el secreto compartido y el autenticador
        m.update(secret + authenticator)
        # Realizo una operacion XOR entre la contraseña y el digest MD5, y retorno la contraseña cifrada
        return "".join(chr(x ^ y) for x, y in zip(password.ljust(16, '\0').encode('utf-8')[:16], m.digest()[:16]))

