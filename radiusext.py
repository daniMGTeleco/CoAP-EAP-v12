#!/usr/bin/env python3
# Copyright (c) 2013 Michal Garcarz
# Modificado por Daniel Menéndez González, 2024
# Licensed under the Open Software License version 3.0
# Nota: Este archivo ha sido modificado a partir de la biblioteca radiustest.

"""Este código es el script radiusext.py de la biblioteca radiustest. El objetivo de este código es definir, construir
y manejar los campos estándar de un paquete RADIUS, así como también analizar y manipular mensajes RADIUS. Los únicos
cambios que he realizado, han sido estabalecer el valor por defecto del authenticator a una cadena de bytes vacia, en
lugar de a una cadena str vacia para eliminar un warning y permitir la impresion dentro de la funcion Display_Packet del
ID, la longitud y el authenticator del paquete RADIUS."""

# Se realizan los imports de las bibliotecas necesarias
from scapy.all import *
from scapy.fields import *
from scapy.layers.inet import UDP, IP
from scapy.layers.radius import Radius
from radiusattr import RadiusAttr
import array
import string
import random
import struct


# Defino una clase llamada 'RadiusExt' que hereda de la clase 'Packet'. Esta clase representa un paquete extendido para
# el protocolo RADIUS.
class RadiusExt(Packet):
    # Defino el nombre del paquete
    name = "RadiusExt"
    # El campo "code" es un byte que define el tipo de mensaje de RADIUS. El valor por defecto es 1 (Access-Request), y
    # los demas valores corresponden a diferentes tipos de mensajes RADIUS
    fields_desc = [ByteEnumField("code", 1, {1: "Access-Request",
                                             2: "Access-Accept",
                                             3: "Access-Reject",
                                             4: "Accounting-Request",
                                             5: "Accounting-Accept",
                                             6: "Accounting-Status",
                                             7: "Password-Request",
                                             8: "Password-Ack",
                                             9: "Password-Reject",
                                             10: "Accounting-Message",
                                             11: "Access-Challenge",
                                             12: "Status-Server",
                                             13: "Status-Client",
                                             21: "Resource-Free-Request",
                                             22: "Resource-Free-Response",
                                             23: "Resource-Query-Request",
                                             24: "Resource-Query-Response",
                                             25: "Alternate-Resource-Reclaim-Request",
                                             26: "NAS-Reboot-Request",
                                             27: "NAS-Reboot-Response",
                                             29: "Next-Passcode",
                                             30: "New-Pin",
                                             31: "Terminate-Session",
                                             32: "Password-Expired",
                                             33: "Event-Request",
                                             34: "Event-Response",
                                             40: "Disconnect-Request",
                                             41: "Disconnect-ACK",
                                             42: "Disconnect-NAK",
                                             43: "CoA-Request",
                                             44: "CoA-ACK",
                                             45: "CoA-NAK",
                                             50: "IP-Address-Allocate",
                                             51: "IP-Address-Release",
                                             253: "Experimental-use",
                                             254: "Reserved",
                                             255: "Reserved"}),
                   # 'ByteField' define un campo de un byte llamado "id". El valor por defecto es 0
                   ByteField("id", 0),
                   # 'ShortField' define un campo de dos bytes llamado "len" (longitud). Su valor sera asignado despues,
                   # si es necesario. El valor por defecto es None
                   ShortField("len", None),
                   # 'StrFixedLenField' define un campo de cadena con longitud fija. Se llama "authenticator" y tiene
                   # una longitud fija de 16 bytes. El valor por defecto es una cadena de bytes vacia
                   StrFixedLenField("authenticator", b"", 16)]

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
            # Reemplazo el tercer y cuarto byte del paquete 'p' por la longitud 'l' empaquetada en dos bytes
            # 'p[:2]' toma la totalidad del contenido del paquete hasta el segundo byte (no incluye el tercer byte)
            # 'struct.pack("!H", l)' convierte la longitud 'l' en dos bytes en formato big-endian (red)
            # 'p[4:]' toma el contenido restante del paquete a partir del quinto byte, sin modificarlo
            # El resultado es un paquete 'p' con el tercer y el cuarto byte actualizados con el valor de la longitud
            p = p[:2] + struct.pack("!H", l) + p[4:]
        # Retorno el paquete modificado
        return p

    ################################ GENERIC FUNCTIONS ####################################

    # Metodo que convierte una cadena de texto en su representacion hexadecimal separada por ":"
    def display_str_as_hex(src):
        # Con encode('hex') convierto cada caracter en su representacion hexadecimal
        # Con ":".join(...) uno las representaciones hexadecimales separadas por ':'
        return ":".join(x.encode('hex') for x in src)

    # Metodo que realiza una operacion XOR entre dos cadenas hexadecimales de la misma longitud
    def hexxor(a, b):
        # Convierto cada par de caracteres de 'a' y 'b' de hexadecimal a entero
        # Realizo una operacion XOR entre los enteros y convierto el resultado de nuevo a hexadecimal
        # Con zip(a, b) combino los elementos de 'a' y 'b' en pares
        return "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(a, b)])

    # Metodo que realiza una operacion XOR entre dos cadenas de caracteres
    def xor_strings(xs, ys):
        # Convierto los caracteres 'x' e 'y' a su valor ASCII con ord()
        # Realizo una operacion XOR entre ellos, y luego los convierto de nuevo a caracter con chr()
        # Con zip(xs, ys) combino los elementos de 'xs' y 'ys' en pares
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

    # Metodo que genera una cadena aleatoria de seis caracteres usando letras mayusculas y digitos
    @staticmethod
    def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
        # Con random.choice(chars) selecciono aleatoriamente un caracter de 'chars'
        # Con size defino la longitud del identificador generado
        return ''.join(random.choice(chars) for x in range(size))

    # Metodo que convierte un array de bytes a un entero mediante operaciones de desplazamiento
    @staticmethod
    def array_to_int(array):
        # Con reduce() aplico una funcion acumulativa a los elementos de 'array'
        # Con la operacion (x << 8) + y desplazo 'x' 8 bits a la izquierda (equivalente a multiplicar por 256)
        # y luego sumo el siguiente byte 'y' convirtiendo una secuencia de bytes en un unico entero
        return reduce(lambda x, y: (x << 8) + y, array)

    ################################ RADIUS FUNCTIONS ##############################

    # Este metodo extrae y retorna una lista de AVPs (Attribute-Value Pairs) de un payload de paquete RADIUS
    # input: Payload del paquete RADUIUS
    # output: Lista de los AVPs
    def Get_AVPList(self, D):
        # Convierto el payload D en una cadena
        Data = str(D)
        # Obtengo la longitud de los datos
        data_len = len(Data)
        # Inicializo el contador de longitud actual
        curr_len = 0
        # Creo una lista vacía para almacenar los AVPs
        AVP_list = []
        # Me aseguro de que haya suficiente longitud restante para leer un AVP
        while curr_len + 2 <= data_len:
            try:
                # Creo un array de bytes a partir de los datos
                result = array.array('B', Data)
                # Obtengo el tipo de AVP
                avp_type = result[curr_len + 0]
                # Obtengo la longitud del AVP
                avp_len = result[curr_len + 1]
                # Extraigo el valor del AVP utilizando la longitud obtenida
                avp_value = result[curr_len + 2:curr_len + avp_len]
                # Añado el AVP a la lista
                AVP_list.append(RadiusAttr(type=avp_type, value=avp_value))
                # Actualizo la longitud actual
                curr_len += avp_len
            except:
                # Imprimo un mensaje de error si ocurre una excepcion
                print("Exception")
                pass
        # Retorno la lista de los AVPs extraidos
        return AVP_list

    # Defino el metodo Print_AVP que toma como entrada una lista de AVPs (Attribute Value Pairs) y los imprime
    def Print_AVP(self, AVP_List):
        # Itero sobre la lista de AVPs usando su longitud
        for i in range(len(AVP_List)):
            # Almaceno el AVP actual en la variable avp
            avp = AVP_List[i]
            # Verifico si el tipo de AVP es 1 (User-Name)
            if avp.type == 1:
                # Imprimo el indice, el tipo y el valor del AVP (nombre de usuario)
                print("AVP[%d] Type: %d (User-Name) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Verifico si el tipo de AVP es 2 (User-Password)
            elif avp.type == 2:
                # Imprimo el indice, el tipo y un asterisco en lugar del valor (contraseña)
                print("AVP[%d] Type: %d (User-Password) Value: *" % (i, avp.type))
            # Verifico si el tipo de AVP es 4 (NAS-IP-Address)
            elif avp.type == 4:
                # Imprimo el indice, el tipo y el valor del AVP (direccion IP NAS)
                print("AVP[%d] Type: %d (NAS-IP-Address) Value: %s" % (i, avp.type, socket.inet_ntoa(avp.value)))
            # Verifico si el tipo de AVP es 5 (NAS-Port)
            elif avp.type == 5:
                # Imprimo el indice, el tipo y el valor del AVP (puerto NAS)
                print("AVP[%d] Type: %d (NAS-Port) Value: %s" % (i, avp.type, socket.inet_ntoa(avp.value)))
            # Verifico si el tipo de AVP es 6 (Service-Type)
            elif avp.type == 6:
                # Reduzco el valor a un entero a partir de los bytes del AVP
                val = reduce(lambda x, y: (x << 8) + y, avp.value)
                # Verifico el valor para imprimir el tipo de servicio correspondiente
                if val == 1:
                    print("AVP[%d] Type: %d (Service-Type) Value: %d (Login)" % (i, avp.type, val))
                elif val == 2:
                    print("AVP[%d] Type: %d (Service-Type) Value: %d (Framed)" % (i, avp.type, val))
                elif val == 5:
                    print("AVP[%d] Type: %d (Service-Type) Value: %d (Outbound)" % (i, avp.type, val))
                elif val == 10:
                    print("AVP[%d] Type: %d (Service-Type) Value: %d (Call-check)" % (i, avp.type, val))
                else:
                    print("AVP[%d] Type: %d (Service-Type) Value: %d" % (i, avp.type, val))
            # Verifico si el tipo de AVP es 7 (Framed-Protocol)
            elif avp.type == 7:
                # Reduzco el valor a un entero a partir de los bytes del AVP
                val = reduce(lambda x, y: (x << 8) + y, avp.value)
                # Verifico el valor para imprimir el protocolo enmarcado correspondiente
                if val == 1:
                    print("AVP[%d] Type: %d (Framed-Protocol) Value: %d (PPP)" % (i, avp.type, val))
                else:
                    print("AVP[%d] Type: %d (Framed-Protocol) Value: %d" % (i, avp.type, val))
            # Verifico si el tipo de AVP es 8 (Framed-IP-Address)
            elif avp.type == 8:
                # Imprimo el indice, el tipo y el valor del AVP (dirección IP enmarcada)
                print("AVP[%d] Type: %d (Framed-IP-Address) Value: %s" % (i, avp.type, socket.inet_ntoa(avp.value)))
            # Verifico si el tipo de AVP es 9 (Framed-IP-Netmask)
            elif avp.type == 9:
                # Imprimo el indice, el tipo y el valor del AVP (mascara de red enmarcada)
                print("AVP[%d] Type: %d (Framed-IP-Netmask) Value: %s" % (i, avp.type, socket.inet_ntoa(avp.value)))
            # Verifico si el tipo de AVP es 11 (Filter-Id)
            elif avp.type == 11:
                # Imprimo el indice, el tipo y el valor del AVP (ID de filtro)
                print("AVP[%d] Type: %d (Filter-Id) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Verifico si el tipo de AVP es 12 (Framed-MTU)
            elif avp.type == 12:
                # Reduzco el valor a un entero a partir de los bytes del AVP y lo imprimo
                val = reduce(lambda x, y: (x << 8) + y, avp.value)
                print("AVP[%d] Type: %d (Framed-MTU) Value: %d" % (i, avp.type, val))
            # Verifico si el tipo de AVP es 13 (Framed-Compression)
            elif avp.type == 13:
                # Reduzco el valor a un entero a partir de los bytes del AVP
                val = reduce(lambda x, y: (x << 8) + y, avp.value)
                # Verifico el valor para imprimir el tipo de compresion correspondiente
                if val == 1:
                    print("AVP[%d] Type: %d (Framed-Compression) Value: %d (Van-Jacobsen-TCP-IP)" % (i, avp.type, val))
                else:
                    print("AVP[%d] Type: %d (Framed-Compression) Value: %d" % (i, avp.type, val))
            # Verifico si el tipo de AVP es 24 (State)
            elif avp.type == 24:
                # Imprimo el indice, el tipo y el valor del AVP (estado)
                print("AVP[%d] Type: %d (State) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Verifico si el tipo de AVP es 25 (Class)
            elif avp.type == 25:
                # Imprimo el indice, el tipo y el valor del AVP (clase)
                print("AVP[%d] Type: %d (Class) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Verifico si el tipo de AVP es 26 (Vendor Specific Attribute)
            elif avp.type == 26:
                # Calculo el vendor_id a partir de los primeros 4 bytes del AVP
                vendor_id = int(avp.value[0]) * 256 * 256 * 256 + 256 * 256 * int(avp.value[1]) + 256 * int(
                    avp.value[2]) + int(avp.value[3])
                # Almaceno el tipo interno y el valor interno a partir del AVP
                internal_avp_type = avp.value[4]
                internal_avp_val = "".join(map(chr, avp.value[6:]))
                # Verifico el vendor_id para imprimir atributos especificos de Cisco
                if vendor_id == 9:
                    if internal_avp_type == 1:
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco) Type: %d (Cisco-AV-Pair) Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
                    elif internal_avp_type == 21:
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco) Type: %d (Cisco-Abort-Cause) Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
                    elif internal_avp_type == 244:
                        internal_avp_val_int = struct.unpack('>I', avp.value[6:])[0]
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco) Type: %d (Cisco-Idle-Limit) Value: %d" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val_int))
                    else:
                        print("AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco) Type: %d Value: %s" % (
                        i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
                # Verifico el vendor_id para imprimir atributos especificos de Motorola
                elif vendor_id == 388:
                    if internal_avp_type == 2:
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Motorola) Type: %d (Symbol-Current-ESSID) Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
                    elif internal_avp_type == 4:
                        internal_avp_val_int = 0
                        try:
                            internal_avp_val_int = struct.unpack('>I', avp.value[6:])[0]
                        except:
                            # Capturo excepciones en caso de que la conversión falle
                            pass
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Motorola) Type: %d (Symbol-WLAN-Index) Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val_int))
                    else:
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Motorola) Type: %d Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
                # Verifico el vendor_id para imprimir atributos especificos de Cisco VPN 3000
                elif vendor_id == 3076:
                    if internal_avp_type == 15:
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-IPSec-Banner1) Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
                    elif internal_avp_type == 28:
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-IPSec-Default-Domain) Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
                    elif internal_avp_type == 61:
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-DHCP-Network-Scope) Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, socket.inet_ntoa(internal_avp_val)))
                    elif internal_avp_type == 85:
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-Tunnel-Group-Lock) Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
                    elif internal_avp_type == 220:
                        internal_avp_val_int = struct.unpack('>I', avp.value[6:])[0]
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d (CVPN3000-Privilege-Level) Value: %d" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val_int))
                    else:
                        print(
                            "AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d (Cisco VPN 3000) Type: %d Value: %s" % (
                            i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
                # Si el vendor_id no coincide con ninguno de los anteriores, imprimo el valor general
                else:
                    print("AVP[%d] Type: %d (Vendor Specific Attribute) Vendor: %d Type: %d Value: %s" % (
                    i, avp.type, vendor_id, internal_avp_type, internal_avp_val))
            # Verifico si el tipo del AVP es 30 (Called-Station-Id)
            elif avp.type == 30:
                print("AVP[%d] Type: %d (Called-Station-Id) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Verifico si el tipo del AVP es 31 (Calling-Station-Id)
            elif avp.type == 31:
                print("AVP[%d] Type: %d (Calling-Station-Id) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Verifico si el tipo del AVP es 40 (Acct-Status-Type)
            elif avp.type == 40:
                # Reduzco el valor a un entero a partir de los bytes del AVP
                val = reduce(lambda x, y: (x << 8) + y, avp.value)
                # Dependiendo del valor, imprimo el tipo de estado de la cuenta correspondiente
                if val == 1:
                    print("AVP[%d] Type: %d (Acct-Status-Type) Value: %d (Start)" % (i, avp.type, val))
                elif val == 2:
                    print("AVP[%d] Type: %d (Acct-Status-Type) Value: %d (Stop)" % (i, avp.type, val))
                elif val == 3:
                    print("AVP[%d] Type: %d (Acct-Status-Type) Value: %d (Interim)" % (i, avp.type, val))
                else:
                    print("AVP[%d] Type: %d (Acct-Status-Type) Value: %s" % (i, avp.type, val))
            # Verifico si el tipo del AVP es 44 (Acct-Session-Id)
            elif avp.type == 44:
                print("AVP[%d] Type: %d (Acct-Session-Id) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Verifico si el tipo del AVP es 61 (NAS-Port-Type)
            elif avp.type == 61:
                # Reduzco el valor a un entero a partir de los bytes del AVP
                val = reduce(lambda x, y: (x << 8) + y, avp.value)
                # Dependiendo del valor, imprimo el tipo de puerto NAS correspondiente
                if val == 5:
                    print("AVP[%d] Type: %d (NAS-Port-Type) Value: %d (Virtual)" % (i, avp.type, val))
                elif val == 15:
                    print("AVP[%d] Type: %d (NAS-Port-Type) Value: %d (Ethernet)" % (i, avp.type, val))
                elif val == 19:
                    print("AVP[%d] Type: %d (NAS-Port-Type) Value: %d (Wireless-802.11)" % (i, avp.type, val))
                else:
                    print("AVP[%d] Type: %d (NAS-Port-Type) Value: %d (Virtual)" % (i, avp.type, val))
            # Verifico si el tipo del AVP es 79 (EAP-Message)
            elif avp.type == 79:
                print("AVP[%d] Type: %d (EAP-Message) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Verifico si el tipo del AVP es 80 (Message-Authenticator)
            elif avp.type == 80:
                print("AVP[%d] Type: %d (Message-Authenticator) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Verifico si el tipo del AVP es 87 (Nas-Port-Id)
            elif avp.type == 87:
                print("AVP[%d] Type: %d (Nas-Port-Id) Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))
            # Si el tipo del AVP no coincide con ninguno de los anteriores
            else:
                print("AVP[%d] Type: %d Value: %s" % (i, avp.type, "".join(map(chr, avp.value))))

    # Este metodo muestra los detalles de un paquete RADIUS incluyendo el tipo de paquete, identificador, longitud
    # y autenticador, así como una lista de pares atributo-valor (AVPs) contenidos en el paquete
    def Display_Packet(self, Packet):
        # Decodifico la carga util del paquete UDP como un paquete RADIUS
        Packet[UDP].decode_payload_as(Radius)
        # Imprimo los detalles del paquete RADIUS con las direcciones IP y puertos de origen y destino
        print("Radius packet details: %s:%d -> %s:%d" % (Packet[IP].src, Packet[UDP].sport, Packet[IP].dst, Packet[UDP].dport))
        # Verifico el codigo del paquete RADIUS y lo imprimo en funcion de su valor
        if Packet[Radius].code == 1:
            # Imprimo que el codigo es 1, lo que indica un Access-Request
            print("Radius Code: 1 (Access-Request)")
        elif Packet[Radius].code == 2:
            # Imprimo que el codigo es 2, lo que indica un Access-Accept
            print("Radius Code: 2 (Access-Accept)")
        elif Packet[Radius].code == 3:
            # Imprimo que el codigo es 3, lo que indica un Access-Reject
            print("Radius Code: 3 (Access-Reject)")
        elif Packet[Radius].code == 4:
            # Imprimo que el codigo es 4, lo que indica un Accounting-Request
            print("Radius Code: 4 (Accounting-Request)")
        elif Packet[Radius].code == 5:
            # Imprimo que el codigo es 5, lo que indica un Accounting-Response
            print("Radius Code: 5 (Accounting-Response)")
        else:
            # Imprimo el codigo RADIUS en caso de que no coincida con los anteriores
            print("Radius Code: %d" % Packet[Radius].code)
        # Imprimo el identificador del paquete RADIUS
        print("Radius Id: %d" % Packet[Radius].id)
        # Imprimo la longitud del paquete RADIUS
        print("Radius Len: %d" % Packet[Radius].len)
        # Imprimo el autenticador del paquete RADIUS en formato hexadecimal
        print("Radius Authenticator:", Packet[Radius].authenticator.hex())
        # Llamo a la funcion Print_AVP para imprimir los AVPs extraidos del paquete RADIUS
        self.Print_AVP(self.Get_AVPList(Packet[Radius].payload))
        # Imprimo una línea en blanco para separar la salida
        print("")

    # Metodo que genera un identificador aleatorio
    @staticmethod
    def Generate_id():
        # Genero un numero aleatorio entre 0 y 254 y lo retorno
        return random.randrange(255)

    # Metodo que genera un autenticador aleatorio de 16 caracteres
    @staticmethod
    def Generate_Authenticator():
        # Utilizo letras mayusculas y digitos
        chars = string.ascii_uppercase + string.digits
        # Uno aleatoriamente 16 caracteres elegidos de 'chars' en una cadena y la retorno
        return ''.join(random.choice(chars) for x in range(16))

    # Metodo que genera un autenticador de cuenta aleatorio de 16 caracteres
    @staticmethod
    def Generate_AcctAuthenticator():
        # Utilizo letras mayusculas y digitos
        chars = string.ascii_uppercase + string.digits
        # Uno aleatoriamente 16 caracteres elegidos de 'chars' en una cadena
        return ''.join(random.choice(chars) for x in range(16))
