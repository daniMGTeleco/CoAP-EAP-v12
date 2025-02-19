#!/usr/bin/env python3
# Copyright (c) 2024 Daniel Menéndez González
# SPDX-License-Identifier: MIT

""" Este código implementa una función para obtener la dirección IP del adaptador Wi-Fi"""

# Importo la biblioteca psutil para acceder a informacion del sistema, como interfaces de red
import psutil
# Importo la biblioteca socket para trabajar con direcciones y familias de direcciones (como IPv4)
import socket


def get_wifi_ip():
    # Obtengo las direcciones de todas las interfaces de red disponibles en el sistema
    interfaces = psutil.net_if_addrs()
    # Itero sobre las interfaces obtenidas, que incluyen el nombre de la interfaz y sus direcciones asociadas
    for interface, addrs in interfaces.items():
        # Verifico si el nombre de la interfaz contiene "Wi-Fi" o "WiFi", lo que indica que es un adaptador Wi-Fi
        if 'Wi-Fi' in interface or 'WiFi' in interface:
            # Itero sobre las direcciones asociadas a esa interfaz
            for addr in addrs:
                # Verifico si la direccion es del tipo IPv4 usando AF_INET
                if addr.family == socket.AF_INET:
                    # Si encuentro una dirección IPv4, la retorno como un string
                    return addr.address
    # Si no encuentro una interfaz Wi-Fi o una dirección IPv4, retorno None
    return None
