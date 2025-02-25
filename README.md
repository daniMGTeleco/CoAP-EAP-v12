# CoAP-EAP-v15

This repository contains the implementation of the latest version (version 15) of the Internet Draft "EAP-based Authentication Service for CoAP" in Python. The CoAP-EAP implementation follows the pass-through model of its architecture, characterized by role separation, authentication externalization, and interaction among three main components:

- **EAP Peer** → IoT device to be authenticated.
- **EAP Authenticator** → Security domain manager to which the EAP Peer intends to connect. It acts as an intermediary between the EAP Peer and the EAP Server.
- **EAP Server** → Contains the logic to complete the authentication of the IoT device using the most suitable EAP method based on its characteristics. In this case, the **EAP-PSK method** is used.

In this implementation, the EAP Server is instantiated in an **Ubuntu** virtual machine running **FreeRADIUS 2.0.2**, which is used to develop a RADIUS server (AAA Server/EAP Server) with EAP-PSK support (EAP-PSK server-side implementation) in C thanks to **hostapd**.

CoAP-EAP aims to provide a standard authentication mechanism that ensures security in dynamic and resource-constrained IoT environments, contributing to a more secure, interoperable, and efficient future for these networks.

## Índice

1. [Introduction](#introduction)
2. [Implementation Specifications](#implementation-specifications)
3. [Reference Documentation](#reference-documentation)
4. [Requirements](#requirements)
5. [Installation Instructions](#installation-instructions)
6. [Usage](#usage)
7. [Acknowledgments](#acknowledgments)
8. [License](#license)
9. [Contributions](#contributions)
10. [Authors and Contact](#authors-and-contact)

## Introduction

This Internet Draft addresses the challenge of access control for resource-constrained IoT devices by developing a secure and efficient authentication service based on the Extensible Authentication Protocol **(EAP)**, transported over Constrained Application Protocol **(CoAP)** messages. Specifically, this document defines how CoAP can be used as a reliable, link-layer-independent **EAP lower layer** for constrained environments. This EAP lower layer is referred to as **CoAP-EAP**.

The primary objective of **CoAP-EAP** is to authenticate a CoAP-enabled IoT device (EAP Peer) that intends to join a security domain managed by a Controller (EAP Authenticator). Another key feature is that it allows the derivation of cryptographic material to protect CoAP messages exchanged between the EAP Peer and the EAP Authenticator using **OSCORE** (Object Security for Constrained RESTful Environments), thus facilitating the establishment of a security association between them.

This implementation replicates the complete operational flow of the latest version of the Internet Draft EAP-based Authentication Service for CoAP.

## Implementation Specifications

The implementation covers the following aspects of the draft:

- **Integration of EAP with CoAP**: Adaptation of the EAP protocol to CoAP for authentication in IoT networks, with CoAP-EAP as the EAP Lower Layer.
- **Cipher suite negotiation**: Establishment of cryptographic suites using CBOR structures for message encryption and authentication.
- **Support for EAP-PSK**: The EAP-PSK protocol is used as the EAP authentication method in this implementation. This protocol provides a secure and efficient approach, suitable for IoT devices. The implementation includes parsing and generating the corresponding messages, performing verifications, deriving all session and long-term keys, and calculating fields such as MAC_S, MAC_P, and the protected channels required for the standard authentication process. EAP-PSK is one of the simplest methods in terms of configuration since it only requires a pre-shared key (PSK) to authenticate a device or user, and its standard authentication process consists of only four messages.
- **Order guarantee**: Using URIs, applying the HATEOAS principle in the context of the CoAP-EAP protocol.
- **Message protection with OSCORE**: CoAP messages containing the EAP Success message and the 2.04 Changed code are protected using OSCORE, providing an additional layer of security and privacy. The implementation generates and configures all the necessary parameters for the OSCORE security context, including the Common Context, Sender Context, and Recipient Context. It also includes the entire process for protecting, unprotecting, or verifying each OSCORE-protected message.
- **RADIUS client integrated into the EAP Authenticator**: Development of a RADIUS client that enables communication with the EAP Server. This RADIUS client is designed to meet EAP authentication requirements, generating all messages with the necessary attributes to complete the authentication process and processing all messages received from the EAP Server. The integration with RADIUS allows delegation of the authentication and authorization process to a centralized server, improving scalability and authentication system management.
- **Decryption of the MSK received from the EAP Server**: A function has been implemented to decrypt the MSK sent by the EAP Server to the EAP Authenticator in two RADIUS attributes (MS-MPPE-Send-Key and MS-MPPE-Recv-Key). This process uses the RADIUS Shared Secret and an MD5-based iterative decryption mechanism. Once decrypted, the MSK serves as the basis for deriving the OSCORE security context, which is necessary to securely and efficiently protect subsequent communications between the EAP Peer and the Authenticator, ensuring message integrity and confidentiality. 
- **Handling of different scenarios**: Ideal successful authentication, duplicate request or late retransmission, failed authentication, and deletion of the CoAP-EAP state after successful authentication.

## Reference Documentation

This project follows multiple IETF specifications and Internet Draft documents:

- [RFC 7252](https://tools.ietf.org/html/rfc7252): The Constrained Application Protocol (CoAP).
- [RFC 3748](https://tools.ietf.org/html/rfc3748): Extensible Authentication Protocol (EAP).
- [RFC 4764](https://tools.ietf.org/html/rfc4764): EAP-PSK.
- [RFC 8613](https://tools.ietf.org/html/rfc8613): OSCORE.
- [RFC 2865](https://tools.ietf.org/html/rfc2865): RADIUS.
- [draft-ietf-ace-wg-coap-eap-12](https://datatracker.ietf.org/doc/draft-ietf-ace-wg-coap-eap/12/): Latest version of the Internet Draft EAP-based Authentication Service for CoAP.

## Requirements

To run this implementation of EAP over CoAP, make sure you have:

- **Python 3.12**: This project is designed to run in environments with Python 3.12.
- **AAA Server**: A configured RADIUS server to handle authentication requests and generate appropriate responses (virtual machine).
- **Bibliotecas y dependencias**: The implementation requires several external libraries, which are listed in `requirements.txt`.

## Installation Instructions

1. Clone this repository:
   ```bash
   git clone https://github.com/daniMGTeleco/CoAP-EAP-v12.git
   cd CoAP-EAP-v12
   ```
2. Install the dependencies listed in the requirements.txt file:
   ```bash
   pip install -r requirements.txt
   ```
3. Download the virtual machine containing the EAP Server through [this link](https://unioviedo-my.sharepoint.com/:u:/g/personal/uo276425_uniovi_es/EZtMQZl93LxDjEpuAKc5piQB-dPKXL7xn5Bzkd_R5I4Fyw?e=AuiR8q) (unzip the .zip file).
4. Open the virtual machine in **VMware Workstation 17 Player** and verify that it works correctly by entering the password (**student**).

## Usage
The project includes scripts for running the authentication service:

- **controller.py**: Initially acts as a CoAP server to receive and respond to EAP authentication requests. Once it receives the activation message, it will act as a CoAP client for the remainder of the flow.
- **peer.py**: Initially acts as a CoAP client, making a POST request to the specified URI and processing the response. Once it sends the activation message, it will act as a CoAP server, processing and responding to messages sent by the peer for the remainder of the flow.

### Ejecución del servicio de autenticación
To run the full authentication flow:

1. Open the terminal in the virtual machine with the EAP Server.
2. In the terminal, run the following three commands:
   ```bash
   cd /home/student/freeradius-psk/sbin
   export LD_PRELOAD=/home/student/coap-eap-tfg/freeradius-2.0.2-psk/hostapd/eap_example/libeap.so
   ./radiusd -X
   ```
3. If you want to see the results in **Wireshark**, select the network interfaces where you want to capture traffic and apply the following filter:
   ```
   coap or radius
   ```
4. Next, in the host machine folder where you cloned this repository, open the command prompt and run the following scripts in order:
   ```bash
   python controller.py 
   python peer.py
   ```

## Acknowledgments
- University of Oviedo
- Open-source projects: FreeRADIUS, Hostap/WPA_Supplicant
- Christian Amsüss as the author of the aiocoap library
- Dan García-Carrillo and Rafael Marín-López as the authors of this Internet Draft

## License

This project is distributed under the **MIT** license. See the `LICENSE` file for more details.

## Contributions

Contributions are welcome! If you would like to collaborate, please follow these steps:

1. **Fork** the repository.
2. Create a **branch** for your new feature or bug fix: `git checkout -b feature-nueva-funcionalidad`.
3. Make your changes and **commit** them: `git commit -m "Descripción de los cambios"`.
4. **Push** the new branch: `git push origin feature-nueva-funcionalidad`.
5. Open a **Pull Request** on GitHub.

Before sending, please review the style requirements, dependencies, and perform testing.

## Authors and Contact
- Daniel Menéndez González
- Dan García Carrillo

If you have any questions or suggestions, you can contact the authors through:

- **GitHub**: [daniMGTeleco](https://github.com/daniMGTeleco)
- **Daniel Menéndez's email address**: [danielmenendezglez@gmail.com](mailto:danielmenendezglez@gmail.com)
- **Dan García's email address**: [garciadan@uniovi.es](mailto:garciadan@uniovi.es)
