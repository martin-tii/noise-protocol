import socket

import dissononce
import logging
from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.sha256 import SHA256Hash
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from cryptography.hazmat.primitives import hashes
from termcolor import colored

dissononce.logger.setLevel(logging.ERROR)



class noise_xx:
    def send_cert(self, socket, handshake):
        expected_cert_fingerprint_hex = self.load_root().fingerprint(hashes.SHA256())
        message_buffer = handshake[1].encrypt_with_ad(b'', expected_cert_fingerprint_hex)
        socket.sendall(bytes(message_buffer))


    def validate_cert(self, socket, handshake):
        '''
        TODO: add x509 validation
        :param socket:
        :param handshake:
        :return: True if valid certificate
        '''
        # get root_certificate
        message_buffer = socket.recv(1024)
        remote_certificate = handshake[1].decrypt_with_ad(b'', message_buffer)
        expected_cert_fingerprint_hex = self.load_root().fingerprint(hashes.SHA256())
        if remote_certificate != expected_cert_fingerprint_hex:
            print(colored("Not Valid Client Certificate", 'red'))
            raise ValueError(
                f"Server certificate fingerprint {remote_certificate} does not match expected fingerprint {expected_cert_fingerprint_hex}")
        else:
            print(colored('> Valid Certificate', 'green'))
            return True


    def load_root(self, ):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        # Load the root certificate from file
        with open("root_cert.pem", "rb") as f:
            root_cert_data = f.read()

        # Parse the root certificate
        return x509.load_pem_x509_certificate(root_cert_data, default_backend())


    def noise_client(self, IP):  # Alice
        # set up logging and initialize Alice's keypair
        client_s = X25519DH().generate_keypair()

        # prepare handshakestate object for initiator
        client_handshakestate = HandshakeState(
            SymmetricState(
                CipherState(
                    AESGCMCipher()
                ),
                SHA256Hash()
            ),
            X25519DH()
        )

        # initialize handshakestate object
        client_handshakestate.initialize(XXHandshakePattern(), True, b'', s=client_s)

        # create a TCP socket and connect to Bob
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((IP, 12345))

            # -> e
            message_buffer = bytearray()
            client_handshakestate.write_message(b'', message_buffer)
            s.sendall(bytes(message_buffer))

            # <- e, ee, s, es
            message_buffer = s.recv(1024)
            client_handshakestate.read_message(bytes(message_buffer), bytearray())

            # -> s, se
            message_buffer = bytearray()
            client_cipherstates = client_handshakestate.write_message(b'', message_buffer)
            s.sendall(bytes(message_buffer))

            self.send_cert(s, client_cipherstates)

            self.validate_cert(s, client_cipherstates)

            # close the socket
            s.close()

        return client_cipherstates


    def noise_server(self, queue):  # Bob
        server_s = X25519DH().generate_keypair()
        server_handshakestate = HandshakeState(
            SymmetricState(
                CipherState(
                    AESGCMCipher()
                ),
                SHA256Hash()
            ),
            X25519DH()
        )
        # initialize handshakestate objects
        server_handshakestate.initialize(XXHandshakePattern(), False, b'', s=server_s)

        # create a socket object
        server_socket = socket.socket()

        # bind the socket to a public host, and a well-known port
        server_socket.bind(('localhost', 12345))

        # become a server socket
        server_socket.listen(1)

        # establish a connection
        print("Waiting for connection...")
        client_socket, addr = server_socket.accept()
        print("Connection established with:", addr)

        # -> e
        message_buffer = client_socket.recv(1024)
        server_handshakestate.read_message(bytes(message_buffer), bytearray())

        # <- e, ee, s, es
        message_buffer = bytearray()
        server_handshakestate.write_message(b'', message_buffer)
        client_socket.sendall(bytes(message_buffer))

        # -> s, se
        message_buffer = client_socket.recv(1024)
        server_cipherstates = server_handshakestate.read_message(bytes(message_buffer), bytearray())

        if self.validate_cert(client_socket, server_cipherstates):
            self.send_cert(client_socket, server_cipherstates)

        client_socket.close()
        queue.put(server_cipherstates)
        return server_cipherstates


