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
import os
from hashlib import blake2b
from cryptography import x509
from cryptography.hazmat.backends import default_backend

dissononce.logger.setLevel(logging.ERROR)

'''
Protocol:
handshake of noise xx (3 messages)
nonce from server to client 
answer from client to server --> hash of the fingerprint root certificate + nonce
repeat from client to server
'''


def load_root(root_cert="root_cert.pem"):
    # Load the root certificate from file
    with open(root_cert, "rb") as f:
        root_cert_data = f.read()
    # Parse the root certificate
    return x509.load_pem_x509_certificate(root_cert_data, default_backend())


class noise_xx:

    def __init__(self, debug=False):
        self.debug = debug

    def send_cert(self, socket, handshake, received_nonce, cert):
        expected_cert_fingerprint_hex = cert.fingerprint(hashes.SHA256())
        gfg = blake2b()
        gfg.update(expected_cert_fingerprint_hex)
        gfg.update(received_nonce)
        message_buffer = handshake[1].encrypt_with_ad(b'', gfg.digest())
        if self.debug:
            print("Sent digest: ", gfg.digest())
        socket.sendall(bytes(message_buffer))

    def send_nonce(self, sock, handshake):
        nonce = os.urandom(100)
        message_buffer = handshake[1].encrypt_with_ad(b'', nonce)
        sock.sendall(message_buffer)
        if self.debug:
            print("Sent Nonce: ", nonce)
        return nonce

    def receive_nonce(self, sock, handshake):
        received = sock.recv(1024)
        received_nonce = handshake[1].decrypt_with_ad(b'', received)
        if self.debug:
            print("Received Nonce: ", received_nonce)
        return received_nonce

    def validate_cert(self, socket, handshake, my_nonce):
        '''
        TODO: add x509 validation
        :param socket:
        :param handshake:
        :return: True if valid certificate
        '''
        # get root_certificate
        message_buffer = socket.recv(1024)
        answer = handshake[1].decrypt_with_ad(b'', message_buffer)
        expected_cert_fingerprint_hex = load_root().fingerprint(hashes.SHA256())
        gfg = blake2b()
        gfg.update(expected_cert_fingerprint_hex)
        gfg.update(my_nonce)
        if answer != gfg.digest():
            print(colored("Not Valid Client Certificate", 'red'))
            raise ValueError(
                f"Response: {answer} does not match expected response: {gfg.digest()}")
        else:
            print(colored('> Valid Response', 'green'))
            if self.debug:
                print(f"Challenge: {gfg.digest()},  Response: {answer}")
            return True

    def noise_client(self, IP, certificate):  # Alice
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

            received_nonce = self.receive_nonce(s, client_cipherstates)

            cert = load_root(certificate)
            self.send_cert(s, client_cipherstates, received_nonce, cert)

            mynonce = self.send_nonce(s, client_cipherstates)

            if self.validate_cert(s, client_cipherstates, mynonce):
                s.close()
                return client_cipherstates
            else:
                s.close()
                return "not valid"
            # close the socket

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

        mynonce = self.send_nonce(client_socket, server_cipherstates)

        if self.validate_cert(client_socket, server_cipherstates, mynonce):
            received_nonce = self.receive_nonce(client_socket, server_cipherstates)
            self.send_cert(client_socket, server_cipherstates, received_nonce, load_root())
            queue.put(server_cipherstates)
            client_socket.close()
            return server_cipherstates
        else:
            client_socket.close()
            return "not valid"
