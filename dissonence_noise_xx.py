import socket
import unittest
import threading
import queue

import dissononce
import logging
from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.sha256 import SHA256Hash
from dissononce.processing.handshakepatterns.interactive.XX import XXHandshakePattern
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState

dissononce.logger.setLevel(logging.ERROR)


def noise_client(IP):  # Alice
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

        # close the socket
        s.close()

    return client_cipherstates


def noise_server(queue):  # Bob
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

    client_socket.close()
    queue.put(server_cipherstates)
    return server_cipherstates


class Testing(unittest.TestCase):
    q = queue.Queue()
    # Start server
    server_thread = threading.Thread(target=noise_server, args=(q,))
    server_thread.start()
    # Get session from queue
    client_session = noise_client('localhost')
    server_session = q.get()

    # transport phase
    # client to server
    ciphertext = client_session[0].encrypt_with_ad(b'', b'Hello')
    plaintext = server_session[0].decrypt_with_ad(b'', ciphertext)
    print("Plaintext decrypted on server: ", plaintext)
    assert plaintext == b'Hello'

    # bob to alice
    ciphertext = server_session[1].encrypt_with_ad(b'', b'World')
    plaintext = client_session[1].decrypt_with_ad(b'', ciphertext)
    print("Plaintext decrypted on client: ", plaintext)
    assert plaintext == b'World'


if __name__ == '__main__':
    unittest.main()
