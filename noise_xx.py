import socket
from noise.connection import NoiseConnection, Keypair
from itertools import cycle
from noise.backends.default import diffie_hellmans as DH
import unittest
import threading


class Noise_XX:
    def generate_keys(self):
        keyp = DH.ED25519().generate_keypair()
        public_key = keyp.public_bytes
        private_key = keyp.private.private_bytes_raw()
        return public_key, private_key

    def server(self, test=False):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if test:
            s.bind(('localhost', 3000))
        else:
            s.bind(('192.168.10.169', 3000))
        s.listen(1)

        conn, addr = s.accept()
        print('Accepted connection from', addr)

        # Initialize Noise connection
        noise = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_SHA256')
        noise.set_as_responder()

        # Generate keypair
        our_public, our_private = self.generate_keys()

        # Receive client's public key
        their_public_key = conn.recv(32)
        noise.set_keypair_from_private_bytes(Keypair.STATIC, our_private)
        noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, their_public_key)

        # Send server's public key
        conn.sendall(our_public)

        # Perform the handshake
        noise.start_handshake()
        # Perform handshake. Break when finished
        for action in cycle(['receive', 'send']):
            if noise.handshake_finished:
                break
            elif action == 'send':
                ciphertext = noise.write_message()
                conn.sendall(ciphertext)
            elif action == 'receive':
                data = conn.recv(2048)
                plaintext = noise.read_message(data)

        # Get the session key and send a message to the client
        session_key = noise.get_handshake_hash()
        print(session_key)
        encrypted_message = noise.encrypt(b'This is a test message using session key')
        ciphertext = noise.write_message(encrypted_message)
        conn.sendall(ciphertext)

        conn.close()
        return session_key

    def client(self, test=False):
        s = socket.socket()
        if test:
            s.connect(('localhost', 3000))
        else:
            s.connect(('192.168.10.169', 3000))

        # Initialize Noise connection
        noise = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_SHA256')
        noise.set_as_initiator()

        # Generate keypair
        our_public, our_private = self.generate_keys()

        # Send client's public key
        s.sendall(our_public)

        # Receive server's public key
        their_public_key = s.recv(32)
        noise.set_keypair_from_private_bytes(Keypair.STATIC, our_private)
        noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, their_public_key)

        # Perform the handshake
        noise.start_handshake()
        # Perform handshake. Break when finished
        for action in cycle(['send', 'receive']):
            if noise.handshake_finished:
                break
            elif action == 'send':
                ciphertext = noise.write_message()
                s.sendall(ciphertext)
            elif action == 'receive':
                data = s.recv(2048)
                plaintext = noise.read_message(data)

        # Get the session key and decrypt the message received from the server
        session_key = noise.get_handshake_hash()
        print(session_key)
        encrypted_message = s.recv(2048)
        plaintext = noise.decrypt(noise.read_message(encrypted_message))
        print(plaintext)

        s.close()
        return session_key

    def test_noise_xx(self):
        noise = Noise_XX()

        # Start server and get session key
        server_thread = threading.Thread(target=noise.server, args=True)
        server_thread.start()
        session_key = noise.client(True)

        # Check that session key is generated correctly
        self.assertEqual(len(session_key), 32)

        # Test message exchange using session key
        message = b'This is a test message'
        encrypted_message = noise.encrypt_with_session_key(message, session_key)
        decrypted_message = noise.decrypt_with_session_key(encrypted_message, session_key)

        self.assertEqual(message, decrypted_message)


if __name__ == '__main__':
    unittest.main()
