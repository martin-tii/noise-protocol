import socket
from noise.connection import NoiseConnection, Keypair
from itertools import cycle
from noise.backends.default import diffie_hellmans as DH
import unittest
import threading
import queue


class Noise_XX:
    @staticmethod
    def generate_keys():
        keyp = DH.ED25519().generate_keypair()
        public_key = keyp.public_bytes
        private_key = keyp.private.private_bytes_raw()
        return public_key, private_key

    def server(self, queue):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('localhost', 3000))
        s.listen(1)
        print("Starting Server")

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


        conn.close()
        queue.put(noise)

    def client(self, IP):
        s = socket.socket()
        s.connect((IP, 3000))

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

        s.close()
        return noise


class Testing(unittest.TestCase):
    def test_noise_xx(self):
        noi = Noise_XX()

        q = queue.Queue()
        # Start server
        server_thread = threading.Thread(target=noi.server, args=(q,))
        server_thread.start()
        # Get session from queue
        client_session = noi.client('localhost')
        server_session = q.get()

        # Test message exchange using session key
        message = b'This is a test message'
        encrypted_message = client_session.encrypt(message)
        decrypted_message = server_session.decrypt(encrypted_message)
        self.assertEqual(message, decrypted_message)


if __name__ == '__main__':
    unittest.main()
