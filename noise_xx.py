import socket
from noise.connection import NoiseConnection, Keypair
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

    def client(self, IP):
        s = socket.socket()
        s.connect((IP, 2000))

        # Initialize Noise connection
        noise = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_SHA256')

        # Generate keypair static
        _, our_private = self.generate_keys()
        noise.set_keypair_from_private_bytes(Keypair.STATIC, our_private)
        noise.set_as_initiator()

        # -> e
        # Perform the handshake
        noise.start_handshake()
        ciphertext = noise.write_message()
        s.sendall(ciphertext)

        # <- e, ee, s, es
        rec = s.recv(2048)

        noise.read_message(rec)


        # -> s, se
        ciphertext = noise.write_message()
        s.sendall(ciphertext)

        s.close()

        return noise

    def server(self, queue):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('localhost', 2000))
        s.listen(1)
        print("Starting Server")

        conn, addr = s.accept()
        print('Accepted connection from', addr)

        # Initialize Noise connection
        noise = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_SHA256')
        noise.set_as_responder()

        # Generate keypair static
        _, our_private = self.generate_keys()
        noise.set_keypair_from_private_bytes(Keypair.STATIC, our_private)
        noise.start_handshake()

        # -> e
        data = conn.recv(2048)
        noise.read_message(data)


        # <- e, ee, s, es
        print("sent responder's public key")
        ciphertext = noise.write_message()
        conn.sendall(ciphertext)
        noise.read_message(conn.recv(2048))

        # Add the Noise connection to the queue
        queue.put(noise)

        conn.close()

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
        message = b'This is a test message 1'
        encrypted_message = client_session.encrypt(message)
        decrypted_message = server_session.decrypt(encrypted_message)
        print("Message: ", message)
        print("Message decrypted on server side: ", decrypted_message)
        self.assertEqual(message, decrypted_message)

        # Test message exchange using session key
        message = b'This is a test message 2 '
        encrypted_message = server_session.encrypt(message)
        decrypted_message = client_session.decrypt(encrypted_message)
        print("Message: ", message)
        print("Message decrypted on server side: ", decrypted_message)
        self.assertEqual(message, decrypted_message)


if __name__ == '__main__':
    unittest.main()
