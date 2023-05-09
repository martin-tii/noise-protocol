import unittest
import threading
import queue
from dissonence_noise_xx import noise_xx


class Testing(unittest.TestCase):
    def setUp(self) -> None:
        self.noi = noise_xx(True)

    def test_encrypt_decrypt(self):
        q = queue.Queue()
        # Start server
        server_thread = threading.Thread(target=self.noi.noise_server, args=(q,))
        server_thread.start()
        # Get session from queue
        client_session = self.noi.noise_client('localhost', "root_cert.pem")
        server_session = q.get()

        # transport phase
        # client to server
        ciphertext = client_session[0].encrypt_with_ad(b'', b'Hello')
        plaintext = server_session[0].decrypt_with_ad(b'', ciphertext)
        print("Plaintext decrypted on server: ", plaintext)
        # assert plaintext == b'Hello'
        self.assertEqual(plaintext, b'Hello')

        # bob to alice
        ciphertext = server_session[1].encrypt_with_ad(b'', b'World')
        plaintext = client_session[1].decrypt_with_ad(b'', ciphertext)
        print("Plaintext decrypted on client: ", plaintext)
        # assert plaintext == b'World'
        self.assertEqual(plaintext, b'World')

    def test_fail_to_authenticate(self):
        pass
        #TODO
        # q = queue.Queue()
        # # Start server
        # server_thread = threading.Thread(target=self.noi.noise_server, args=(q,))
        # server_thread.start()
        # # Get session from queue
        # client_session = self.noi.noise_client('localhost', "fake_cert.pem")
        # server_session = q.get()
        # self.assertEqual(client_session, "not valid")
        # self.assertEqual(server_session, "not valid")


if __name__ == '__main__':
    unittest.main()
