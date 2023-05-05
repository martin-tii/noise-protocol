import unittest
import threading
import queue
from dissonence_noise_xx import noise_xx


class Testing(unittest.TestCase):
    noi = noise_xx()
    q = queue.Queue()
    # Start server
    server_thread = threading.Thread(target=noi.noise_server, args=(q,))
    server_thread.start()
    # Get session from queue
    client_session = noi.noise_client('localhost')
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
