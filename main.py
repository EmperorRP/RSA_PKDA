import time
import random
from rsa import generate_key_pair, encrypt, decrypt


class PKDA:
    def __init__(self):
        self.clients = {}
        self.public_key, self.private_key = generate_key_pair()

    def register_client(self, client_id, public_key):
        self.clients[client_id] = public_key

    def get_client_public_key(self, client_id):
        return self.clients[client_id]

class Client:
    def __init__(self, pkda, client_id):
        self.pkda = pkda
        self.client_id = client_id
        self.public_key, self.private_key = generate_key_pair()
        self.pkda.register_client(client_id, self.public_key)

    def request_public_key(self, target_client_id):
        # 1. Initiator A: sends request || T1 to the public key authority
        T1 = time.time()
        request = (self.client_id, target_client_id, T1)

        # 2. Public Key Authority: Receives request and reverts with E(PRauth, (PUb || Request || T1))
        public_key_authority_response = self.pkda.get_client_public_key(target_client_id)
        PRauth, n = self.pkda.private_key
        encrypted_response = pow(public_key_authority_response[0], PRauth, n)

        # 3. Initiator A to Responder B: E(PUb, [IDa || N1])
        N1 = random.randint(1, 100)
        message_to_responder = f"{self.client_id}||{N1}"
        encrypted_message_to_responder = encrypt(message_to_responder, public_key_authority_response)

        # 4. Responder B sends request || T2 to the public key authority
        T2 = time.time()
        request_from_responder = (target_client_id, self.client_id, T2)

        # 5. Public Key Authority: Receives request and reverts with E(PRauth, (PUa || Request || T2))
        public_key_authority_response_responder = self.pkda.get_client_public_key(self.client_id)
        encrypted_response_responder = pow(public_key_authority_response_responder[0], PRauth, n)

        # 6. Responder B to Initiator A: E(PUa, [N1 || N2])
        N2 = random.randint(1, 100)
        message_to_initiator = f"{N1}||{N2}"
        encrypted_message_to_initiator = encrypt(message_to_initiator, public_key_authority_response_responder)

        # 7. Initiator A sends E(PUb, N2) to Responder B
        encrypted_N2 = encrypt(str(N2), public_key_authority_response)

        return encrypted_message_to_responder, encrypted_message_to_initiator, encrypted_N2


    def send_encrypted_message(self, target_client_id, message):
        # Request the target client's public key securely
        encrypted_message_to_responder, encrypted_message_to_initiator, encrypted_N2 = self.request_public_key(target_client_id)

        # Use the target client's public key to encrypt the message
        target_client_public_key = self.pkda.get_client_public_key(target_client_id)
        encrypted_message = encrypt(message, target_client_public_key)

        # Send the encrypted message to the target client
        return encrypted_message


    def receive_encrypted_message(self, encrypted_message):
        # Decrypt the received encrypted message using the client's private key
        decrypted_message = decrypt(encrypted_message, self.private_key)
        return decrypted_message


def main():
    pkda = PKDA()
    client_a = Client(pkda, 'client_a')
    client_b = Client(pkda, 'client_b')

    client_a.request_public_key('client_b')
    client_b.request_public_key('client_a')

    messages_to_send = ['Hi1', 'Hi2', 'Hi3']
    for msg in messages_to_send:
        encrypted_message = client_a.send_encrypted_message('client_b', msg)
        decrypted_message = client_b.receive_encrypted_message(encrypted_message)
        print(f"Client B received: {decrypted_message}")
        response = f"Got-it{messages_to_send.index(msg) + 1}"
        encrypted_response = client_b.send_encrypted_message('client_a', response)
        decrypted_response = client_a.receive_encrypted_message(encrypted_response)
        print(f"Client A received: {decrypted_response}")

if __name__ == "__main__":
    main()
