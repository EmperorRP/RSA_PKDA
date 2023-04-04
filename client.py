import socket
import rsa
import json
import uuid
import pickle

class Client:

    def __init__(self, pkda_server_host="localhost", pkda_server_port=12346):
        self.client_id = str(uuid.uuid4()) # Generate a unique client ID
        self.public_key, self.private_key = rsa.generate_key_pair()
        self.pkda_server_host = pkda_server_host
        self.pkda_server_port = pkda_server_port
        self.pkda_public_key = None  # Add this line

    def register_with_pkda(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.pkda_server_host, self.pkda_server_port))
            registration_request = {
                "type": "register",
                "client_id": self.client_id,
                "public_key": list(self.public_key)
            }
            sock.sendall(json.dumps(registration_request).encode("utf-8"))
            response = sock.recv(4096)
            self.pkda_public_key = json.loads(response.decode())["pkda_public_key"]

    def request_public_key(self, target_client_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.pkda_server_host, self.pkda_server_port))
            public_key_request = {
                "type": "request_public_key",
                "source_client_id": self.client_id,
                "target_client_id": target_client_id
            }
            sock.sendall(json.dumps(public_key_request).encode("utf-8"))
            response = json.loads(sock.recv(1024).decode("utf-8"))
            target_public_key = tuple(response["target_public_key"])
            return target_public_key

    def send_encrypted_message(self, target_client_id, message):
        target_public_key = self.request_public_key(target_client_id)
        encrypted_message = rsa.encrypt(message.encode('utf-8'), target_public_key)
        message_data = {
            "type": "encrypted_message",
            "source_client_id": self.client_id,
            "target_client_id": target_client_id,
            "message": encrypted_message
        }
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.pkda_server_host, self.pkda_server_port))
            sock.sendall(json.dumps(message_data).encode("utf-8"))


    def receive_encrypted_message(self, source_client_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.pkda_server_host, self.pkda_server_port))
            message_request = {
                "type": "receive_encrypted_message",
                "source_client_id": source_client_id,
                "target_client_id": self.client_id
            }
            sock.sendall(json.dumps(message_request).encode("utf-8"))
            response = json.loads(sock.recv(1024).decode("utf-8"))
            encrypted_message = response["message"]
            decrypted_message = rsa.decrypt(encrypted_message, self.private_key)
            return decrypted_message


# Example usage:
if __name__ == "__main__":
    client1 = Client()
    print("Initiating Client 1...")
    client1.register_with_pkda()
    print("Registering Client 1 PKDA keys...")

    print(f"Client 1 ID: {client1.client_id}")
    print(f"Client 1 public key: {client1.public_key}")
    print(f"PKDA public key: {client1.pkda_public_key}")
