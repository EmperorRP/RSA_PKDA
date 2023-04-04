import socket
import rsa
import json
import uuid
import pickle
import threading
import time

class Client:
    def __init__(self, pkda_server_host="localhost", pkda_server_port=12346):
        self.client_id = str(uuid.uuid4())
        self.public_key, self.private_key = rsa.generate_key_pair()
        self.pkda_server_host = pkda_server_host
        self.pkda_server_port = pkda_server_port
        self.pkda_public_key = None
        self.clients = {}

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
            decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')
            return decrypted_message

    def connect_to_client(self, target_ip, target_port, target_public_key, target_client_id):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((target_ip, target_port))
            message = f"{self.client_id} wants to initiate a secure connection with you"
            encrypted_message = rsa.encrypt(message.encode('utf-8'), target_public_key)
            message_data = {
                "type": "encrypted_message",
                "source_client_id": self.client_id,
                "target_client_id": target_client_id,
                "message": encrypted_message
            }
            sock.sendall(json.dumps(message_data).encode("utf-8"))



    def run(self):
        while True:
            command = input("Enter a command (send/receive/connect): ")
            if command == "send":
                target_client_id = input("Enter the target client ID: ")
                message = input("Enter the message to send: ")
                self.send_encrypted_message(target_client_id, message)
            elif command == "receive":
                source_client_id = input("Enter the source client ID: ")
                message = self.receive_encrypted_message(source_client_id)
                print(f"Received message: {message}")
            elif command == "connect":
                target_ip = input("Enter the target client IP address: ")
                target_port = int(input("Enter the target client port number: "))
                self.target_client_id = input("Enter the target client ID: ")
                self.target_public_key = self.request_public_key(self.target_client_id)
                self.connect_to_client(target_ip, target_port)
            elif command == "listen":
                self.start_listening()
            else:
                print("Invalid command.")

    def start_listening(self, host="localhost", port=None):
        if port is None:
            port = input("Enter a listening port number: ")
            port = int(port)

        self.host = host
        self.port = port

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Client {self.client_id} is listening for connections on {self.host}:{self.port}")

        while True:
            conn, addr = self.server.accept()
            print(f"New connection from {addr}")
            client_handler = threading.Thread(target=self.handle_incoming_message, args=(conn,))
            client_handler.start()

    def handle_incoming_message(self, conn):
        data = conn.recv(4096)
        if not data:
            return

        message_data = json.loads(data.decode('utf-8'))
        if message_data["type"] == "encrypted_message":
            source_client_id = message_data["source_client_id"]
            encrypted_message = message_data["message"]
            decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')

            print(f"Received encrypted message from {source_client_id}: {decrypted_message}")
        else:
            print("Unknown message type received.")
        conn.close()

    




def run_client1(client1):
    print("Initiating Client 1...")
    client1.register_with_pkda()
    print("Registering Client 1 PKDA keys...")
    print(f"Client ID: {client1.client_id}")
    print(f"Client public key: {client1.public_key}")

    client1.start_listening(port=5000)

def run_client2(client2):
    print("\nInitiating Client 2...")
    client2.register_with_pkda()
    print("Registering Client 2 PKDA keys...")
    print(f"Client ID: {client2.client_id}")
    print(f"Client public key: {client2.public_key}")

    # Give some time for client1 to start listening
    time.sleep(2)

    target_ip = "localhost"
    target_port = 5000
    target_client_id = client1.client_id
    target_public_key = client1.public_key

    client2.connect_to_client(target_ip, target_port, target_public_key, target_client_id)
    client2.send_encrypted_message(target_client_id, "Hello from Client 2!")

if __name__ == "__main__":
    client1 = Client()
    client2 = Client()

    client1_thread = threading.Thread(target=run_client1, args=(client1,))
    client2_thread = threading.Thread(target=run_client2, args=(client2,))

    client1_thread.start()
    client2_thread.start()

    client1_thread.join()
    client2_thread.join()
