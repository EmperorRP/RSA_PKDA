import socket
import threading
from rsa import generate_key_pair
import pickle
import json


class PKDA:
    def __init__(self):
        self.clients = {}
        self.public_key, self.private_key = generate_key_pair()

    def register_client(self, client_id, public_key):
        self.clients[client_id] = public_key

    def get_client_public_key(self, client_id):
        return self.clients[client_id]

def handle_client(conn, pkda):
    while True:
        # Receive and decode the client request
        data = conn.recv(4096)
        if not data:
            break
        print(f"Received data: {data}")
        request = json.loads(data.decode('latin-1')) # Use 'latin-1' instead of 'utf-8'

        # Check the request type and handle it accordingly
        if request["type"] == "register":
            client_id = request["client_id"]
            public_key = tuple(request["public_key"])
            pkda.register_client(client_id, public_key)
            pkda_public_key = pkda.public_key
            response = {"pkda_public_key": pkda_public_key}
            conn.sendall(json.dumps(response).encode())

        elif request["type"] == "request_public_key":
            source_client_id = request["source_client_id"]
            target_client_id = request["target_client_id"]
            target_public_key = pkda.get_client_public_key(target_client_id)
            response = {"target_public_key": target_public_key}
            conn.sendall(json.dumps(response).encode())

        elif request["type"] == "encrypted_message":
            pass  # Not implemented yet

        elif request["type"] == "receive_encrypted_message":
            pass  # Not implemented yet

    conn.close()




def start_server():
    pkda = PKDA()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12346))
    server.listen(5)

    print("PKDA server is listening for connections...")

    while True:
        conn, addr = server.accept()
        print(f"New connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(conn, pkda))
        client_handler.start()

if __name__ == "__main__":
    start_server()
