import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

# Simulate a breach database (server-side)
breach_db = [
    hashlib.sha256(b"password123").hexdigest(),
    hashlib.sha256(b"qwerty").hexdigest(),
    hashlib.sha256(b"admin").hexdigest()
]

# Simplified OPRF implementation using Diffie-Hellman-like blinding
class SimplifiedOPRF:
    def __init__(self):
        # Generate DH parameters
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        self.server_private_key = self.parameters.generate_private_key()
        self.server_public_key = self.server_private_key.public_key()

    def blind(self, password):
        # Client blinds the password hash
        password_hash = hashlib.sha256(password.encode()).digest()
        client_private_key = self.parameters.generate_private_key()
        client_public_key = client_private_key.public_key()
        # Simulate blinding by combining with client's public key
        return client_private_key, client_public_key, password_hash

    def evaluate(self, client_public_key):
        # Server evaluates OPRF using its private key
        shared_secret = self.server_private_key.exchange(client_public_key)
        # Derive a key using HKDF
        oprf_output = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'oprf',
            backend=default_backend()
        ).derive(shared_secret)
        return oprf_output

    def unblind(self, client_private_key, server_output, password_hash):
        # Client unblinds the result
        return server_output  # Simplified; in real OPRF, unblinding involves removing client blinding factor

# Simulated Private Set Intersection
def private_set_intersection(client_item, server_set):
    # In a real PSI, this would involve cryptographic comparison
    # Here, we simulate by checking if the OPRF output matches any server-hashed items
    return client_item.hex() in [hashlib.sha256(item.encode()).hexdigest() for item in server_set]

# Client-side password checkup
def client_check_password(password, oprf):
    # Step 1: Blind the password
    client_private_key, client_public_key, password_hash = oprf.blind(password)
    
    # Step 2: Send blinded input to server (simulated)
    server_response = server_evaluate(client_public_key, oprf)
    
    # Step 3: Unblind the response
    unblinded_output = oprf.unblind(client_private_key, server_response, password_hash)
    
    # Step 4: Perform PSI with breach database
    is_breached = private_set_intersection(unblinded_output, breach_db)
    return is_breached

# Server-side evaluation
def server_evaluate(client_public_key, oprf):
    # Server evaluates OPRF on blinded input
    return oprf.evaluate(client_public_key)

# Main function to test the protocol
def main():
    oprf = SimplifiedOPRF()
    test_passwords = ["password123", "unique_password"]
    
    for password in test_passwords:
        is_breached = client_check_password(password, oprf)
        print(f"Password '{password}' {'is' if is_breached else 'is not'} in breach database")

if __name__ == "__main__":
    main()