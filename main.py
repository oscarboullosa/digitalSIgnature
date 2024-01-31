from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

class BlockchainSecurity:
    def __init__(self):
        # Generar un par de claves (pública y privada)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = private_key.public_key()
        self.private_key = private_key

    def sign_message(self, message):
        # Firmar un mensaje con la clave privada
        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, message, signature, public_key):
        # Verificar la firma utilizando la clave pública
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Error al verificar la firma: {e}")
            return False

# Ejemplo de uso
if __name__ == "__main__":
    blockchain_security = BlockchainSecurity()

    # Mensaje a firmar y verificar
    message_to_sign = "Hola, este es un mensaje para la blockchain"

    # Firmar el mensaje
    signature = blockchain_security.sign_message(message_to_sign)
    print(f"Firma generada: {signature}")

    # Verificar la firma utilizando la clave pública
    is_verified = blockchain_security.verify_signature(
        message_to_sign, signature, blockchain_security.public_key
    )

    if is_verified:
        print("La firma es válida.")
    else:
        print("La firma no es válida.")
