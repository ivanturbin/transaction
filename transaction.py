import json
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


class Transaction:
    def __init__(self, tx_inputs, tx_outputs):
        self.inputs = tx_inputs       # [{'tx_id': str, 'output_index': int}]
        self.outputs = tx_outputs     # [{'address': str, 'amount': float}]
        self.signature = None         # Подпись после подписи

    def to_dict(self, include_signature=False):
        data = {
            'inputs': self.inputs,
            'outputs': self.outputs,
        }
        if include_signature and self.signature:
            data['signature'] = self.signature.hex()
        return data

    def to_json(self, include_signature=False):
        return json.dumps(self.to_dict(include_signature), sort_keys=True)

    def hash(self):
        tx_json = self.to_json()
        return hashlib.sha256(tx_json.encode()).hexdigest()

    def sign(self, private_key):
        tx_json = self.to_json()
        self.signature = private_key.sign(
            tx_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, public_key):
        tx_json = self.to_json()
        try:
            public_key.verify(
                self.signature,
                tx_json.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key
