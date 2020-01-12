import uuid

class PKE:
    def __init__(self):
        self.public_key = "SERVER PUBLIC KEY"
        self.private_key = "SERVER PRIVATE KEY"
        self.uuid = uuid.uuid4()
        'generate public and private keys here.'
 
    def generateSecret(secretKeyB, publicKeyA):
        'We will use the c libraries here to generate secret from secretKey of itself, and public key of the end node.'

    def compareSecrets(secretA, secretB):
        'We will compare secretA and secretB, and return an authorisation value accordingly.'
        return secretA == secretB