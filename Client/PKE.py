import uuid
import subprocess

class PKE:
    def __init__(self):
        self.uuid = uuid.uuid4()
        self.public_key = "CLIENT PUBLIC KEY"
        self.private_key = "CLIENT PRIVATE KEY"
        args = ('../FourQ/FourQlib-master/FourQ_32bit/crypto_keypair_generation')
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        print(output)
        'generate public and private keys here.'
 
    def generateSecret(secretKeyB, publicKeyA):
        'We will use the c libraries here to generate secret from secretKey of itself, and public key of the end node.'

    def compareSecrets(secretA, secretB):
        'We will compare secretA and secretB, and return an authorisation value accordingly.'
        return secretA == secretB