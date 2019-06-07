from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode
from base64 import b64decode


def rsa_verify(message):
    public_key_file = open('./myPublicKey.pem', 'r')
    public_key = RSA.importKey(public_key_file)
    sign_file = open('./signThing.txt', 'r')
    sign = b64decode(sign_file.read())
    h = SHA.new(message)
    verifier = PKCS1_v1_5.new(public_key)
    return verifier.verify(h, sign)


def rsa_sign(message):
    private_key_file = open('./myPrivateKey.pem', 'r')
    private_key = RSA.importKey(private_key_file)
    hash_obj = SHA.new(message)
    signer = PKCS1_v1_5.new(private_key)
    d = b64encode(signer.sign(hash_obj))
    file = open('./signThing.txt', 'wb')
    file.write(d)
    file.close()


def decrypt():
    externKey = "./myPrivateKey.pem"
    publickey = open(externKey, "r")
    decryptor = RSA.importKey(publickey, passphrase="f00bar")
    retval = None
    file = open("./cryptThingy.txt", "rb")
    retval = decryptor.decrypt(file.read())
    file.close()
    return retval


def encrypt(message):
    externKey = "./myPublicKey.pem"
    privatekey = open(externKey, "r")
    encryptor = RSA.importKey(privatekey, passphrase="f00bar")
    encriptedData = encryptor.encrypt(message, 0)
    file = open("./cryptThingy.txt", "wb")
    file.write(encriptedData[0])
    file.close()
