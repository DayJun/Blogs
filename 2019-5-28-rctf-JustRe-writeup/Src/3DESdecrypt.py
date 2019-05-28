from Crypto.Cipher import DES3
import base64

BS = DES3.block_size


def pad(s):
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)


def unpad(s):
    return s[0:-ord(s[-1])]


class prpcrypt():
    def __init__(self, key):
        self.key = key
        self.mode = DES3.MODE_ECB

    def encrypt(self, text):
        text = pad(text)
        cryptor = DES3.new(self.key, self.mode)
        x = len(text) % 8
        if x != 0:
            text = text + '\0' * (8 - x)
        # print(text)
        self.ciphertext = cryptor.encrypt(text)
        return (self.ciphertext).encode("hex")

    def decrypt(self, text):
        cryptor = DES3.new(self.key, self.mode)
        # de_text = base64.standard_b64decode(text)
        plain_text = cryptor.decrypt(text)
        st = str(plain_text.decode("utf-8")).rstrip('\0')
        print st.encode("hex")
        print st
        out = unpad(st)
        return out

# 507CA9E68709CEFA20D50DCF90BB976C  #9090F6B07BA6A4E8

cipher = "507CA9E68709CEFA20D50DCF90BB976C".decode("hex")

p = prpcrypt("AFSAFCEDYCXCXACNDFKDCQXC")

print p.decrypt(cipher)