import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.primitives.asymmetric as asymm

def Myencrypt(message, key):
    if(not isinstance(message, bytes)):
        m = bytes(message, "utf-8")
    else:
        m = message

    if(len(m) % 16 != 0 or len(m) < 16):
        padder = padding.PKCS7(128).padder()
        m = padder.update(m)
        m += padder.finalize()

    if(len(key) < 32):
        print("The key size is too small!!")
    else:
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

        encryptor = cipher.encryptor()
        ct = encryptor.update(m) + encryptor.finalize()

        return iv, ct

def Mydecrypt(C, iv, key):

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    m = decryptor.update(C) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        mData = unpadder.update(m)
        mData += unpadder.finalize()
        # return mData.decode("utf-8")
        return mData
    except:
        # return m.decode("utf-8")
        return m


def MyfileEncrypt(filePath):
    # IMAGE TEST NOW
    # getting the path of the image
    imgKey = os.urandom(32)
    path = filePath
    filePath, ext = os.path.splitext(path) # getting the extension for the img

    # converts the image to a string
    with open(path, "rb") as file:
        imgStr = base64.b64encode(file.read()) # string is in bytes

    # encrypting image string
    iv, c = Myencrypt(imgStr, imgKey)

    # converts an encrypted img string into an image
    # encImg = base64.b64decode(imgC)
    encFile = filePath + "enc" + ext
    with open(encFile, 'wb') as file:
        # file.write(encImg)
        file.write(c)
        file.close()

    return c, iv, imgKey, ext

def MyfileDecrypt(C, IV, key, fileName, ext):
    unEncFile = fileName + ext
    # decrypts the image string from the encrypted image
    dImgStr = Mydecrypt(C, IV, key)
    #converts decrypted image str into an image
    imageData = base64.b64decode(dImgStr)
    with open(unEncFile, 'wb') as file:
        file.write(imageData)
        file.close()



def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    #encrypt file to get the key
    C, IV, key, ext = MyfileEncrypt(filepath)
    
    #load the public key
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
                )
    #encrypt the key to get RSACipher
    RSACipher = public_key.encrypt(
            key, 
            asymm.padding.OAEP(
                    mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None 
                    )
            )
    
    return RSACipher, C, IV, ext
    
    
def MyRSADecrypt(RSACipher, C, IV, filepath, ext, RSA_Privatekey_filepath):
    #load private key
    with open(RSA_Privatekey_filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())
        
    #decrypt the RSACipher to get the key
    key = private_key.decrypt(
        RSACipher,
        asymm.padding.OAEP(
                mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
        )
    )
    #decrypt using original key
    MyfileDecrypt(C, IV, key, filepath, ext)
        

def generateKeys():
    # key info
    key = rsa.generate_private_key(backend=default_backend(), 
                                   public_exponent=65537,
                                      key_size=2048)
    # private key
    private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
    #write private key to file
    with open("keys/private_key.pem", 'wb') as file:
        file.write(private_pem)
        file.close()
    
    #create a public key
    public = key.public_key()
    public_pem = public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    #write pub key to file
    with open("keys/public_key.pem", 'wb') as file:
        file.write(public_pem)
        file.close()
        
    print(private_pem)
    print(public_pem)
    #print(public_pem.decode('utf-8'))
    


import time

#generateKeys()
# testing RSA
RSACipher, C, IV, ext = MyRSAEncrypt("img/bird.jpg", "keys/public_key.pem")
time.sleep(5)
MyRSADecrypt(RSACipher, C, IV, "img/birdenc", ext, "keys/private_key.pem")
#Test case for jpg file
"""
fileName = "img/bird.jpg"
C, IV, akey, ext = MyfileEncrypt(fileName)
time.sleep(3)
fileName2 = "img/birdenc"
MyfileDecrypt(C, IV, akey, fileName2, ext)
"""

#test case for text
"""
key = os.urandom(32)
sMessage = "This is a test run for the encryption method, it will decrypt shortly after"
iv, ct = Myencrypt(sMessage, key)
print("The IV is: >>>", iv)
print("The Cipher-text is: >>>", ct)
time.sleep(3)
message = Mydecrypt(ct, iv, key)
m = message.decode("utf-8")
print(m)
"""
