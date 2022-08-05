from base64 import b64decode
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

import os
import pathlib

APP_NAME="linuxpythonCryptography"

class Encrypt(object):

    ## Monitor secrets in the vol /run/secrets and trigger encryption when new secret is found
    def watch_secrets():

        #secret vol dir
        dir_path = '/run/secrets'

        # list to store files
        res = []
        while True:
            # Iterate directory
            for secret in os.listdir(dir_path):
                # check if current path is a file
                if os.scret.isfile(os.secret.join(dir_path, secret)):
                    if secret.stat().st_mtime - currenttime < 5
                        # secret has been created/modified. encrypt it.

                    res.append(secret)
            wait 5 mins.


    ##Encrypt base64 encoded secret data with user provided RSA private key
    def encrypt_data():

        clean_private_key = read_encryption_key()
        encrypted_data = read_encrypted_data()

        #import cleaned private  key and passing passphrase used to create key  
        private_key = RSA.importKey(clean_private_key,passphrase=APP_NAME)

        #using PKCS1_OAEP since the private key used the PKCS1_OAEP padding 
        rsa_cipher = PKCS1_OAEP.new(private_key)

        #decrypt data and decode
        decrypted_data = rsa_cipher.decrypt(encrypted_data).decode()

        print(decrypted_data)

    #read private key, clean it and return usable key
    def read_encryption_key():
        #private key
        private_key_file = "keys/privatekey.pem"

        with open(private_key_file,'r') as key:
        #skip first and last line (-----BEGIN RSA PRIVATE KEY----- -----END RSA PRIVATE KEY-----)
            private_key_lines = key.readlines()[1:-1]

        clean_private_key =""
        #clean the private key into format readable by RSA importkey
        for line in private_key_lines:
                clean_private_key ="".join([clean_private_key,line.rstrip()])

        #b64decode the cleaned private key and return
        return b64decode(clean_private_key)

    #Read encrypted data from file
    def read_encrypted_data():
        encrypted_data_file = "encrypteddata"
    
        #read file and b64 decode for decryption
        with open(encrypted_data_file,'r') as encrypted_file:
            encrypted_data = b64decode(encrypted_file.read())

        return encrypted_data
