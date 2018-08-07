import sys
import base64
import urllib
from Crypto.Cipher import AES

def pad(m):
    p = 16 - len(m) % 16
    return m + chr(p) * p

def unpad(m):
    return m[:-ord(m[-1])]

def decrypt(c, key, iv, isURL=False):
    if isURL == '1':
        c = urllib.unquote(c)
    c = base64.b64decode(c)
    s = AES.new(key, AES.MODE_CBC, IV=iv).decrypt(c)
    return unpad(s).strip()

def encrypt(m, key, iv, isURL=False):
    s = AES.new(key, AES.MODE_CBC, IV=iv).encrypt(pad(m.strip()))
    c = base64.b64encode(s)
    if isURL == '1':
        c = urllib.quote_plus(c)
    return c

if __name__ == '__main__':
    mode, text, key, iv, isURL = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
    if sys.argv[1] == '-d':
        sys.stdout.write(decrypt(text, key, iv, isURL))
    elif sys.argv[1] == '-e':
        sys.stdout.write(encrypt(text, key, iv, isURL))
