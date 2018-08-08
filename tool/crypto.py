import sys
import base64
from Crypto.Cipher import AES

try:
    from urllib import unquote, quote_plus
except:
    from urllib.parse import unquote, quote_plus

def pad(m):
    p = 16 - len(m) % 16
    return m + chr(p) * p

def unpad(m):
    p = m[-1] if type(m[-1]) is int else ord(m[-1])
    return m[:-p]

def decrypt(c, key, iv, isURL=False):
    if isURL == '1':
        c = unquote(c)
    c = base64.b64decode(c)
    s = AES.new(key, AES.MODE_CBC, IV=iv).decrypt(c)
    return unpad(s).strip()

def encrypt(m, key, iv, isURL=False):
    s = AES.new(key, AES.MODE_CBC, IV=iv).encrypt(pad(m.strip()))
    c = base64.b64encode(s)
    if isURL == '1':
        c = quote_plus(c)
    return c

def output(data):
    if type(data) is str:
        sys.stdout.write(data)
    else:
        sys.stdout.buffer.write(data)

if __name__ == '__main__':
    mode, text, key, iv, isURL = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
    if sys.argv[1] == '-d':
        output(decrypt(text, key, iv, isURL))
    elif sys.argv[1] == '-e':
        output(encrypt(text, key, iv, isURL))
