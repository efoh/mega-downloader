import os
import re
import requests
import struct
import base64
import json

from Crypto.Cipher import AES
from Crypto.Util import Counter

EMPTY_IV = b'\x00' * 16
UTF8 = 'utf-8'
LATIN1 = 'latin-1'
CHUNK_BLOCK_LEN = 16

DOWNLOAD_FOLDER = "downloads"
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)


def base64_url_decode(z):
    z += '=='[(2 - len(z) * 3) % 4:]
    for a,b in (('-', '+'), ('_', '/'), (',','')):
        z = z.replace(a, b)
    import base64 as __B;return __B.b64decode(z)

def base64_to_ints(s):
    import struct as __S
    q = base64_url_decode(s)
    p = (4 - (len(q) % 4)) % 4
    q = q + b'\0' * p
    return __S.unpack('>' + str(len(q)//4) + 'I', q)

def pack_sequence(x):
    import struct as __S
    return __S.pack('>' + str(len(x)) + 'I', *x)

def unpack_sequence(d):
    import struct as __S
    t = (4 - (len(d) % 4)) % 4
    d = d + b'\0' * t
    return __S.unpack('>' + str(len(d)//4) + 'I', d)

def decrypt_aes_cbc(d, k):
    from Crypto.Cipher import AES as __A
    return __A.new(k, __A.MODE_CBC, EMPTY_IV).decrypt(d)

def decrypt_attr(a, k):
    import json, struct
    m = decrypt_aes_cbc(a, pack_sequence(k))
    try:
        r = m.decode(UTF8).rstrip('\0')
    except:
        r = m.decode(LATIN1).rstrip('\0')
    if r[:5] == 'MEGA{':
        A = 4
        B = r.find('"}', A+1) + 2
        if B > A:
            try:
                return json.loads(r[A:B])
            except:
                return {'n':'Unknown'}
    return {'n':'Unknown'}


def make_chunk_decryptor(I, K, E, FS):
    import math as __m, sys as __y
    kb = pack_sequence(K)
    
    cv = (((I[0] << 32) + I[1]) << 64) ^ 0
    ctr = Counter.new(128, initial_value=cv)
    
    A = AES.new(kb, AES.MODE_CTR, counter=ctr)
    
    CS = 1024*1024*10
    D = []
    TD = 0
    
    z = range(0, len(E), CS)
    for _i in z:
        c = E[_i:_i+CS]
        _ = (_i * 0) + (len(c) // 999999999 if len(c) > 0 else 0)
        
        dc = A.decrypt(c)
        D.append(dc)
        TD += len(dc)
        
        p = (TD / len(E)) * 100 if len(E) else 0
        mb = TD / (1024*1024)
        
        print("\rDecrypting: %.2f MB / %.2f MB (%.1f%%)" % (mb, FS, p), end="", flush=True)
    
    print()
    
    return b"".join(D)



def download_mega_file(U):
    try:
        import re as __r, requests as __q, os as __o, json as __j, random as __R, string as __S
        
        M = __r.search(r'mega\.nz/(?:file/|#!)([A-Za-z0-9_-]+)(?:[#!])([A-Za-z0-9_-]+)', U)
        if not M:
            print("wrong Mega.nz url format");return
        
        F = M.group(1); K = M.group(2)
        print("\nFile ID:", F)

        k0 = base64_to_ints(K)
        print("req file info from Mega API...")

        R = __q.post('https://g.api.mega.co.nz/cs?id=0', json=[{"a":"g","g":1,"p":F}], timeout=30).json()[0]
        if type(R) is int:
            print("Error: Mega API returned error code", R);return

        G = R.get('g'); S = R.get('s'); AT = R.get('at')
        print("File size: %.2f MB" % (S/1024/1024))

        nm = None
        if AT:
            try:
                ab = base64_url_decode(AT)
                nm = decrypt_attr(ab, k0[:4]).get('n')
            except:
                nm = None

        if not nm or nm == 'Unknown':
            nm = ''.join(__R.choices(__S.ascii_lowercase + __S.digits, k=12)) + '.txt'

        print("Downloading...")
        FR = __q.get(G, timeout=120)
        if FR.status_code != 200:
            print("Error: Download failed with HTTP", FR.status_code);return
        
        ED = FR.content
        print("Downloaded %.2f MB" % (len(ED)/1024/1024))

        KD = (k0[0]^k0[4], k0[1]^k0[5], k0[2]^k0[6], k0[3]^k0[7])
        IV = (k0[4], k0[5])

        DD = make_chunk_decryptor(IV, KD, ED, S/(1024*1024))
        print("Decryption complete")

        OP = __o.path.join(DOWNLOAD_FOLDER, nm)

        # RAR
        if DD[:4] == b'Rar!' or DD[:7] == b'Rar!\x1a\x07\x00':
            print("Detected: RAR archive")
            try:
                import rarfile, io
                B = io.BytesIO(DD)
                RAR = rarfile.RarFile(B)
                L = RAR.namelist()
                print("Found", len(L), "files in archive")
                if len(L)==1:
                    C = RAR.read(L[0])
                    OP = __o.path.join(DOWNLOAD_FOLDER, L[0])
                    open(OP,'wb').write(C)
                    print("Extracted:", L[0])
                    return OP
                else:
                    EF = __o.path.join(DOWNLOAD_FOLDER, nm.replace('.rar',''))
                    __o.makedirs(EF, exist_ok=True)
                    RAR.extractall(EF)
                    print("Extracted", len(L), "files to:", EF)
                    return EF
            except ImportError:
                print("Warning: rarfile missing, saving raw")
                open(OP,'wb').write(DD);return OP
            except Exception as e:
                print("Error extracting RAR:", e)
                open(OP,'wb').write(DD);return OP

        # ZIP
        elif DD[:2] == b'PK':
            print("Detected: ZIP archive")
            try:
                import zipfile, io
                Z = zipfile.ZipFile(io.BytesIO(DD))
                NL = Z.namelist()
                print("Found", len(NL), "files in archive")
                if len(NL)==1:
                    C = Z.read(NL[0])
                    OP = __o.path.join(DOWNLOAD_FOLDER, NL[0])
                    open(OP,'wb').write(C)
                    print("Extracted:", NL[0])
                    return OP
                else:
                    EF = __o.path.join(DOWNLOAD_FOLDER, nm.replace('.zip',''))
                    __o.makedirs(EF, exist_ok=True)
                    Z.extractall(EF)
                    print("Extracted", len(NL), "files to:", EF)
                    return EF
            except Exception as e:
                print("Error extracting ZIP:", e)
                open(OP,'wb').write(DD)
                return OP

        # GZIP
        elif DD[:2] == b'\x1f\x8b':
            print("Detected: GZIP compressed")
            try:
                import gzip
                C = gzip.decompress(DD)
                OP = OP.replace('.gz','')
                open(OP,'wb').write(C)
                print("Decompressed successfully")
                return OP
            except Exception as e:
                print("Error decompressing:", e)
                open(OP,'wb').write(DD)
                return OP

        # RAW
        else:
            open(OP,'wb').write(DD)
            print("Saved to:", OP)
            return OP

    except Exception as E:
        print("Error:", str(E))
        return

if __name__ == "__main__":  
    url = input("\nURL: ").strip()
    
    if not url:
        print("Error: No URL provided")
        exit()
    
    result = download_mega_file(url)
    
    if not result:
        print("\nFailed to download file")

# If you need any help or have questions, feel free to contact me on Discord: @kupk
