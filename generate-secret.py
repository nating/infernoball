
import sys
import os
import base64
from Crypto.Cipher import AES
from Crypto import Random
import secretsharing as sss
import json
from hashlib import sha256

#------------------ SYS ARGS ------------------

if(len(sys.argv)!=3):
    print("Error: Please provide an infernoball.json and potfile, e.g.: \n\tpython generate-secret.py layer-1/infernoball.json potfile.txt")
    sys.exit(1)

if( not os.path.isfile(sys.argv[1])):
    print("Error: %s is not a file." % sys.argv[1])
    sys.exit(1)

if( not os.path.isfile(sys.argv[2])):
    print("Error: %s is not a file." % sys.argv[2])
    sys.exit(1)

#------------------ STEPHEN'S FUNCTIONS ------------------

def pxor(pwd,share):
    '''
      XOR a hashed password into a Shamir-share
      1st few chars of share are index, then "-" then hexdigits
      we'll return the same index, then "-" then xor(hexdigits,sha256(pwd))
      we truncate the sha256(pwd) to if the hexdigits are shorter
      we left pad the sha256(pwd) with zeros if the hexdigits are longer
      we left pad the output with zeros to the full length we xor'd
    '''
    words=share.split("-")
    hexshare=words[1]
    slen=len(hexshare)
    hashpwd=sha256(pwd.encode('utf-8')).hexdigest()
    hlen=len(hashpwd)
    outlen=0
    if slen<hlen:
        outlen=slen
        hashpwd=hashpwd[0:outlen]
    elif slen>hlen:
        outlen=slen
        hashpwd=hashpwd.zfill(outlen)
    else:
        outlen=hlen
    xorvalue=int(hexshare, 16) ^ int(hashpwd, 16) # convert to integers and xor
    paddedresult='{:x}'.format(xorvalue)          # convert back to hex
    paddedresult=paddedresult.zfill(outlen)       # pad left
    result=words[0]+"-"+paddedresult              # put index back
    return result

def pwds_shares_to_secret(kpwds,kinds,diffs):
    '''
            take k passwords, indices of those, and the "public" shares and
            recover shamir secret
    '''
    shares=[]
    for i in range(0,len(kpwds)):
        shares.append(pxor(kpwds[i],diffs[kinds[i]]))
    secret=sss.SecretSharer.recover_secret(shares)
    return secret


#------------------ MAIN CODE ------------------

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def decrypt(enc, password):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

passwords = []
indexes = []
shares = []

# Read in Infernoball
with open(sys.argv[1], encoding='utf-8') as infernoball_file:
    infernoball = json.loads(infernoball_file.read())
    ciphertext = infernoball.get('ciphertext')
    hashes = infernoball.get('hashes')
    shares = infernoball.get('shares')

# Get relevant passwords from potfile
with open(sys.argv[2], "r", encoding='utf-8') as potfile:
    potfile_content = potfile.readlines()
    for index, line in enumerate(potfile_content):
        s = line.strip().split(':')
        hash = s[0]
        password = s[1]
        if hash in hashes:
            passwords.append(password)
            indexes.append(hashes.index(hash))

secret = pwds_shares_to_secret(passwords,indexes,shares)

# Check that the secret is correct
if secret != pwds_shares_to_secret(passwords[:-1],indexes[:-1],shares):
    print("You do not have enough passwords cracked yet")
    sys.exit(1)
else:
    print(secret)
