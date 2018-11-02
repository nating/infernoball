
import sys
import os
import base64
from Crypto.Cipher import AES
from Crypto import Random
import secretsharing as sss
import json
from hashlib import sha256

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


#------------------ GEOFF'S FUNCTIONS ------------------

# Returns an infernoball object, read in from a json file found at path_to_infernoball
def read_infernoball(path_to_infernoball):
    with open(path_to_infernoball) as infernoball_file:
        return json.loads(infernoball_file.read())

# Returns an infernoball object, given a ciphertext and secret
def decrypt(ciphertext, secret):
    BLOCK_SIZE = 16
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    secret_variant = secret.zfill(32).decode('hex')
    enc = base64.b64decode(ciphertext)
    iv = enc[:16]
    cipher = AES.new(secret_variant, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

# Returns a secret, given an infernoball and a potfile
def get_secret(path_to_infernoball,path_to_potfile):
    passwords = []
    indexes = []
    shares = []

    # Read in Infernoball
    infernoball = read_infernoball(path_to_infernoball)
    ciphertext = infernoball.get('ciphertext')
    hashes = infernoball.get('hashes')
    shares_obj = infernoball.get('shares')
    for s in shares_obj:
        shares.append(str(s))

    # Get relevant passwords from potfile
    with open(path_to_potfile, "r") as potfile:
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
        print("You do not have enough passwords cracked yet.")
        sys.exit(1)
    else:
        return secret


# Create a wordlist that is essentially the result of a combinator of file_1+file_2
def combine_wordlists(file_1,file_2,output_file):

	second_words = []
	with open(file_2, "r") as second_wordlist_file:
		print("Getting file 1 contents.")
		second_wordlist = second_wordlist_file.readlines()
		for word in second_wordlist:
			second_words.append(word)

	with open(output_file,"w") as output:
		with open(file_1, "r") as first_wordlist_file:
			print("Creating wordlist.")
			first_wordlist = first_wordlist_file.readlines()
			for word_1 in first_wordlist:
				for word_2 in second_words:
					output.write("%s%s\n" % (word_1.strip(),word_2.strip()))
