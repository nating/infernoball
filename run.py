
import sys
import os
import json
from infernoball_functions import get_secret, decrypt, read_infernoball, combine_wordlists

#------------------ SYS ARG ERRORS ------------------

if( (len(sys.argv)==4 and sys.argv[1]!='generate-secret')
    or (len(sys.argv)==5 and sys.argv[1] not in ['generate-next-layer','combine-wordlists'])
    or len(sys.argv)>5 or len(sys.argv)<4):
    print("Error: Command should look like one of:\n " \
        + "python run.py combine-wordlists <path_to_wordlist_1> <path_to_wordlist_2> <path_to_output_file>\n" \
        + "python run.py generate-secret <path_to_infernoball> <path_to_potfile>\n" \
        + "python run.py generate-next-layer <path_to_infernoball> <path_to_potfile> <next_layer_folder>")
    sys.exit(1)

if(not os.path.isfile(sys.argv[2])):
    print("Error: %s is not a file." % sys.argv[2])
    sys.exit(1)

if( not os.path.isfile(sys.argv[3])):
    print("Error: %s is not a file." % sys.argv[3])
    sys.exit(1)

if( sys.argv[1]=='generate-next-layer' and not os.path.isdir(sys.argv[4])):
    print("Error: %s is not a directory." % sys.argv[4])
    sys.exit(1)

#------------------ MAIN CODE ------------------


if(sys.argv[1]=='combine-wordlists'):
    print("Combining Wordlists...")
    combine_wordlists(sys.argv[2], sys.argv[3], sys.argv[4])
    print("Done.")
    sys.exit(0)


path_to_infernoball = sys.argv[2]
path_to_potfile = sys.argv[3]
secret = get_secret(path_to_infernoball,path_to_potfile)

if(sys.argv[1]=='generate-secret'):
    print("Secret: %s" % secret)

    # Check for presence of secret in team18.secrets
    with open("team18.secrets", "r") as secrets_file:
        secrets = secrets_file.readlines()
        if secret in map(str.strip, secrets):
            print("Secret already in team18.secrets.")
            sys.exit(0)

    # Write new secret to secrets file
    with open("team18.secrets", "a") as secrets_file:
        secrets_file.write(secret)
        print("team18.secrets has been updated.")
        sys.exit(0)

elif(sys.argv[1]=='generate-next-layer'):

    previous_infernoball = read_infernoball(path_to_infernoball)
    next_infernoball = json.loads(decrypt(previous_infernoball.get('ciphertext'),secret))

    # Write new infernoball file
    next_layer_folder = sys.argv[4]
    with open(next_layer_folder+'/infernoball.json', 'w') as outfile:
        json.dump(next_infernoball, outfile)

    # Create new hash files
    argons = []
    pbkdf2s = []
    sha1crypts = []
    sha512s = []
    hashes = next_infernoball.get('hashes')
    for hash in hashes:
        if hash.startswith('$argon2'):
            argons.append(hash)
        elif hash.startswith('$pbkdf2'):
            pbkdf2s.append(hash)
        elif hash.startswith('$sha1$'):
            sha1crypts.append(hash)
        elif hash.startswith('$6$'):
            sha512s.append(hash)
        else:
            print("Error: Not sure what type of hash %s is." % hash)

    if not os.path.exists(next_layer_folder+'/hashes'):
        os.makedirs(next_layer_folder+'/hashes')

    with open(next_layer_folder+'/hashes/argon.txt', 'w') as f:
        for hash in argons:
            f.write(hash+"\n")

    with open(next_layer_folder+'/hashes/PBKDF2.txt', 'w') as f:
        for hash in pbkdf2s:
            f.write(hash+"\n")

    with open(next_layer_folder+'/hashes/sha1crypt.txt', 'w') as f:
        for hash in sha1crypts:
            f.write(hash+"\n")

    with open(next_layer_folder+'/hashes/SHA512.txt', 'w') as f:
        for hash in sha512s:
            f.write(hash+"\n")

    print("Done.")
