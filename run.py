
import sys
import os
import json
from infernoball_functions import get_secret, decrypt, read_infernoball

#------------------ SYS ARG ERRORS ------------------

if( (len(sys.argv)==4 and sys.argv[1]!='generate-secret') or (len(sys.argv)==5 and sys.argv[1]!='generate-next-layer') or len(sys.argv)>5 or len(sys.argv)<4):
    print("Error: Command should look like one of:\n " \
        + "python run.py generate-secret <path_to_infernoball> <path_to_potfile>\n" \
        + "python run.py generate-next-layer <path_to_infernoball> <path_to_potfile> <next_layer_folder>")
    sys.exit(1)

if(not os.path.isfile(sys.argv[2])):
    print("Error: %s is not a file." % sys.argv[2])
    sys.exit(1)

if( not os.path.isfile(sys.argv[3])):
    print("Error: %s is not a file." % sys.argv[3])
    sys.exit(1)

if( len(sys.argv)==5 and not os.path.isdir(sys.argv[4])):
    print("Error: %s is not a directory." % sys.argv[4])
    sys.exit(1)

#------------------ MAIN CODE ------------------

path_to_infernoball = sys.argv[2]
path_to_potfile = sys.argv[3]
secret = get_secret(path_to_infernoball,path_to_potfile)

if(sys.argv[1]=='generate-secret'):
    print(secret)

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

    with open(next_layer_folder+'/argon.txt', 'w') as f:
        for hash in argons:
            f.write(hash+"\n")

    with open(next_layer_folder+'/PBKDF2.txt', 'w') as f:
        for hash in pbkdf2s:
            f.write(hash+"\n")

    with open(next_layer_folder+'/sha1crypt.txt', 'w') as f:
        for hash in sha1crypts:
            f.write(hash+"\n")

    with open(next_layer_folder+'/SHA512.txt', 'w') as f:
        for hash in sha512s:
            f.write(hash+"\n")

    print("Done.")
