
import sys
import os
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
    next_layer_folder = sys.argv[4]
    infernoball = read_infernoball(path_to_infernoball)
    next_infernoball = json.loads(decrypt(infernoball.get('ciphertext'),secret))
    with open(next_layer_folder+'/infernoball.json', 'w') as outfile:
        json.dump(next_infernoball, outfile)
        print("Done.")
