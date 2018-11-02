# infernoball
🔥 Hash cracking the Infernoball. 🔥

## Cracking Hashes

To combine two wordlists into a 'combinator-style' wordlist:
```bash
python run.py combine-wordlists <wordlist_1> <wordlist_2> <output_file>
```

## Progressing into the Inferno

To generate a secret:
```bash
python run.py generate-secret <path_to_infernoball> <path_to_potfile>
```

To create the next layer:
```bash
python run.py generate-next-layer <path_to_infernoball> <path_to_potfile> <next_layer_folder>
```
