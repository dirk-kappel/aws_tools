# Decrypt the file
aws kms decrypt --key-id <key_id> --ciphertext-blob fileb://encrypted_file.txt --query Plaintext --output text | base64 --decode  > ExamplePlaintextFile
