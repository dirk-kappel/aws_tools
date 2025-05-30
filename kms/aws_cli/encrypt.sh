# Encrypt a sample file using the CMK
aws kms encrypt --key-id <key_id> --plaintext fileb://test_file.txt --query CiphertextBlob --output text | base64 --decode > encrypted_file.txt

aws kms encrypt --key-id <key_id> --plaintext "My Secret" --query CiphertextBlob --output text | base64 --decode > MyEncryptedSecret