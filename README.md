File encryption that encrypts every file and folder in the current working directory.

* [x] Create a basic message encryptor and decryptor using a 16B IV.
* [x] Create a basic file encryptor and decryptor using a 32B Key.
* [x] Use [RSA](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/) encryption and decryption on a file using OAEP padding mode.
* [x] Modify files to include Encrypt-then-[MAC](https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/)
* [x] Create a script that looks for RSA keys using a constant file path
  * [x] Create keys if it does not exist
* [x] Encrypt every file in current working directory.
  * [x] Store information into JSON file.
  * [x] Remove plaintext files after encrypting.
* [x] Read JSON file and decrypt the files.
  * [x] Remove encrypted files after decrypting.
