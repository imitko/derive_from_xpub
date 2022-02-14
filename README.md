# derive_from_xpub
Derive a Ki public from given BIP-32 pub key

Depends on:

- openssl lib
- base58 lib

Build:
`$ gcc -lssl -lcrypto -lbase58 derive_from_xpub.c -o derive_from_xpub`

Run basic test:
 `$ ./derive_from_xpub test`
