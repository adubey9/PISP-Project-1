Secure Messaging Prototype
This project is a Python prototype that simulates a secure messaging system between two parties, Alice and Bob. It uses cryptographic concepts learned in class to ensure that their communication is both confidential (secret) and has integrity (cannot be tampered with).

The simulation is built step-by-step, with each task adding a new layer of security.

How the Code Works
The project is broken down into five main tasks, each building upon the last to create a complete secure channel.

Task 1: Digital Signatures (RSA)
Purpose: To prove identity. This is like a handwritten signature for the digital world.

How it's used: Alice and Bob each create a pair of keys: a private key they keep secret and a public key they can share. Alice can "sign" a message with her private key, and Bob can use her public key to verify that the message really came from her. This is essential to prevent imposters.

Task 2: Authenticated Diffie-Hellman Key Exchange
Purpose: To securely create a shared secret key over an insecure channel.

How it's used: Alice and Bob use a clever math trick (Diffie-Hellman) to agree on a secret key, even if someone is listening. To prevent a Man-in-the-Middle attack, they use the digital signatures from Task 1 to sign their messages during this exchange, proving they are talking to the right person.

Task 3: Encryption Key Derivation (KDF)
Purpose: To strengthen the shared secret key.

How it's used: The shared secret from the Diffie-Hellman exchange is put through a Key Derivation Function (KDF). Our simple KDF just hashes the secret 10,000 times. This process turns the raw secret into a cryptographically strong key suitable for encryption.

Task 4: Pseudo-Random Number Generator (PRNG)
Purpose: To create random numbers needed for the encryption process.

How it's used: This part of the code implements a simple PRNG. Secure encryption needs unpredictable numbers to use as Initialization Vectors (IVs) or nonces. This component provides those numbers.

Task 5: Secure Message Exchange (Authenticated Encryption)
Purpose: To finally send a message that is both secret and tamper-proof.

How it's used: This brings everything together. To send a message, Alice uses the Encrypt-then-MAC method:

Encrypt: She encrypts her message using the derived key (from Task 3) and a random IV (from Task 4). This provides confidentiality.

MAC: She then creates a MAC (like a keyed hash) of the encrypted message. This provides integrity and authenticity.

Bob receives the message and verifies the MAC first. If it's valid, he knows the message wasn't tampered with and can safely decrypt it.
