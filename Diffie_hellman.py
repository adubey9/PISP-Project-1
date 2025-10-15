import rsa
import random
import hashlib

# --- PLACEHOLDER FUNCTIONS (MIMICKING TASK 1) ---

def generate_key_pair():
    """Generates a public/private RSA key pair for signing/verification."""
    (public_key, private_key) = rsa.newkeys(512) # Use a small key size for demonstration
    return public_key, private_key

def sign_message(message: bytes, private_key: rsa.PrivateKey) -> bytes:
    """Placeholder for the signature mechanism from Task 1 (using RSA)."""
    # Hash the message before signing (common practice)
    hashed_message = hashlib.sha256(message).digest()
    signature = rsa.sign(hashed_message, private_key, 'SHA-256')
    return signature

def verify_signature(message: bytes, signature: bytes, public_key: rsa.PublicKey) -> bool:
    """Placeholder for the verification mechanism from Task 1 (using RSA)."""
    hashed_message = hashlib.sha256(message).digest()
    try:
        rsa.verify(hashed_message, signature, public_key)
        return True
    except rsa.VerificationError:
        return False

# ----------------------------------------------------------------------
# 1. Setup and Calculation Functions
# ----------------------------------------------------------------------

# NOTE: In a real-world scenario, 'p' would be 2048+ bits and 'g' would be a generator.
# We use small values here for fast computation and readability.
PUBLIC_PRIME_P = 17173  # A large enough prime for demonstration
GENERATOR_G = 3

def generate_secret_value(p: int) -> int:
    """
    Generates a secret integer (a or b) where $1 < secret < p - 1$.
    """
    return random.randint(2, p - 2)

def compute_public_value(g: int, secret: int, p: int) -> int:
    """
    Computes the public part: $g^{\text{secret}} \pmod p$.
    """
    return pow(g, secret, p)

def compute_shared_secret(public_value: int, own_secret: int, p: int) -> int:
    """
    Computes the final shared secret: $B^{\text{own\_secret}} \pmod p$ (or $A^{\text{own\_secret}} \pmod p$).
    """
    return pow(public_value, own_secret, p)

# ----------------------------------------------------------------------
# 2. Key Exchange Function
# ----------------------------------------------------------------------

def run_authenticated_key_exchange(
    entity_id: str,
    own_private_key: rsa.PrivateKey,
    peer_public_key: rsa.PublicKey,
    p: int,
    g: int
) -> tuple[int, bytes]:
    """
    Performs one side of the Authenticated Diffie-Hellman Key Exchange.

    This function represents the steps taken by either Alice or Bob.
    The communication step is simulated by requiring the peer's public data as input.

    Returns: (Shared_Secret, Own_Public_Value_and_Signature)
    """
    # 1. Generate own secret
    secret = generate_secret_value(p)
    
    # 2. Compute own public value
    public_val = compute_public_value(g, secret, p)
    
    # 3. Prepare data for transmission and signing
    # The message is (public_value) and is signed using the sender's private key.
    public_val_bytes = str(public_val).encode('utf-8')
    signature = sign_message(public_val_bytes, own_private_key)
    
    # The entity transmits (public_value, signature)
    transmit_data = public_val_bytes + b":" + signature
    
    print(f"[{entity_id}] Generated secret: {secret}. Public value $g^{{secret}} \pmod p$: {public_val}")
    print(f"[{entity_id}] Signing and preparing to send public value.")
    
    # --- SIMULATED PEER COMMUNICATION ---
    
    # The calling function (demonstration block) will handle receiving the peer's data.
    return secret, transmit_data

def finalise_key_exchange(
    own_secret: int,
    p: int,
    peer_transmit_data: bytes,
    peer_public_key: rsa.PublicKey
) -> int:
    """
    Receives peer's data, verifies the signature, and computes the shared secret.
    
    Returns: The final shared secret.
    """
    # 1. Separate the received public value and signature
    try:
        public_val_bytes, signature = peer_transmit_data.split(b":", 1)
        peer_public_val = int(public_val_bytes.decode('utf-8'))
    except ValueError:
        raise ValueError("Received data is malformed.")

    # 2. Verify the signature (Authentication step)
    is_valid = verify_signature(public_val_bytes, signature, peer_public_key)
    
    if not is_valid:
        raise ValueError("Signature verification failed! Potential Man-in-the-Middle attack.")
    
    print("  Signature verified successfully. Peer's identity is confirmed. ✅")

    # 3. Compute the shared secret: $PeerPublicVal^{\text{own\_secret}} \pmod p$
    shared_secret = compute_shared_secret(