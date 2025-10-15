import hashlib

def iterative_kdf(secret_value: int, num_iterations: int) -> str:
    """
    Performs iterative SHA-256 hashing on the given secret to produce a derived key.

    Args:
        secret_value (int): The shared secret (e.g., from Diffie-Hellman).
        num_iterations (int): Number of times the secret will be hashed.

    Returns:
        str: Final derived key as a hexadecimal string.
    """

    # Convert the integer secret into bytes
    current_hash = str(secret_value).encode()

    # Perform hashing multiple times
    for i in range(num_iterations):
        current_hash = hashlib.sha256(current_hash).digest()

        # Show progress every 10% of iterations (or every iteration if < 10)
        if i % (num_iterations // 10 or 1) == 0:
            print(f"Iteration {i+1}: {current_hash.hex()}")

    return current_hash.hex()

if __name__ == "__main__":
    print("=== Simple Key Derivation Function (KDF) ===")

    try:
        # Get user input for the shared secret and number of hashing rounds
        secret_input = int(input("Enter shared secret (from Diffie-Hellman): "))
        iteration_input = int(input("Enter number of hash iterations (e.g., 10000): "))
    except ValueError:
        print("Invalid input. Please enter numeric values.")
        exit()

    # Generate the derived key
    final_key = iterative_kdf(secret_input, iteration_input)

    # Display the final result
    print("\nFinal Derived Encryption Key:")
    print(final_key)
