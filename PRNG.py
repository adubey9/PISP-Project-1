import hashlib
import hmac
import os
import time
import secrets

class CustomRandomGenerator:
    def __init__(self):
        # The confidential data used to maintain randomness across calls
        self.secret_data = None

    def establish_initial_value(self, initial_value_input=None):
        """
        Sets the starting value for the random sequence.
        If no starting value is provided, it incorporates system timing, 
        process identifier, and fresh cryptographic data for better unpredictability.
        """
        if initial_value_input is None:
            initial_value_input = f"{time.time()}_{os.getpid()}_{secrets.token_hex(8)}"
        # Hash the input to establish the initial secret data
        self.secret_data = hashlib.sha256(initial_value_input.encode()).digest()
        return initial_value_input

    def incorporate_more_randomness(self, additional_random_data=None):
        """
        Mixes in extra unpredictable data to the current confidential state.
        """
        if self.secret_data is None:
            raise ValueError("Generator not set up. Call establish_initial_value() first.")
        if additional_random_data is None:
            additional_random_data = secrets.token_bytes(16)
        # Update the secret data by hashing it along with the new random input
        self.secret_data = hashlib.sha256(self.secret_data + additional_random_data).digest()

    def produce_random_output(self, desired_length=8, use_fixed_state=False):
        """
        Creates a pseudo-random integer.
        If use_fixed_state=True, the output relies purely on the current secret data (for repeatability).
        Otherwise, new random data is included in the computation.
        """
        if self.secret_data is None:
            raise ValueError("Generator not set up. Call establish_initial_value() first.")
        
        # Prepare the message for HMAC
        working_message = b"produce"
        if not use_fixed_state:
            working_message += secrets.token_bytes(16)
            
        # Generate the output block using HMAC-SHA256 with the secret data as the key
        output_block = hmac.new(self.secret_data, working_message, hashlib.sha256).digest()
        
        # Update the secret data with the output block (a crucial step for security)
        self.secret_data = hmac.new(self.secret_data, output_block, hashlib.sha256).digest()
        
        # Convert the leading bytes of the output block to an integer
        return int.from_bytes(output_block[:desired_length], 'big')

# --- Demonstration of Functionality ---

if __name__ == "__main__":
    print("=== Unpredictable Output Sequence Test ===")
    generator_unpredictable = CustomRandomGenerator()
    generator_unpredictable.establish_initial_value()
    for i in range(2):
        # The default behavior includes extra randomness in the message for each call
        print(f"Random Result {i+1}: {generator_unpredictable.produce_random_output()}")

    print("\n=== Repeatable Output Sequence Test ===")
    consistent_initial_value = "repeatable_seed_42"
    gen_one = CustomRandomGenerator()
    gen_two = CustomRandomGenerator()
    
    # Initialize both generators with the same starting value
    gen_one.establish_initial_value(consistent_initial_value)
    gen_two.establish_initial_value(consistent_initial_value)
    
    # Generate sequences using the deterministic mode (use_fixed_state=True)
    list_one = [gen_one.produce_random_output(use_fixed_state=True) for _ in range(2)]
    list_two = [gen_two.produce_random_output(use_fixed_state=True) for _ in range(2)]
    
    print("List One:", list_one)
    print("List Two:", list_two)
    print(f"Lists are identical: {list_one == list_two}")

    print("\n=== Initial Value Variation Test ===")
    gen_alpha = CustomRandomGenerator()
    gen_beta = CustomRandomGenerator()
    
    # Use distinct initial values
    gen_alpha.establish_initial_value("start_value_A")
    gen_beta.establish_initial_value("start_value_B")
    
    # Generate deterministic sequences
    list_alpha = [gen_alpha.produce_random_output(use_fixed_state=True) for _ in range(2)]
    list_beta = [gen_beta.produce_random_output(use_fixed_state=True) for _ in range(2)]
    
    print("List Alpha:", list_alpha)
    print("List Beta:", list_beta)
    print(f"Lists are identical: {list_alpha == list_beta}")