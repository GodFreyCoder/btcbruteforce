import hashlib
import ecdsa
import base58
import random
import bech32

# ANSI color escape codes
CYAN = '\033[96m'
YELLOW = '\033[93m'
RED = '\033[91m'
GREEN = '\033[92m'
PINK = '\033[95m'
RESET = '\033[0m'  # Reset color to default

# Define the range of private keys
start_hex = "0000000000000000000000000000000000000000000000000000000000000001"
end_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"

start_int = int(start_hex, 16)
end_int = int(end_hex, 16)

# Function to generate compressed address for a given private key
def generate_address(private_key):
    private_key_hex = hex(private_key)[2:].zfill(
        64)  # Convert to hex and zero fill to 64 characters
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Get the public key
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes,
                                               curve=ecdsa.SECP256k1)
    public_key_compressed = signing_key.verifying_key.to_string(
        "compressed")  # Compressed public key
    public_key_uncompressed = signing_key.verifying_key.to_string(
        "uncompressed")  # Uncompressed public key

    # Compute the hash of the public key
    sha256_hash = hashlib.sha256(public_key_compressed)
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash.digest())
    hash_bytes = ripemd160_hash.digest()

    # Add the version byte (0x00 for mainnet)
    version_byte = b'\x00'
    hash_with_version = version_byte + hash_bytes

    # Calculate the checksum
    checksum = hashlib.sha256(
        hashlib.sha256(hash_with_version).digest()).digest()[:4]

    # Concatenate the hash and checksum
    binary_address = hash_with_version + checksum

    # Convert the binary address to base58
    compressed_address = base58.b58encode(binary_address).decode()

    # P2PKH uncompressed address
    p2pkh_uncompressed_address = generate_p2pkh_uncompressed(
        public_key_uncompressed)

    # P2SH compressed address
    p2sh_compressed_address = generate_p2sh_compressed(public_key_compressed)

    # Bech32 compressed address
    bech32_compressed_address = generate_bech32_compressed(public_key_compressed)

    return private_key_hex, compressed_address, p2pkh_uncompressed_address, p2sh_compressed_address, bech32_compressed_address


# Function to generate P2PKH uncompressed address
def generate_p2pkh_uncompressed(public_key_uncompressed):
    hash160 = hashlib.new('ripemd160')
    hash160.update(hashlib.sha256(public_key_uncompressed).digest())
    return base58.b58encode_check(b'\x00' + hash160.digest()).decode()


# Function to generate P2SH compressed address
def generate_p2sh_compressed(public_key_compressed):
    redeem_script = bytes.fromhex('0014') + hashlib.new(
        'ripemd160',
        hashlib.sha256(public_key_compressed).digest()).digest()
    hashed_redeem_script = hashlib.new(
        'ripemd160',
        hashlib.sha256(redeem_script).digest()).digest()
    return base58.b58encode_check(b'\x05' + hashed_redeem_script).decode()


# Function to generate Bech32 compressed address
def generate_bech32_compressed(public_key_compressed):
    witness_version = 0
    witness_program = hashlib.new(
        'ripemd160',
        hashlib.sha256(public_key_compressed).digest()).digest()
    return bech32.encode('bc', witness_version, witness_program)


# Function to check if address matches any of the target addresses
def check_address(result):
    global checked_count, targets_found  # Declare checked_count and targets_found as global to use it in this function
    private_key_hex, compressed_address, p2pkh_uncompressed_address, p2sh_compressed_address, bech32_compressed_address = result

    if compressed_address in target_addresses or p2pkh_uncompressed_address in target_addresses \
            or p2sh_compressed_address in target_addresses or bech32_compressed_address in target_addresses:
        targets_found += 1
        print(
            f"{GREEN}Target found! Target Count: {targets_found}/{num_target_addresses}{RESET}"
        )
        print(f"{GREEN}Checked Count: {checked_count}{RESET}")
        print(f"{YELLOW}Private Key Hex: {private_key_hex}{RESET}")
        print(f"{PINK}Compressed Address: {compressed_address}{RESET}")
        print(
            f"{PINK}P2PKH Uncompressed Address: {p2pkh_uncompressed_address}{RESET}"
        )
        print(f"{PINK}P2SH Compressed Address: {p2sh_compressed_address}{RESET}")
        print(
            f"{PINK}Bech32 Compressed Address: {bech32_compressed_address}{RESET}")

        # Remove the found target from the set of targets
        target_addresses.discard(compressed_address)
        target_addresses.discard(p2pkh_uncompressed_address)
        target_addresses.discard(p2sh_compressed_address)
        target_addresses.discard(bech32_compressed_address)

        return True  # Exit the loop if a target is found

    else:
        print(f"|Hex64:{RED}{private_key_hex}{RESET}")
        print(f"P2PKH(c):{YELLOW}{compressed_address}{RESET}")
        print(f"P2PKH(u):{YELLOW}{p2pkh_uncompressed_address}{RESET}")
        print(f"P2SH(c):{YELLOW}{p2sh_compressed_address}{RESET}")
        print(f"BECH32(u):{YELLOW}{bech32_compressed_address}{RESET}"    )
        print(f"Checking...{CYAN}{checked_count}{RESET}|{CYAN}========== H a n z o C o d e =========={RESET}|Found:{GREEN}{targets_found}{RESET}")


# Ask for search mode
search_mode = input("Enter search mode (1 for sequential, 2 for random): ")
if search_mode == "1":
    sequential_mode = True
elif search_mode == "2":
    sequential_mode = False
else:
    print("Invalid search mode. Exiting.")
    exit()

# Ask for the target file name
target_file_name = input("Enter the target file name (e.g., '1.txt'): ")

# Read target addresses from the specified file
with open(target_file_name, 'r') as file:
    target_addresses = {line.strip() for line in file}

num_target_addresses = len(target_addresses)

checked_count = 0
targets_found = 0

# Generate and check addresses
target_found = False
while not target_found:
    if sequential_mode:
        private_key = start_int + checked_count  # Incremental search in sequential mode
    else:
        private_key = random.randint(start_int, end_int)  # Random search in random mode

    result = generate_address(private_key)
    checked_count += 1
    target_found = check_address(result)

print(f"{GREEN}Done.{RESET}")
