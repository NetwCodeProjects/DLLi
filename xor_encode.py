# xor_encode.py
import sys

print("Usage: python xor_encode.py <input_dll> <output_file>")
if len(sys.argv) != 3:
    print("[-] Missing arguments. Example:")
    print("    python xor_encode.py payload.dll payload.xor")
    sys.exit(1)

key = input("Enter XOR key: ").encode()  # Convert string to bytes

input_file = sys.argv[1]
output_file = sys.argv[2]

try:
    with open(input_file, "rb") as f:
        data = f.read()
except FileNotFoundError:
    print(f"[-] File not found: {input_file}")
    sys.exit(1)

# XOR encode
encoded = bytearray([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Write output
with open(output_file, "wb") as f:
    f.write(encoded)

print(f"[+] XOR-encoded payload saved to {output_file}")
