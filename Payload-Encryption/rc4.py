import sys
#gemini stuff tbh
def rc4(data, key):
    S = list(range(256))
    j = 0
    out = []

    # KSA (Key Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA (Pseudo-Random Generation Algorithm)
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    
    return bytes(out)

FILE_IN = "../shellcode/payload.bin"
KEY = b"ILOVEMALWARE"

try:
    with open(FILE_IN, "rb") as f:
        data = f.read()
except FileNotFoundError:
    print(f"Error: {FILE_IN} not found")
    sys.exit()

encrypted = rc4(data, KEY)

# --- maldev print ---
print(f"// RC4 key: {KEY.decode()}")
print(f"unsigned char Key[] = {{ '" + "', '".join([chr(b) if 32 <= b <= 126 else f'\\x{b:02x}' for b in KEY]) + "' };")

print(f"\n// Encrypted payload with RC4")
print("unsigned char Payload[] = {")
for i in range(0, len(encrypted), 12):
    chunk = encrypted[i:i+12]
    print("    " + ", ".join([f"0x{b:02x}" for b in chunk]) + ",")
print("};\n")
