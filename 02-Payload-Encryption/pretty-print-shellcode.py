with open("../shellcode/payload.bin", "rb") as f:
    shellcode = f.read()

print("unsigned char Data[] = {")
print("    " + ", ".join([f"0x{b:02x}" for b in shellcode]))
print("};")
