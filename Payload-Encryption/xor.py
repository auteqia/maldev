# generated with msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin
with open("../shellcode/payload.bin", "rb") as f:
    shellcode = bytearray(f.read())

key = 0xAA
final = 0

for i in range(len(shellcode)):
    shellcode[i] ^= key
    final += shellcode[i]
    print(f"0x{shellcode[i]:02X}, ", end="")


with open("../shellcode/payload_enc.bin", "wb") as f:
    f.write(shellcode)

print("\nencrypted")
