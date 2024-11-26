import base64
import pefile

def Get_data_and_Key(FilePath):
    pe = pefile.PE(FilePath)
    for section in pe.sections:
        if b'rdata' in section.Name:
            key = section.get_data()   [0xBAF8:0xBAF8 + 0x10]
            data = section.get_data()  [0xBB10:0xBB10 + 0x23A0]
            key2 = section.get_data()  [0xB8AC:0xB8AC + 0x10]
            data2 = section.get_data() [0xFA94:0xFA94 + 0x940]
    return key,data,key2,data2
    
def rc4_decrypt(ciphertext, key):
    # Initialization
    S = list(range(256))
    j = 0
    key_length = len(key)
    plaintext = bytearray(len(ciphertext))
    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    # Pseudo-random generation algorithm (PRGA) and decryption
    i = j = 0
    for idx, byte in enumerate(ciphertext):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream_byte = S[(S[i] + S[j]) % 256]
        if byte == 0x00 :
             continue
        else :
            plaintext[idx] = byte ^ keystream_byte
    return bytes(plaintext)
    
key,data,key2,data2 = Get_data_and_Key(r"File Path")
part1_decoded = base64.b64decode(data)
part1_decrypted_stream = rc4_decrypt(part1_decoded,key)
part2_streams_list =data2.split(b'\x00\x00\x00\x00')
part2_decrypted_streams=[]
for stream in part2_streams_list :
    if stream:
        b64decoded=base64.b64decode(stream)
        rc4_decrypted = rc4_decrypt(b64decoded,key2)
        part2_decrypted_streams.append(rc4_decrypted)
print(part1_decrypted_stream.decode('utf-8'))
for decrypted_stream in part2_decrypted_streams :
    print(decrypted_stream.decode('utf-8'))

