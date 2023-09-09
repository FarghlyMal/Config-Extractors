import pefile
import re
file = r"filename"
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

def get_PE_Data(file_name):
    pe=pefile.PE(file_name)
    for section in pe.sections:
         if b'.rdata' in section.Name:
            Key = section.get_data()[3056:3076]
            encryption_block = section.get_data()[2056:3032]
    return Key,encryption_block
    
def map_base64_to_enc(b_data,len_of_base):          # u can use builtin Python function to decode instead of this 
    RC4_Key,data = get_PE_Data(file)                # just for practice i decoded it manually 
    count = 0
    mapped_data=[]
    for i in range(0,len(b_data),3):
        mapped_data.append(((data[b_data[count + 1]] >> 4 )&0xFF) | ((data[b_data[count]] * 4)&0xFF))
        mapped_data.append(((data[b_data[count + 1]] * 16)&0xFF) | ((data[b_data[count + 2 ]] >> 2)&0xFF))
        mapped_data.append((data[b_data[count+3]]) | ((data[b_data[count + 2]] << 6) & 0xFF))
        count+=4 
        if count >= len(b_data):
            break
    if (b_data[-1]==0x3d):
        mapped_data[-1] = 0
    if (b_data[-2]==0x3d):
        mapped_data[-2] = 0
    byte_array=bytes(mapped_data)
    print(rc4_decrypt(byte_array,RC4_Key).decode("utf-8"))
    
def extract_and_decrypt():    
    pe = pefile.PE(file)
    for section in pe.sections:
        if b'.rdata' in section.Name :
            encrypted_block = section.get_data()[3080:11844]
    usefull_chunks=[]
    current_chunk=bytearray()
    for byte in encrypted_block:
        if byte != 0x00:
            current_chunk.append(byte)
        else:
            if current_chunk:
                usefull_chunks.append(bytes(current_chunk))
                current_chunk=bytearray()
    if current_chunk:
        usefull_chunks.append(bytes(current_chunk))
    x=0
    for chunk in usefull_chunks:
       map_base64_to_enc(chunk,len(chunk))
       x+=1
    print(x)
extract_and_decrypt()
