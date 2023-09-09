# this file contain how the real code looks like , here i am talking about debuggging and testing your code several times so it does not come from the first time :) 
import pefile
#import idautils
#import idc
file = r"C:\Users\REM\Desktop\Mal DB\Stealc Stealer\Stealc"
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
    return Key,data
        
def map_base64_to_enc(b_data,len_of_base):          # u can decode it using base64.decode() function but i do it for fun and practice :( 
    RC4_Key,data = get_PE_Data(file)
    count = 0
    mapped_data=[]
    for i in range(0,len(b_data),3):
        mapped_data.append(((data[b_data[count + 1]] >> 4 )&0xFF) | ((data[b_data[count]] * 4)&0xFF))
     #   print(f"operation {i}")
        mapped_data.append(((data[b_data[count + 1]] * 16)&0xFF) | ((data[b_data[count + 2 ]] >> 2)&0xFF))
    #    print(f"operation {i+1}")
        mapped_data.append((data[b_data[count+3]]) | ((data[b_data[count + 2]] << 6) & 0xFF))
     #   print(f"operation {i+2}")
        count+=4 
        if count >= len(b_data):
            break
    if (b_data[-1]==0x3d):
   #     print("we got = sign")
        mapped_data[-1] = 0
    if (b_data[-2]==0x3d):
    #    print("we got = sign")
        mapped_data[-2] = 0
  #  print(mapped_data)
    byte_array=bytes(mapped_data)
 #   print(byte_array)
 #   print(RC4_Key)
    print(rc4_decrypt(byte_array,RC4_Key).decode("utf-8"))

    
base_64_str=input("Enter Base64 value : \n ").encode('utf-8')
len_base_str =len(base_64_str)
map_base64_to_enc(base_64_str,len_base_str)

# if (len_base_str % 3):
#     len_base_str=len_base_str - (len_base_str % 3) + 3
# len_base_str = int(8 * (len_base_str / 6 ) + 1)
