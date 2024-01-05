# ref "https://docs.google.com/document/d/10vH-viRghPPg-TD1K2mvOfYktkUS7oGBDVRis--Fp4M/edit?usp=drive_link"  @FarghlyMal
# ref "https://n1ght-w0lf.github.io/malware%20analysis/smokeloader/"  @_n1ghtw0lf
# ref "https://research.openanalysis.net/smoke/smokeloader/loader/config/yara/triage/2022/08/25/smokeloader.html"  @herrcore

# this script will help you to fix and decrypt the encrypted function which makes our analysis harder.

import pefile
import binascii
import struct
filepath=r"Malware Path"
decrypted_file =r"path of the file to write the compressed payload after decryption"
x_64_size =0x2E46            # x64 payload size
x_86_size=0x22F8             # x86 payload size

def get_encrypted_s3():              # this function retrive the encrypted payload of the next stage to decrypt it using another function
    pe=pefile.PE(filepath)
    for section in pe.sections:
        if b'text' in section.Name:
            return (section.get_data()[0x463a:0x463a+x_64_size],section.get_data()[0x2342:0x2342+ x_86_size])


def xor_chunk(offset, n,key):    # this function decrypts the code of the next function to be executed
    ea = 0x400000 + offset
    for i in range(n):
        byte = ord(idc.get_bytes(ea+4, 1))
        bytekey0x50
        idc.patch_byte(a+i, byte)


xor_chunk(0x3292,0x2C,0x41)                     # arguments 1- offset of the function that will be decrypted    2- number of bytes of the function    3-Key for this function

def xor_chunk_API(offset, n, key, is_big_endian=False):     # This function decrypts API Hashes before translating these hashes to API addresses
    ea = 0x400000 + offset
    for i in range(0, (n//4)*4, 4):
        # Get a chunk of 4 bytes
        chunk = idc.get_bytes(ea + i, 4)

        # Reverse byte order if using big-endian
        if is_big_endian:
            chunk = chunk[::-1]
        # Convert the bytes to an integer
        value = int.from_bytes(chunk, byteorder='little')
        # XOR the integer with the key
        xor_result = value ^ key
        # Convert the result back to bytes
        xor_bytes = xor_result.to_bytes(4, byteorder='little')
        # Patch the original bytes with the XOR result
        idc.patch_bytes(ea + i, xor_bytes)


def xor_chunk_s3( data, dword_key, b_key):  # this function  the third stage 
    decrypted=b''
    #print(data)
    for i in range(0,(len(data)//4)*4,4):     # u can replace "(len(data)//4)*4" with size of the stream %4 but you will miss one byte may be 
        _4_bytes= struct.unpack("<I",data[i:i+4])[0]      # this line get 4 bytes in Littel Endian format
        xor_result = _4_bytes ^ dword_key
        decrypted+=struct.pack("<I",xor_result)          # assign the Xor result 
  
   last_bytes_len = len(data)%4                           # As we are xoring DWORDs we need to handle single bytes that exist at the end of the stream
   if last_bytes_len > 0:                                                       # because the stream may not accept division by 4,so we need to handle the last (1,2,3) bytes 
      last_decrypted=[]                                                  # with one byte as XOR Key.
      for byte in data[-last_bytes_len:]:
         last_decrypted.append(byte ^ b_key)
         print(last_decrypted)
      decrypted+=bytes(last_decrypted)  
   return decrypted      
 
decrypted_86 = xor_chunk_s3(data_86,0x880BD3F6,0xF6)
size_86=hex(struct.unpack("<I",test_86[0:4])[0])
print(f"size 86 = {size_86} and compressed length = {hex(len(test_86))}")

payload = test_86[4:]                      # the first 4 bytes are the size of the real payload because it is also compressed using LZSA2 algorithem 
open(decrypted_file,'wb').write(payload)
print("Written Done :) ")
