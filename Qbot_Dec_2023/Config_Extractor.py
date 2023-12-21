from Crypto.Cipher import AES
import hashlib
import binascii
import pefile
path=r"file path"

# this function retrieve the AES Key,AES encrypted data, and The Encrypted coonfig
def get_data():
    pe=pefile.PE(path)
    key_val=b''
    AES_encrypted=b''
    blob_data=b''
    key_val_length=0xA7      
    AES_encrypted_len=0xC0        
    blob_data_len=0x165D
    
    for section in pe.sections :
        if b".data" in section.Name:
            key_val=section.get_data()[157696:157696 + key_val_length]              # key to be hashed and used as AES decryption Key
            AES_encrypted=section.get_data()[157488 :157488 + AES_encrypted_len]    # AES Encrpyted Data to be decrypted and used to decrypted the encrypted config
            blob_data= section.get_data()[157872 : 157872 + blob_data_len]          # Encrypted Config 
    return AES_encrypted,blob_data,key_val



# this function retrieve the AES Key,AES encrypted data, and The  <second> Encrypted config 

def get_data_2():
    pe=pefile.PE(path)
    key_val_2 = b''
    AES_encrypted_2 = b''
    blob_data_2 =b''
    key_val_2_len = 0x47
    AES_encrypted_2_len = 0x90
    blob_data_2_len =0x5AD
    for section in pe.sections :
        if b".data" in section.Name:
            key_val_2 = section.get_data()[151888 : 151888 + key_val_2_len]                    # <second> key to be hashed and used as AES decryption Key
            AES_encrypted_2 = section.get_data()[151968 : 151968 + AES_encrypted_2_len]        # <second> AES Encrypted Data to be decrypted and used to decrypt the encrypted config
            blob_data_2 = section.get_data()[152128 : 152128 + blob_data_2_len]                # <second> Encrypted Config
    return AES_encrypted_2,blob_data_2,key_val_2        

# this function retrieve the AES Key,AES encrypted data, and The  <third> Encrypted config 
def get_data_3():
    pe=pefile.PE(path)
    key_val_3 = b''
    AES_encrypted_3 = b''
    blob_data_3 =b''
    key_val_3_len = 0x58
    AES_encrypted_3_len = 0x100
    blob_data_3_len =0x17
    
    for section in pe.sections :
        if b".data" in section.Name: 
            key_val_3=section.get_data()[156416 : 156416 + key_val_3_len]                # <third> key to be hashed and used as AES decryption Key
            AES_encrypted_3=section.get_data()[156512 : 156512 + AES_encrypted_3_len]    # <third> AES Encrypted Data to be decrypted and used to decrypt the encrypted config
            blob_data_3=section.get_data()[156392 : 156392 + blob_data_3_len]            # <third> Encrypted Config
    return AES_encrypted_3,blob_data_3,key_val_3    
  
# This function gets the length of the AES decrypted data  
def get_original_length(unpadded_data):     # unpadded_data is the AES decrypted data
    padding_length = unpadded_data[-1]
    
    original_length = len(unpadded_data) - padding_length
    return original_length

#this function uses AES crypto to decrypt the data that will be used as a key to decrypt the original config
def decrypt_data_using_AES(encrypted_data, session_key):
    iv = encrypted_data[:16]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    encrypted_data=encrypted_data[16:]
    decrypted_data = cipher.decrypt(encrypted_data)
    original_length = get_original_length(decrypted_data)
    return decrypted_data,original_length


# This function uses the AES-decrypted data to decrypt the config
def mw_decryypt(decrypted_AES_Data,AES_d_length,encrypted_blob_,index_val,max_index_):
    flag = 1
    ref_index_val=index_val
    X=0
    decrypted_string=""
    while encrypted_blob_[ref_index_val] != decrypted_AES_Data[ref_index_val%AES_d_length]:        # This loop iterates until it hits a matching in the char between the AES-Encrypted data and the encrypted config
                                                                                                    # to get the length of the required chunk to be decrypted
        ref_index_val+=1
        if ref_index_val >= max_index_:
            flag=0
            break
    if flag:
        X = ref_index_val - index_val                                    # X is the length

    for i in range(0,X):                                                # Decryption block
        xor_val =encrypted_blob_[index_val + i] ^ decrypted_AES_Data[(index_val +i) % AES_d_length]
        decrypted_string+=chr(xor_val)
    return str(decrypted_string)
    
def decrypt_1():            # This function decrypts the first blob of configuration 
    encrypted_data,encrypted_blob,key_to_be_hashed = get_data()
    session_key = derive_session_key(key_to_be_hashed)
    
    
    decrypted_data,orginal_len = decrypt_data_using_AES(encrypted_data, session_key)
    decrypted_data=list(decrypted_data)
    decrypted_data[orginal_len]=0x00
    decrypted_data=decrypted_data[:orginal_len + 1]
    max_index = 0x165b
    idx=0
    while idx <max_index:
        dec_str=mw_decryypt(decrypted_data,orginal_len,encrypted_blob,idx,max_index)
        print(f"{hex(idx)} --> {dec_str}")
        idx +=len(dec_str)+1
        print("_______________________________________________________")
        
        
def decrypt_2():                # this function decrypts the second  blob of configuration 
    encrypted_data,encrypted_blob,key_to_be_hashed = get_data_2()
    session_key = derive_session_key(key_to_be_hashed)
    
    
    decrypted_data,orginal_len = decrypt_data_using_AES(encrypted_data, session_key)
    decrypted_data=list(decrypted_data)
    decrypted_data[orginal_len]=0x00
    decrypted_data=decrypted_data[:orginal_len + 1]
    max_index=0x5AB
    idx=0
    while idx <max_index:
        
        dec_str=mw_decryypt(decrypted_data,orginal_len,encrypted_blob,idx,max_index)
        print(f"{hex(idx)} --> {dec_str}")
        idx +=len(dec_str)+1
        print("_______________________________________________________")

def decrypt_3():            # This function decrypts the third blob of configuration 
    encrypted_data,encrypted_blob,key_to_be_hashed = get_data_3()
    session_key = derive_session_key(key_to_be_hashed)
    decrypted_data,orginal_len = decrypt_data_using_AES(encrypted_data, session_key)
    decrypted_data=list(decrypted_data)
    decrypted_data[orginal_len]=0x00
    decrypted_data=decrypted_data[:orginal_len + 1]
    max_index= 0x9
    idx = 0x00
    dec_str=mw_decryypt(decrypted_data,orginal_len,encrypted_blob,idx,max_index)
    print(dec_str)
    print("_______________________________________________________")
