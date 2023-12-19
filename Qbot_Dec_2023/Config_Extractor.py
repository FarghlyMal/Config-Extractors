from Crypto.Cipher import AES
import hashlib
import binascii
import pefile
path=r"file path"
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
            key_val=section.get_data()[157696:157696 + key_val_length]
            AES_encrypted=section.get_data()[157488 :157488 + AES_encrypted_len]
            blob_data= section.get_data()[157872 : 157872 + blob_data_len]
    return AES_encrypted,blob_data,key_val
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
            key_val_2 = section.get_data()[151888 : 151888 + key_val_2_len]
            AES_encrypted_2 = section.get_data()[151968 : 151968 + AES_encrypted_2_len]
            blob_data_2 = section.get_data()[152128 : 152128 + blob_data_2_len]
    return AES_encrypted_2,blob_data_2,key_val_2        
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
            key_val_3=section.get_data()[156416 : 156416 + key_val_3_len]
            AES_encrypted_3=section.get_data()[156512 : 156512 + AES_encrypted_3_len]
            blob_data_3=section.get_data()[156392 : 156392 + blob_data_3_len]
    return AES_encrypted_3,blob_data_3,key_val_3    
  
def get_original_length(unpadded_data):
    padding_length = unpadded_data[-1]
    
    original_length = len(unpadded_data) - padding_length
    return original_length
  
def get_original_length(unpadded_data):
    padding_length = unpadded_data[-1]
    
    original_length = len(unpadded_data) - padding_length
    return original_length

def decrypt_data_using_AES(encrypted_data, session_key):
    iv = encrypted_data[:16]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    encrypted_data=encrypted_data[16:]
    decrypted_data = cipher.decrypt(encrypted_data)
    original_length = get_original_length(decrypted_data)
    return decrypted_data,original_length
  
def mw_decryypt(decrypted_AES_Data,AES_d_length,encrypted_blob_,index_val,max_index_):
    flag = 1
    ref_index_val=index_val
    X=0
    decrypted_string=""
    while encrypted_blob_[ref_index_val] != decrypted_AES_Data[ref_index_val%AES_d_length]:
        ref_index_val+=1
        if ref_index_val >= max_index_:
            flag=0
            break
    if flag:
        X = ref_index_val - index_val

    for i in range(0,X):
        xor_val =encrypted_blob_[index_val + i] ^ decrypted_AES_Data[(index_val +i) % AES_d_length]
        decrypted_string+=chr(xor_val)
    return str(decrypted_string)
    
def decrypt_1():
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
        
        
def decrypt_2():
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

def decrypt_3():
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
