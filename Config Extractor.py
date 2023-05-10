import binascii
import pefile

#this routine implements the Xor operation and Key's size into account

def decrypter(data_string,data_key):
    data_bytes =bytes.fromhex(data_string)
    _key   = bytes.fromhex(data_key)
#    print(_key)
    decode = []
    for i in range(0,len(data_bytes)):
        decode.append(data_bytes[i] ^ _key[i % 90])    # you can replace 90 with len(_key) 
        
        data = Make_String_table(decode)
    return data

def Make_String_table(string_bytes):
    string_bytes = bytes(string_bytes)
    string = string_bytes.decode('utf-8')

    str_table = string.split('\x00')
    return str_table
   

Data ='but your hexa encrypted Data Here '
Key  ='but your hexa decryption key herer '  

x = decrypter(data,key)

for i in x :
    print(i)
