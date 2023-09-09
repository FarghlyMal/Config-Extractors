import binascii
import pefile


def decrypter(data_string,data_key):
# convert Data from Hexa to binary represtation for XOR ing Operation

    data_bytes =bytes.fromhex(data_string)
    _key   = bytes.fromhex(data_key)
    decode = []
 #The Below Loop for xoring key with index % 90 or len(_key)___________ 90 --> size of the decryption key
    for i in range(0,len(data_bytes)):
        decode.append(data_bytes[i] ^ _key[i % 90])    # you can replace 90 with len(_key) 
        
        data = Make_String_table(decode)
    return data
# this function dumps the decrypted strings into a list 
def Make_String_table(string_bytes):
# the below line convert data from int to bytes
    string_bytes = bytes(string_bytes)
# the below line decode the converted bytes into and readable representation  'ascii' or 'utf'
    string = string_bytes.decode('utf-8')
# to seperate between strings we need to split the string based on Null terminator '0x00'
    str_table = string.split('\x00')
    return str_table
   

Data ='but your hexa encrypted Data Here '
Key  ='but your hexa decryption key herer '  

x = decrypter(data,key)

for i in x :
    print(i)
