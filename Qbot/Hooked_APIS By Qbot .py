import binascii
import sys
import struct
import pefile
filename = sys.argv[1]
def get_data_key():
#    val = input("Enter Hex Val passed to Decryption Function")
    pe  = pefile.PE(filename)
    for section in pe.sections:
        if b'.data' in section.Name:
            key = section.get_data()[1216:1283]
        if b'.rdata' in section.Name:
            data = section.get_data()[32048:46118]

    return data,key
def decrypt_str(hex_size):
    data,key = get_data_key()
    max_size = b'36F4'
    ref_need =int(hex_size,16)
    ref_max = int(max_size,16)

    flag = False
    decrypted =''
    if ref_need < ref_max :
        while key[ref_need & int(b'3f',16)] != data[ref_need]:
            and_operation = ref_need & int(b'3f',16)
            decrypted +=chr((data[ref_need] ^ key[and_operation]))
            ref_need +=1
            if ref_need >= ref_max :
                flag = True 
                print("i hit  break ")
                break
        if not flag :
             chunk = ref_need - int(hex_size,16)     
    return decrypted
    
def parse_struct(struct_data):
    dll = struct_data[:2]
    API = struct_data[4:6]
    dll = binascii.hexlify(dll[::-1])
    API = binascii.hexlify(API[::-1])
    print("Dll : {0}          API : {1} ".format(decrypt_str(dll),decrypt_str(API)))
    
   
def get_all_struct(struct_off , len_hooks):
    ptr_data = 0
    for i in range(0,len_hooks):
        data = struct_off[ptr_data:ptr_data + 21]
        parse_struct(data)
        ptr_data +=21

    print("-----------------------------------------------")

def main():
    data = open(filename,'rb').read()
    get_all_struct(data[0x23d20:],10)
    get_all_struct(data[0x23bd4:],1)
    get_all_struct(data[0x23bf0:],10)
    get_all_struct(data[0x23df8:],8)
    

          
main()
