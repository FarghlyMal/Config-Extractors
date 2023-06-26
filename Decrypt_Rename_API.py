
import pefile
import idautils
import binascii
import struct
import ida_idaapi, ida_kernwin, ida_bytes, ida_name

filename = 'FilePath'
#def fix_operand(address_to_patch,string_to_paste):
 #   address =  address_to_patch
  #  string_bytes = bytes(string_to_paste,'utf-8')+b'\x00'
  #  for x in string_bytes:
  #      patch_byte(address,x)
  #      address+=1
  #  create_strlit(prov_addr,idc.BADADDR)
def rename_operand(address,string):
   #print(type(string))
   ida_name.set_name(int(address,16), string, ida_name.SN_CHECK)
def get_data_key():
    pe  = pefile.PE(filename)
    for section in pe.sections:
        if b'.data' in section.Name:
            key = section.get_data()[1216:1283]    
        if b'.rdata' in section.Name:
            data = section.get_data()[32048:46118]

    return data,key
def get_data(file_name):
    pe = pefile.PE(file_name)
    for section in pe.sections:
        if b'.data' in section.Name:
            return section.get_data()[int(b'E4',16):]
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
    #print(decrypted)
    return decrypted
API_Encrypted_Chunk =0x1000800C
data=get_data(r'Filepath')
the_end = data.index(b'\x00\x00\x00\x00\x00\x00')
print(hex(the_end))

API_encrypted = data[:the_end]
print(binascii.hexlify(API_encrypted))

lol = 0
jump_of_encrypted = 4
while lol < len(API_encrypted):
    val = API_encrypted[lol:lol+4]
    val_to_decrypt = binascii.hexlify(API_encrypted[lol + 4 : lol + 6])    # get bytes of api to decrypt
    data = val_to_decrypt[2:] + val_to_decrypt[:2]  # Swap the order of hexadecimal digits
    hex_addr = "0x" + "".join(format(byte, "02x") for byte in val[::-1])   #convert the address to effective address where the API address will reside 
    print(hex_addr)
    decrypted_str = decrypt_str(data)
    print(decrypted_str)
    print("__________________________")
    rename_operand(hex_addr,decrypted_str)
    lol +=12
