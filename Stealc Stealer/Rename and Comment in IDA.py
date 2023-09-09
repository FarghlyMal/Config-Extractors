import pefile
import idautils
import idc
import ida_idaapi, ida_kernwin, ida_bytes, ida_name
file = r"file path"

def rc4_decrypt(ciphertext, key):
    # Initialization
    S = list(range(256))
    j = 0
    key_length = len(key)
    plaintext = bytearray(len(ciphertext))

    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]


    i = j = 0
    for idx, byte in enumerate(ciphertext):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream_byte = S[(S[i] + S[j]) % 256]
        if byte == 0x00 :                       #this the modified part of RC4 to ignore null bytes form decryption 
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
        
def map_base64_to_enc(b_data,len_of_base):
    RC4_Key,data = get_PE_Data(file)
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

    return (rc4_decrypt(byte_array,RC4_Key).decode('utf-8',errors='ignore'))
    
def Modify_Xrefs(Decryption_routin):
    Xrefs = idautils.CodeRefsTo(Decryption_routin,0)

    count=0
    for x in Xrefs:
        ea = idc.prev_head(x)
        inst_type = ida_ua.ua_mnem(ea)
        type = idc.get_operand_type(ea,1)
        operand_address = idc.get_operand_value(ea,1)
        size = 200
        data__ = idaapi.get_bytes(operand_address,size)
        if operand_address != -1 :
            index=data__.index(b'\x00\x00')
            count +=1
            data__=data__[:index]
            decrypted_str = map_base64_to_enc(data__,len(data__))
            idc.set_cmt(x,decrypted_str,0)
            print(decrypted_str)
            dword_address = idc.next_head(x)
            dword_value = idc.get_operand_value(dword_address,0)
            rename_operand(dword_value,decrypted_str)
        else:
            continue
def rename_operand(address,string):
    ida_name.set_name(address, string, ida_name.SN_CHECK)
Decryption_fun_address = 0x00403047
Modify_Xrefs(Decryption_fun_address)
