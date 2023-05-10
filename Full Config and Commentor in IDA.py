import binascii
import pefile
import idaapi
import idautils

#the Below Function is FOR XOR Operation

def decrypter(Data,key)
    decrypted = ''
    for i in range(0,len(Data))
        decrypted +=chr(Data[i] ^ key[i % len(key)])
    return decrypted


#the Below Function is FOR Strings's Table Creation

def string_table(data)
    str_table=[]
    for k in data.splitit('x00')
        str_table.append(k)
    return str_table
# the Below Function of String Printing
def print_str_table(str_table)
    for i in str_table
        print(i)

# the Below Function searchs for a string in a string table

def string_decrypt_search(arg_string, arg_key, str_addr)
    local_table = []
    for i in range (0,len(arg_string))
        local_table.append(arg_string[i] ^ (arg_key[i%len(arg_key)]))
    converted_table =bytes(local_table)[str_addr].decode('latin').split('x00')[0]
    return (str_addr,converted_table)

#the Below Funtion Extracts Data from '.data' Section

def extract_data(filename)
    pe=pefile.PE(filename)
    for section in pe.sections
        if '.data' in section.Name.decode(encoding = 'utf-8').rstrip('x00')
            return (section.get_data(section.VirtualAddress,section.SizeOfRawData))

# The Function Below  calculates the offset between the current address of the targeted data and the start address of the .data section

def calc_offsets(x_seg_start,x_start)
    data_offset = hex(int(x_start,16) - int (x_seg_start,16))
    return data_offset


######
# data_seg_start         -- start address of the provided '.data' segment
# encrypted_string_addr  -- start address of the encrypted strings 
# key_data_addr          -- start address of the key strings which is used to decrypt Strings

def string_decrypter(arg_encrypted_string_addr,arg_key_data_addr,str_offset)
    
    data_1 =b''
    data_2 =b''
    
    #convert arguments to the appropriated format and notation .
    
    encrypted_string_addr = hex(int(arg_encrypted_string_addr))
    key_data_addr        = hex(int(arg_key_data_addr))
    
    
    #find the start address of the '.data' segment 
    for segment in idautils.Segments()
        if'.data' == idc.get_segm_name(segment)
            data_seg_start = hex(int(idc.get_segm_start(segment)))
            
    
    #next 2 lines calcs the offset between data blogbs and start of the '.data' segment. 
    
    encrypted_string_addr_rel = calc_offsets(data_seg_start,encrypted_string_addr)
    key_data_addr_rel = calc_offsets(data_seg_start,key_data_addr)
    
    
    #Next Three Lines extract '.data' section information 
    filename=r'CUsersHackDesktopQBotrundll32_00CC0000NT_res.bin'
    data_encoded_extracted_1 = extract_data(filename)
    data_encoded_extracted_2 = extract_data(filename)
    
    # Next Six Lines Calcs the size of the encrypted string table and the XOR key ,pay attention that 
    # I have an approach of searching up to tow end of String  Maker is found
    d1_off = 0x00
    d2_off = 0x00
    if (b'x00x00' in data_encoded_extracted_1[int(encrypted_string_addr_rel,16)])
        d1_off = (data_encoded_extracted_1[int(encrypted_string_addr_rel,16)]).index(b'x00x00')    
    if (b'x00x00' in data_encoded_extracted_1[int(key_data_addr_rel,16)])
        d2_off = (data_encoded_extracted_1[int(key_data_addr_rel,16)]).index(b'x00x00')    
        
        
    # Next Tow Lines the Meaingful information (encrypted string and XOR Key ) are isolated .
    data_1 = data_encoded_extracted_1[int(encrypted_string_addr_rel,16) int(encrypted_string_addr_rel,16) + d1_off]
    data_2 = data_encoded_extracted_2[int(key_data_addr_rel,16) int(key_data_addr_rel,16) + d2_off]
    
    
    #Finally the string table is decrypted 
    decoded_data = decrypter(data_1,data_2)
    item, result = string_decrypt_search(data_1,data_2,str_offset)
    return (string [%d]  %s  % (item,result))


def comment_string_offset(arg_encrypted_string_addr,arg_key_data_addr,arg_str_offset)
    str_function = idc.get_name_ea_simple(arg_str_offset)
    print(nn)
    for k in idautils.CodeRefsTo(str_function,0)
        p = idc.prev_head(k)
        my = idc.print_insn_mnem(p)
        if my in('mov','push')
            if my == mov 
                if idc.get_operand_type(p,1) == 5 
                    str_off_1 = int(idc.print_operand(p,1)[-1],16)
                    local_result_1 = string_decrypter(arg_encrypted_string_addr , arg_key_data_addr ,str_off_1)
                    final_result_1 = (local_result_1[local_result_1.find(' ')]).strip()
                    idc.set_cmt(k,final_result_1,0)
                    
            if my == push 
                if idc.get_operand_type(p,1) == 5 
                    str_off_1 = int(idc.print_operand(p,0)[-1],16)
                    local_result_1 = string_decrypter(arg_encrypted_string_addr , arg_key_data_addr ,str_off_1)
                    final_result_1 = (local_result_1[local_result_1.find(' ')]).strip()
                    idc.set_cmt(k,final_result_1,0)  
                    
            else
                j = idc.prev_head(p)
                my2 = idc.print_insn_mnem(j)
                if my2 in ('mov','push')
                    if my2 == 'mov' 
                        if idc.get_operand_type(j,1) == 5 
                            str_off_2 = int(idc.print_operand(j,1)[-1],16)
                            local_result_2 = string_decrypter(arg_encrypted_string_addr , arg_key_data_addr ,str_off_2)
                            final_result_2 = (local_result_2[local_result_2.find(' ')]).strip()
                            idc.set_cmt(k,final_result_2,0)
                    if my2 == 'push' 
                         if idc.get_operand_type(j,0) == 5 
                            str_off_2 = int(idc.print_operand(j,0)[-1],16)
                            local_result_2 = string_decrypter(arg_encrypted_string_addr , arg_key_data_addr ,str_off_2)
                            final_result_2 = (local_result_2[local_result_2.find(' ')]).strip()
                            idc.set_cmt(k,final_result_2,0)
                    
                    
string_slot = string_decrypter(0x1001D5A8,0x1001E3F8,1486)
string_slot = string_decrypter(0x1001D0B0,0x1001D050,708)
print(n+ string_slot)

comment_string_offset(0x1001D5A8,0x1001E3F8,az_w_decrypt_string)    # replace with your decryption Function Name
comment_string_offset(0x1001D5A8,0x1001E3F8,az_w_decrypt_string_1)  # replace with your decryption Function Name
comment_string_offset(0x1001D0B0,0x1001D050,az_w_decrypt_string_2)  # replace with your decryption Function Name
    
