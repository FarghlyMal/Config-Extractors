import pefile

filename = 'file path'                                                           # enter file path here
max_size = b'36F4'                                                               # Max size granted from the sample

def enter_hex_val():                                                            # this function parse data and keys from file using PEFILE module
    val = input("Enter Hex Val passed to Decryption Function")                  # this input is used to control what digits to decrypt cause if the value was wrong it will result no correct strings
    pe  = pefile.PE(filename)
    for section in pe.sections:
        if b'.data' in section.Name:
            key = section.get_data()[1216:1283]                                    # the key blob reside at offset   (0x04C0 to 0x0503  RVA
        if b'.rdata' in section.Name:
            data = section.get_data()[32048:46118]                                 # the data blob resides at offset (0x7D30 to 0xB426 RVA

    return data,key,val                                                            

data,key,needed_size = enter_hex_val()                                              # need_size --> this var contain a hexa value the determine which chunk to decrypt and 
                                                                                    # this value is passed to the decryption function 

ref_need =int(needed_size,16)                                                       # creating INT refernces to use them inside loop
ref_max = int(max_size,16)

flag = False
decrypted =''

if ref_need < ref_max :                                                             # the algorithem is that it do "and operation" between the passed hex value and byte '3f'
                                                                                    # then it XOR the result of this operation with data of address [passed hexa value]
    while key[ref_need & int(b'3f',16)] != data[ref_need]:
        and_operation = ref_need & int(b'3f',16)
        decrypted +=chr((data[ref_need] ^ key[and_operation]))
        ref_need +=1
        if ref_need >= ref_max :
            flag = True                                                             # this part to alter if there is any mistake in passed hexa value
            print("i hit  break and value is bigger then blob size ")
            break
    if not flag :
         chunk = ref_need - int(needed_size,16)     
print(decrypted)

