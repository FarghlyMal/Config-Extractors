import pefile
filename = 'C:\\Users\\Hack\\Desktop\\Zero2Auto\\04\\web_inject_ldr\\rsc1.dump'
max_size = b'36F4'
def enter_hex_val():
    val = input("Enter Hex Val passed to Decryption Function")
    pe  = pefile.PE(filename)
    for section in pe.sections:
        if b'.data' in section.Name:
            key = section.get_data()[1216:1283]
        if b'.rdata' in section.Name:
            data = section.get_data()[32048:46118]

    return data,key,val

data,key,needed_size = enter_hex_val()
max_size = b'36F4'

ref_need =int(needed_size,16)
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
         chunk = ref_need - int(needed_size,16)     
print(decrypted)

