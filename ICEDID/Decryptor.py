from arc4 import ARC4
import binascii
import pefile

def config_extract(filename):      	        	#this function parse pe file and extract the data from '.data' section
    pe = pefile.PE(filename)
    for section in pe.sections:
       if b".data" in section.Name :
         return section.get_data()
           
        
        
def rc4_decrypt(key, data):   			        # RC4 Decryption
    cipher = ARC4(key)
    decrypted = cipher.decrypt(data)
    return decrypted 

def main():
   # print(input("Enter File Name"))
    data =  config_extract('File name path ') 	    # like C:\\Users\\ICEDID.bin

#   data = binascii.unhexlify(data)
    key = data[:8] 				                     #key is the first 8 bytes of the Blob
    data = data[8:592]    	
    decrypted_data = rc4_decrypt(key, data)
   # DA = decrypted_data.replace(b'\x00', b'').split(b'\x00')
    print(decrypted_data.decode('latin-1'))

main()
