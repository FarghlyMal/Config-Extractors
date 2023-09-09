import pefile
import struct
import binascii
import socket

# this function applies the decryption algorithm which i had reversed form binary
def decrypter(data,key,length):
    decode=[]
    for i in range(length):
        decode.append(data[i] ^ key[i % len(key)])
    return decode

# this function retrive encrypted data which reside at the start of  '.data' section
def Get_PE_Data(filename):
    pe=pefile.PE(filename)
    # the next loop itrate over all sections of the pefile  untill it hit data section
    for section in pe.sections:
        if b'.data' in section.Name:
            # the next line just return the data untill the end of the setion with SizeOfRawData as Size
            return section.get_data(section.VirtualAddress,section.SizeOfRawData)

# the next function is the base function which applies some math changes on the data to prepare it for decryption routine
def data_decrypter():
    filename = r'put here your file name'
    # the next line retrive the data using function of Get_PE_Data
    extracted_data = Get_PE_Data(filename)
    # the next  2 lines are one of the important beacous the data block retrived is so big and all of it is not used in decryption method so
    # after some reversing i got that i can used null trmintor of thad encrypted blob as a end of the decryption routine 
    # so i tried to get the index where the encrypted data ends using index function with helping of b"\x00\x00' as trminator
    data_end = extracted_data.index(b'\x00\x00')
    encrypted_config = extracted_data[:data_end]
    # so in the next lines which is my reversing result, the key is 4th bytes of the blob and the length is the result of XORing with second 4 bytes and the reminder is the encrypted config 
    xor_key = encrypted_config[:4]
    xor_key_unpacked = struct.unpack('<I',xor_key)[0]
    xor_length_unpacked = struct.unpack('<I',encrypted_config[4:8])[0]
    string_length = xor_key_unpacked ^ xor_length_unpacked 
    encrypted_data = encrypted_config[8:]
    # here i called the decryption function
    decrypted_data = decrypter(encrypted_data,xor_key,string_length)
    # i had to convert it to bytes becouse the return value was in int format and was hard to deal with this
    decrypted_data = bytes(decrypted_data)
    len_of_decrypted = len(decrypted_data)
    # so after some manuplation to data i reconginzed that the encrypted data is a block of ips and port numbers so i will itrate over it and convert it 
    # to ip address  using socket lib and inet_nto
    i = 0
    counter = 0
    for i in range(len_of_decrypted):
        ip = decrypted_data[counter : counter + 4]
        port = decrypted_data[counter + 4 : counter + 6]
        ip_address = socket.inet_ntoa(ip)
        port_num = int(binascii.hexlify(port),16)
        print(ip_address,':',port_num)
        counter+=8
        # the next line is just for handling any exception 
        if counter >= len_of_decrypted:
            print("we will have a break bro -_- ")
            break 
data_decrypter()
