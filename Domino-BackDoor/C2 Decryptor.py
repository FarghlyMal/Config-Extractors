output = ""  
key = "039b547217d35ee6e0e9efe0df360d79"  
size = 128  
key_by = bytes.fromhex(key)  
  
Data = "3ba37a4326ea70d7d7dcc1d1ed02714037b565472ffd6cd2d7c7d8d2df58e3e0342a79f6f25e3496c1d73ac1f3f73acc1c2c5d818cd99918b3dbcc8a5386435b6227217df515756aa081ffceda7f61af7c944cf1929949ad943026602a08c919a40e05e92611e831730d74b0f7b91cdc11fb9d57fcc59368b6774126a96c85aa369bee6cbd9b786000"  
Data_by = bytes.fromhex(Data)  
  
for i in range(size):  
    output += chr(Data_by[i] ^ key_by[i % 16])  
  
print(output.encode('utf-8', 'ignore'))  
  
"""  
output = 119.175.124|94.158.247.72  
"""  
