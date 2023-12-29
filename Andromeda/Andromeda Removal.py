import os
import winreg
#for key, value in os.environ.items():
    #print(f"{key} = {value}")
registry_key_1 = winreg.HKEY_LOCAL_MACHINE
registry_key_2 = winreg.HKEY_CURRENT_USER
keys = [r"SOFTWARE\MICROSOFT" ,r"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENT VERSION\WINDOWS"]
value_name="load"
for key_path in keys:
    try:
        key=winreg.OpenKey(registry_key_2,key_path,0,winreg.KEY_READ | winreg.KEY_WRITE)
    
        try:
            value , data_type = winreg.QueryValueEx(key,value_name)
            print(f"{value_name} exists and its value is {value}")
            winreg.DeleteValue(key,value_name)
            print(f"{value_name} has been deleted.")
    
        except FileNotFoundError:
            print(f"{value_name} does not exist in the registry.")
    except FileNotFoundError:
        print(f"The specified key was not found.")
    except Exception as e:
        print(f" Error:{e}")

for key_path in keys:
    try:
        key=winreg.OpenKey(registry_key_1,key_path,0,winreg.KEY_READ | winreg.KEY_WRITE)
    
        try:
            value , data_type = winreg.QueryValueEx(key,value_name)
            print(f"{value_name} exists and its value is {value}")
            winreg.DeleteValue(key,value_name)
            print(f"{value_name} has been deleted.")
    
        except FileNotFoundError:
            print(f"{value_name} does not exist in the registry.")
    except FileNotFoundError:
        print(f"The specified key was not found.")
    except Exception as e:
        print(f" Error:{e}")

        
variable_name="SRC"
variable_value=os.environ.get(variable_name)
print(variable_value)
if variable_value is not None:
    if os.path.isfile(variable_value):
        try:
            os.remove(variable_value)
            print(f"File {variable_value} has been removed")
        except Exception as e:
            print(F"Error Deleting the File :{e}")

    else:
        print(f"{variable_value} is not a valid file path.")
else:
    print(f"{variable_name} is not defined in the environment.")
