# PyHide
A lightweight tool that creates one time files to send to people that are strong encrypted with a key. This tool is designed with minimal dependencies and takes advantage of standardized cryptography.

## Features
- AES CBC Encryption
- PBKDF2 Key Derivation with randomized iterations
- Automatically zips folders to send batches of files
- Filenames are encrypted
- SHA512 checksum to verify authenticity of package
This tool encodes the encrypted binary data to inject into the templated python script. This obviously is not an efficient way to transmit data, however I use base 85 for a small size advantage over the standard base 64.

## Dependencies 
- Python 2.7 or greater
- [PyCrypto](https://pypi.org/project/pycrypto/ "PyCrypto")

On Windows, [PyCrypto](https://pypi.org/project/pycrypto/ "PyCrypto") is known to fail on install. [PyCryptodome](https://pypi.org/project/pycryptodome/ "PyCryptodome") is fully compatible with this tool.

## Usage
Encrypting a file
```
python pyhide.py -f path/to/file/file.txt
```
Encrypting a folder
```
python pyhide -d path/to/folder/
```
Command-line password input
```
python pyhide -f file.txt -pThisIsNotASecurePasswordInput
```

## Warning
This is the first tool I have publicly posted. Please feel free to make change requests. 
**If you find a security vulnerability in this code or a point of weakness in the encryption please let me know and it will be fixed immediately.**