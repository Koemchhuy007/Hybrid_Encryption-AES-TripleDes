from Crypto.Cipher import AES


def pad(entry):
    padded = entry+(16-len(entry)%16)*'['
    return(padded)
       

plain_text='Apply Royal'


key='12345'


def aes_encrypt(plain_text1 , key1):
    plain_text1 = pad(plain_text1)
    plain_text1 = plain_text1.encode('utf-8')
    key1=pad(key1)
    key1=key1.encode('utf-8')
    cipher = AES.new(key1, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plain_text1)
    return ciphertext

def aes_decrypt(ciphertext2, key2):
    key2=pad(key2)
    key2=key2.encode('utf-8')
    cipher = AES.new(key2, AES.MODE_ECB)
    data = cipher.decrypt(ciphertext2)
    data = data.decode('utf-8')
    unpad = data.find('[')
    data = data[:unpad]
    return data

print('1. Encrypt Data with AES')
print('2. Decrypt Data with AES')
num = input('===>>> ')
num = int(num)
if num == 1:
    print(aes_encrypt(plain_text, key))
elif num == 2:
    print(aes_decrypt(aes_encrypt(plain_text, key), key))
else:
    print('Please Input Number above')

