from Crypto.Cipher import DES3


def pad(entry):
    padded = entry+(16-len(entry)%16)*'['
    return(padded)
       

plain_text='Apply Royal'
key='12345'


def tripleDes_encrypt(plain_text1 , key1):
    plain_text1 = pad(plain_text1)
    plain_text1 = plain_text1.encode('utf-8')
    key1=pad(key1)
    key1=key1.encode('utf-8')
    cipher = DES3.new(key1, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(plain_text1)
    return ciphertext

def tripleDes_decrypt(ciphertext2, key2):
    key2=pad(key2)
    key2=key2.encode('utf-8')
    cipher = DES3.new(key2, DES3.MODE_ECB)
    data = cipher.decrypt(ciphertext2)
    data = data.decode('utf-8')
    unpad = data.find('[')
    data = data[:unpad]
    return data

print('1. Encrypt Data with 3DES')
print('2. Decrypt Data with 3DES')
num = input('===>>> ')
num = int(num)
if num == 1:
    print(tripleDes_encrypt(plain_text, key))
elif num == 2:
    print(tripleDes_decrypt(tripleDes_encrypt(plain_text, key), key))
else:
    print('Please Input Number above')

