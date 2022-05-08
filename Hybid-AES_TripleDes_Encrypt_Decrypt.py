from Crypto.Cipher import AES
from Crypto.Cipher import DES3
#from multiprocessing import Process
#Get value from Thread Process
try:
    import time
    import threading
except Exception as e:
    pass

global queue

class Queue(object):

    def __init__(self):
        self.item = []

    def __str__(self):
        return "{}".format(self.item)

    def __repr__(self):
        return "{}".format(self.item)

    def enque(self, item):
        """
        Insert the elements in queue
        :param item: Any
        :return: Bool
        """
        self.item.insert(0, item)
        return True

    def size(self):
        """
        Return the size of queue
        :return: Int
        """
        return len(self.item)

    def dequeue(self):
        """
        Return the elements that came first
        :return: Any
        """
        if self.size() == 0:
            return None
        else:
            return self.item.pop()

    def peek(self):
        """
        Check the Last elements
        :return: Any
        """
        if self.size() == 0:
            return None
        else:
            return self.item[-1]

    def isEmpty(self):
        """
        Check is the queue is empty
        :return: bool
        """
        if self.size() == 0:
            return True
        else:
            return False

queue = Queue()

def pad(entry):
    padded = entry+(16-len(entry)%16)*'['
    return(padded)
       

plain_text_origenal='Apply Royal'
key_origenal='12345'

def tripleDes_Encrypt_64bit_BlockSize(plain_text, key):
    cipher = DES3.new(key,DES3.MODE_ECB)
    ciphertext = cipher.encrypt(plain_text)
    queue.enque(ciphertext)

def tripleDes_Decrypt_64bit_BlockSize(cipher_text, key):
    cipher = DES3.new(key,DES3.MODE_ECB)
    plain_text = cipher.decrypt(cipher_text)
    queue.enque(plain_text)

def aes_Encrypt_128bit_BlockSize(plain_text, key):
    cipher = AES.new(key,AES.MODE_ECB)
    ciphertext = cipher.encrypt(plain_text)
    return ciphertext

def aes_Decrypt_128bit_BlockSize(cipher_text, key):
    cipher = AES.new(key,AES.MODE_ECB)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text


def hybrid_AES_3DES_encrypt(plain_text , key):
    plain_text = pad(plain_text)
    plain_text = plain_text.encode('utf-8')
    key=pad(key)
    key=key.encode('utf-8')
    length = len(plain_text)/2
    TripleDes_1_64bit = plain_text[:int(length)] 
    TripleDes_2_64bit = plain_text[int(length):]


    if __name__ == '__main__':
        thread1 = threading.Thread(target= tripleDes_Encrypt_64bit_BlockSize, args =(TripleDes_1_64bit, key,))
        thread2 = threading.Thread(target= tripleDes_Encrypt_64bit_BlockSize, args=(TripleDes_2_64bit,key,))
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()
        leftCipherText = queue.dequeue()
        rihgtCipherText = queue.dequeue()
        ciphertextFrom3Des= leftCipherText+rihgtCipherText

        #Apply AES encryption 
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(ciphertextFrom3Des)
        return ciphertext

    
def hybrid_AES_3DES_decrypt(ciphertext, key):
    key=pad(key)
    key=key.encode('utf-8')
    cipherTextAfter3Aes = aes_Decrypt_128bit_BlockSize(ciphertext, key)
    print(len(cipherTextAfter3Aes))
    length = len(cipherTextAfter3Aes)/2
    rihgtCipherTextAfterAES_64Bit = cipherTextAfter3Aes[:int(length)]
    leftCipherTextAfterAES_64Bit = cipherTextAfter3Aes[int(length):]
    
    if __name__ == '__main__':
        thread1 = threading.Thread(target= tripleDes_Decrypt_64bit_BlockSize, args=(rihgtCipherTextAfterAES_64Bit, key,))
        thread2 = threading.Thread(target= tripleDes_Decrypt_64bit_BlockSize, args=(leftCipherTextAfterAES_64Bit,key,))
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()
        right_plainText = queue.dequeue()
        left_plainText = queue.dequeue()
        #Merge Plain text
        data =right_plainText+left_plainText
        

        data = data.decode('utf-8')
        unpad = data.find('[')
        data = data[:unpad]
        return data


print(hybrid_AES_3DES_decrypt(hybrid_AES_3DES_encrypt(plain_text_origenal, key_origenal),key_origenal))

# print('1. Encrypt Data with Hybrid_AES_TripleDes')
# print('2. Decrypt Data with Hybrid_AES_TripleDes')
# num = input('===>>> ')
# num = int(num)
# if num == 1:
#     print(hybrid_AES_3DES_encrypt(plain_text_origenal, key_origenal))
# elif num == 2:
#     print(aes_decrypt(aes_encrypt(plain_text, key), key))
# else:
#     print('Please Input Number above')
