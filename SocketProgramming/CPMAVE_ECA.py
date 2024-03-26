import argparse
import socket, pickle
import os

# The elliptic curve
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.curve import Curve
from fastecdsa import keys, curve
from ecdsa.util import PRNG
from ecdsa import SigningKey

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from fastecdsa import curve, ecdsa, keys
from hashlib import sha384
import binascii

import hashlib
import os 
import sys
import time

def Hash(*dataListByte):
    h = hashlib.new('sha256')
    Mydata=b""
    for data in dataListByte:
        #print("Data: ",data)
        Mydata = Mydata + data.to_bytes(32, 'big')
    h.update(Mydata)
    HashResult=h.hexdigest()
    Hash_value=int(HashResult,16)%P256.q
    return Hash_value

def Registration_With_KGC(KGC_priv_key):
    KGC_yA_priv_key, KGC_yA_pub_key = keys.gen_keypair(curve.P256)
    h_a=Hash(KGC_yA_priv_key)
    C_a=h_a*KGC_yA_priv_key*P256.G
    sigma=(KGC_priv_key+h_a*KGC_yA_priv_key+KGC_yA_priv_key)%P256.q
    return C_a,sigma, KGC_yA_pub_key

def AES_Enc_using_Key(Key, iv, message):
    #converting the key from a point to a string
    h = hashlib.new('sha256')
    h.update(Key.x.to_bytes(32, 'big')+Key.y.to_bytes(32, 'big'))
    HashResult=h.hexdigest()
    EncKey=bytes(h.hexdigest(),'utf-8')

    #The Encryption
    ENC = AES.new(EncKey[:16], AES.MODE_CBC, iv)
    Msg_encrypted=ENC.encrypt(message.to_bytes(32,'big'))

    return Msg_encrypted, EncKey

def AES_Dec_using_Key(Key, iv, Cipher):
    #converting the key from a point to a string
    h = hashlib.new('sha256')
    h.update(Key.x.to_bytes(32, 'big')+Key.y.to_bytes(32, 'big'))
    HashResult=h.hexdigest()
    DecKey=bytes(h.hexdigest(),'utf-8')

    #The Decryption
    DEC = AES.new(DecKey[:16], AES.MODE_CBC, iv)
    Cipher_decrypted=int.from_bytes(DEC.decrypt(Cipher),'big')

    return Cipher_decrypted, DecKey

#########################################################################################
#########################   Registration Data   #########################################
#########################################################################################

###########################    ECA Identity  ##########################################

ECA_Identity= 13385647806998004153020035149177702292929509406886890249193697053202672561527

ECA_priv_key= 27035679567817885497930140100479440063071582958031951165314744143627511123473
ECA_pub_key_X= 0x6aadbccb88ad8839c21e7a3754e42f7281eeb2b75a07358f6889eef9030c1793
ECA_pub_key_Y= 0x869e40c7c429fa96ddc6ad3576224ff5bd95c55a68224a0d1f734e4786443af5
ECA_pub_key=Point(ECA_pub_key_X, ECA_pub_key_Y, curve=P256)

ECA_sigma= 25106535378440752376581550080743121753402285117385170558988665032551770271000

ECA_C_i_X= 0xb617e0900b2d6304a11d7a99e27e7498483b6563b47c1ee06dd2dc73e62408fb
ECA_C_i_Y= 0x90dcbf5075f41420fc7a51b078dfbe2a1b401d6d431e7df45072a8134186cae6
ECA_C_i=Point(ECA_C_i_X, ECA_C_i_Y, curve=P256)

ECA_Y_i_X= 0x3dda16e64b2fde142872b07e2a28271ac3b014425e15575caa405bdfb6052b94
ECA_Y_i_Y= 0xc797bb1d4a12fedc152c3b2aedb1f34a12537b6b5ec388502bdc2825565d2d
ECA_Y_i=Point(ECA_Y_i_X, ECA_Y_i_Y, curve=P256)

PK_g_X= 0x6d1973e8554c68424fc51542ff8b0fe6a84bd7c88f2e2f19f4d0712a13604d55
PK_g_Y= 0xe64e6122ce7a70e26f7496510ea93fb5730a9894448d1a6b4bd15da8c08cfdc0
PK_g=Point(PK_g_X, PK_g_Y, curve=P256)

#############################  TMA Identity   #############################################

TMA_Identity= 8169104755805935683608881213542562938956147541291769502712984486856835317573

TMA_pub_key_X= 0x6880bbbb54c1a66f3618249d550fa629ec31eece9a3be989e6093ac1b790dbb2
TMA_pub_key_Y= 0xa315167d2f09b9a27b0fe53fc96b47eea13bc8deaea8c50cabde9428e8683d03
TMA_pub_key=Point(TMA_pub_key_X, TMA_pub_key_Y, curve=P256)

############################   Vehicle Identity  ###########################################

Vehicle_Identity= 6330614295947393657856040725909354215571545936334951160496604125994438196162

Vehicle_pub_key_X= 0xf81cc47e2caf24468ddf86ab9279c14bae235a07c5c2f960a1ba395ffc14d2b6
Vehicle_pub_key_Y= 0xd8d7dab908578b5aa9f87118662117587bd44f38b8d67eb0e9b4439f04f8a723
Vehicle_pub_key=Point(Vehicle_pub_key_X, Vehicle_pub_key_Y, curve=P256)

##############################################################################################

# The Socket programming
parser = argparse.ArgumentParser(description = 'Server CA for IoT Simulation')
args = parser.parse_args()

A = P256.G
B= A = P256.G
ExpiryTime=int.from_bytes(os.urandom(1024),'big')%P256.q
iv=Random.new().read(AES.block_size)
ECA_key=P256.G

def ECA_program():
    Veh_socket = socket.socket()  # get instance
    host = '192.168.122.202'
    port = 5000  # socket server port number

    # look closely. The bind() function takes tuple as argument
    Veh_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    Veh_socket.listen(10)    

    while True:
        conn, address = Veh_socket.accept()  # accept new connection
        # print("PAS:Connection from: " + str(address))

        #Step 1: Receiving the identity of the sender and receiver from the Veghicle
        data = conn.recv(2048)         
        # print('ECA: step 1: received from Vehicle: ')
        # print(pickle.loads(data))  # show in terminal
        message=pickle.loads(data)
        Sender_Identity=message[0]
        Receiver_Identity=message[1]
        
        # Generate the Nonce and encrypt it using the vehicle public key and the ECA private key
        Nonce = int.from_bytes(os.urandom(1024),'big')%P256.q
        message = Encrypt_nonce_Send_Receiver_PublicKey(Nonce)
        iv=message[0]
        ECA_key=message[3]


        #Step 2: sending Encrypted Nonce and the public key of the receiver to the vehicle
        conn.send(pickle.dumps(message)) 
        # print("ECA: step 2: the sent data to the vehicle", message)

        # #Step 3: Receiving A||ExpiryPeriod||Encryption of the incremneted nonce from the Veghicle
        data = conn.recv(2048)         
        # print('ECA: step 3: received from Vehicle: ')
        # print(pickle.loads(data))  # show in terminal
        message=pickle.loads(data)
        A=message[0]
        ExpiryTime=message[1]
        Nonce_incremented_encrypted=message[2]
        
        #computing sigma_t
        message=DecryptENcrementedNonceComputingSigma_t(iv,ECA_key,Nonce,Nonce_incremented_encrypted,Receiver_Identity,Sender_Identity,A,ExpiryTime)

        # #Step 4: sending sigma_t, B, startTime to the vehicle
        conn.send(pickle.dumps(message)) 
        # print("ECA: step 4:The sent data to the vehicle", message)
             

def Encrypt_nonce_Send_Receiver_PublicKey(Nonce):
    # print("ECA: The nonce sent to the vehicle ", Nonce)
    iv = Random.new().read(AES.block_size)
    ECA_key=ECA_priv_key*Vehicle_pub_key
    Nonce_encrypted, ECA_EncKey= AES_Enc_using_Key(ECA_key,iv,Nonce)
    # print("ECA: The nonce encrypted",Nonce_encrypted)
    return iv, Nonce_encrypted, TMA_pub_key,ECA_key

def DecryptENcrementedNonceComputingSigma_t(iv,ECA_key,Nonce,Nonce_incremented_encrypted,Receiver_Identity,Sender_Identity,A,ExpiryTime):
    ReceivedIncrementedNonce, Vehicle_DecKey= AES_Dec_using_Key(ECA_key,iv,Nonce_incremented_encrypted)
    assert (Nonce+1)==ReceivedIncrementedNonce, "The authentication of the Vehicle with the ECA has failed"
    
    hash_sigma_a=Hash(ECA_sigma)
    h_tr=Hash(Sender_Identity,Receiver_Identity,hash_sigma_a,A.x,A.y)
    B=h_tr*ECA_pub_key

    # Compute I_p and sigma_t
    StartTime=int.from_bytes(os.urandom(1024),'big')%P256.q
    I_p=Hash(Receiver_Identity,StartTime,ExpiryTime)
    sigma_t=ECA_sigma+I_p*h_tr*ECA_priv_key+I_p*ECA_priv_key
    return sigma_t, B, StartTime

if __name__ == '__main__':
    ECA_program()
