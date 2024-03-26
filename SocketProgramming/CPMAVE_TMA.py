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

A = P256.G
P_1 = P256.G
P_2 = P256.G
P_3 = P256.G
P_4 = P256.G
P_5 = P256.G
T_1 = P256.G


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

#ECA identities from registration.py

import json

#########################################################################################
####################      Data Registration       #######################################
#########################################################################################


###########################     TMA Data      ###########################################

TMA_Identity= 8169104755805935683608881213542562938956147541291769502712984486856835317573
TMA_priv_key= 3822204222889312141452796624401703944169653051092257917058141841645549240302
TMA_pub_key_X= 0x6880bbbb54c1a66f3618249d550fa629ec31eece9a3be989e6093ac1b790dbb2
TMA_pub_key_Y= 0xa315167d2f09b9a27b0fe53fc96b47eea13bc8deaea8c50cabde9428e8683d03
TMA_pub_key=Point(TMA_pub_key_X, TMA_pub_key_Y, curve=P256)

########################    The ECA public key      ######################################

PK_g_X= 0x6d1973e8554c68424fc51542ff8b0fe6a84bd7c88f2e2f19f4d0712a13604d55
PK_g_Y= 0xe64e6122ce7a70e26f7496510ea93fb5730a9894448d1a6b4bd15da8c08cfdc0
PK_g=Point(PK_g_X, PK_g_Y, curve=P256)


# The Socket programming
parser = argparse.ArgumentParser(description = 'Client for IoT Simulation')
parser.add_argument('-c', '--connect', default="127.0.0.1", help='server to connect to') 
parser.add_argument('-i', '--iterations', default=1, help='how many tim to run') 
args = parser.parse_args()

def TMA_program():

    Veh_socket = socket.socket()  # instantiate
    # host = args.connect # as both code is running on same pc
    # iterations = int(args.iterations) # how many time to run
    bind_address = '192.168.122.200'
    port = 5001  # socket server port number

    # look closely. The bind() function takes tuple as argument
    Veh_socket.bind((bind_address, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    Veh_socket.listen(10)
    
    # i = 0

    while True:
    
        conn, address = Veh_socket.accept()  # accept new connection
        #print("TMA: Connection from: " + str(address))
        # message = ""
        #Step 1: Receive Gateway_Identity, G_nonce, G_sigma_1, G_sigma_2, Epison_1_1, Epison_1_2, Epison_1_3, Epison_1_4, Epison_1_5 from the gateway
        
        data = conn.recv(2048)         
        #print('TMA: The received data from the vehicle: ')
        #print(pickle.loads(data))  # show in terminal
        message=pickle.loads(data)  
        # print('TMA: Message 0: ', message[0])
        A = Point(message[0].x, message[0].y, curve=P256)
        P_1 = Point(message[1].x, message[1].y, curve=P256)
        P_2 = Point(message[2].x, message[2].y, curve=P256)
        P_3 = Point(message[3].x, message[3].y, curve=P256)
        P_4 = Point(message[4].x, message[4].y, curve=P256)
        P_5 = Point(message[5].x, message[5].y, curve=P256)
        T_1 = Point(message[6].x, message[6].y, curve=P256)
        StartTime = message[7]
        ExpiryPeriod = message[8]
        s_1=message[9]
        sigma_2=message[10]
        iv=message[11]
        Msg_encrypted=message[12]

        # The message decrypted
        TMA_key=TMA_priv_key*A
        MsgDecrypted, ECA_DecKey= AES_Dec_using_Key(TMA_key,iv,Msg_encrypted)
        # print("The decrypted Msg on the TMA", MsgDecrypted)
        I_c=Hash(A.x,A.y,P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,P_5.x,P_5.y,T_1.x,T_1.y)
        I_p=Hash(TMA_Identity,StartTime,ExpiryPeriod)
        assert s_1*PK_g==(T_1+I_c*P_1), "TMA: Verification of s_1 failed"
        assert sigma_2*P256.G==(P_1+P_2+P_3+I_p*P_4+I_p*P_5+I_c*A), "TMA: Verification of sigma_2 failed"
        # print("TMA: The protocol pass the authentication process")

        
        message="Ack: The Message has been delivered"
        conn.send(pickle.dumps(message)) 
        # print('TMA: step 2: sent to Vehicle: ' + str(message))
        
        
        
          
        

# def verifySigma2DecryptMessage(A, P_1, P_2, P_3, P_4, P_5, T_1, StartTime, ExpiryPeriod, s_1, sigma_2):
#     I_c=Hash(A.x,A.y,P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,P_5.x,P_5.y,T_1.x,T_1.y)
#     I_p=Hash(TMA_Identity,StartTime,ExpiryPeriod)
#     assert s_1*PK_g==(T_1+I_c*P_1), "TMA: Verification of s_1 failed"
#     assert sigma_2*P256.G==(P_1+P_2+P_3+I_p*P_4+I_p*P_5+I_c*A), "TMA: Verification of sigma_2 failed"

#     return VehicleMessage

    
if __name__ == '__main__':
    TMA_program()
