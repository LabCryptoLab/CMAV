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
import csv

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

#############################  TMA Identity   ###########################################

TMA_Identity= 8169104755805935683608881213542562938956147541291769502712984486856835317573

TMA_pub_key_X= 0x6880bbbb54c1a66f3618249d550fa629ec31eece9a3be989e6093ac1b790dbb2
TMA_pub_key_Y= 0xa315167d2f09b9a27b0fe53fc96b47eea13bc8deaea8c50cabde9428e8683d03
TMA_pub_key=Point(TMA_pub_key_X, TMA_pub_key_Y, curve=P256)

############################   Vehicle Identity  ########################################

Vehicle_Identity= 6330614295947393657856040725909354215571545936334951160496604125994438196162

Vehicle_priv_key= 62718740499567001559645896635471998470595369862886026081752443059900420476791

Vehicle_pub_key_X= 0xf81cc47e2caf24468ddf86ab9279c14bae235a07c5c2f960a1ba395ffc14d2b6
Vehicle_pub_key_Y= 0xd8d7dab908578b5aa9f87118662117587bd44f38b8d67eb0e9b4439f04f8a723
Vehicle_pub_key=Point(Vehicle_pub_key_X, Vehicle_pub_key_Y, curve=P256)

###########################    ECA Identity  ##########################################

ECA_priv_key= 27035679567817885497930140100479440063071582958031951165314744143627511123473
ECA_pub_key_X= 0x6aadbccb88ad8839c21e7a3754e42f7281eeb2b75a07358f6889eef9030c1793
ECA_pub_key_Y= 0x869e40c7c429fa96ddc6ad3576224ff5bd95c55a68224a0d1f734e4786443af5
ECA_pub_key=Point(ECA_pub_key_X, ECA_pub_key_Y, curve=P256)

ECA_C_i_X= 0xb617e0900b2d6304a11d7a99e27e7498483b6563b47c1ee06dd2dc73e62408fb
ECA_C_i_Y= 0x90dcbf5075f41420fc7a51b078dfbe2a1b401d6d431e7df45072a8134186cae6
ECA_C_i=Point(ECA_C_i_X, ECA_C_i_Y, curve=P256)

ECA_Y_i_X= 0x3dda16e64b2fde142872b07e2a28271ac3b014425e15575caa405bdfb6052b94
ECA_Y_i_Y= 0xc797bb1d4a12fedc152c3b2aedb1f34a12537b6b5ec388502bdc2825565d2d
ECA_Y_i=Point(ECA_Y_i_X, ECA_Y_i_Y, curve=P256)

PK_g_X= 0x6d1973e8554c68424fc51542ff8b0fe6a84bd7c88f2e2f19f4d0712a13604d55
PK_g_Y= 0xe64e6122ce7a70e26f7496510ea93fb5730a9894448d1a6b4bd15da8c08cfdc0
PK_g=Point(PK_g_X, PK_g_Y, curve=P256)

###########################################################################

A = P256.G
B = P256.G
ExpiryPeriod=int.from_bytes(os.urandom(1024),'big')%P256.q


parser = argparse.ArgumentParser(description = 'Client for IoT Simulation')
parser.add_argument('-c', '--connect', default="127.0.0.1", help='CA server to connect to') 
args = parser.parse_args()


def Vehicle_program():



    # #####################################################################################################
    # # Number of runs for calculation
    num_runs = 10000
    file_name = 'output_timing.csv'
    # Arrays to store times
    eca_times = []
    tma_times = []





    # Perform communication and store times in arrays
    for _ in range(num_runs):
        print("Start run: ", _)
        eca_result, tma_result = Phase1_2()
        #print("Done run: ", _)
        eca_times.append(eca_result)
        tma_times.append(tma_result)

    # Calculate average times
    eca_average_time = sum(eca_times) / num_runs
    tma_average_time = sum(tma_times) / num_runs

    print("Average time for communication with ECA:", eca_average_time)
    print("Average time for communication with TMA:", tma_average_time)

    # Open the file in write mode ('w') and create a csv.writer object
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write column headers
        writer.writerow(['Phase1', 'Phase2'])

        # Combine the two arrays into rows and write them
        for row in zip(eca_times, tma_times):
            writer.writerow(row)

    print(f'Timings have been written to {file_name}')




def Phase1_2():    
    ECA_socket = socket.socket()  # get instance    
    TMA_socket = socket.socket()  # get instance

        # get the hostname
    bind_address_eca = '192.168.122.202'
    eca_port = 5000  # initiate port no above 1024
    # host = args.connect # CA server
        
    ECA_socket.connect((bind_address_eca, eca_port))  # connect to the server
    # print("Vehicle: Creating new socket for the TMA")
    bind_address_tma = '192.168.122.200'
    tma_port = 5001  # initiate port no above 1024

    # # Step 5: Sending ID_r, A, P_1, P_2, P_3, P_4, P_5, T_1, Sigma_2, s_1, startTime, ExpiryPeriod to the TMA
    TMA_socket.connect((bind_address_tma, tma_port))  # connect to the server


    # PHASE 1
    Phase1StartTime = time.time()

    # step 1: sending Identity of the sender and receiver to the ECA
    message = SendID_Sender_Receiver()
    ECA_socket.send(pickle.dumps(message))    
    # print('Vehicle: step 1: sent to ECA: ' + str(message))

    # step 2: Receiving the encrypted nonce from the PAS
    data = ECA_socket.recv(2048)         
    # print('Vehicle: step 2: received from ECA: ')
    # print(pickle.loads(data))  # show in terminal

    message=pickle.loads(data)         
    iv=message[0]
    # # does the decryption and the increment of the nonce
    
    r_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
    A = r_1*P256.G
    message = Send_A_IncrementedNonce(message[0],message[1])
    ExpiryPeriod=message[1]

    # # Step 3: sending A and the encrypted incremented nonce to the ECA
    ECA_socket.send(pickle.dumps(message))    
    # print('Vehicle: step 3: sent to ECA: ' + str(message))

    # # Step 4: Receiving sigma_1, B, StartTime
    data = ECA_socket.recv(2048)         
    # print('Vehicle: step 4: received from ECA: ')
    # print(pickle.loads(data))  # show in terminal
    message=pickle.loads(data)
    sigma_t=message[0]
    B = Point(message[1].x, message[1].y, curve=P256)
    StartTime=message[2]

    # # Compute I_p and verify sigma_t
    I_p=Hash(TMA_Identity,StartTime,ExpiryPeriod)
    assert sigma_t*P256.G==(PK_g+ECA_C_i+ECA_Y_i+I_p*B+I_p*ECA_pub_key), "Vehicle: Verification of generated sigma_t has failed"

    Phase1EndTime = time.time()
    Phase1Time=Phase1EndTime-Phase1StartTime

    print("Phase 1 time:", Phase1Time)
    
    # PHASE 2
    phase2StartTime = time.time()
  
    message=computeSigma2_s1(sigma_t, r_1, I_p, B, A, StartTime, ExpiryPeriod, iv)
    TMA_socket.send(pickle.dumps(message)) 
    # print(pickle.loads(data))  # show in terminal
    # print('Vehicle: step 4: sent to ECA: ' + str(message))

    # # Step 4: Receiving sigma_1, B, StartTime
    data = TMA_socket.recv(2048)         
    # print('Vehicle: step 5: received from TMA: ')
    # print(pickle.loads(data))  # show in terminal
    
    phase2EndTime= time.time()
    Phase2Time=phase2EndTime-phase2StartTime
    print("Phase 2 time:", Phase2Time) 
    ECA_socket.close()
    TMA_socket.close()
    return Phase1Time, Phase2Time
 
def SendID_Sender_Receiver():
    return Vehicle_Identity, TMA_Identity

def Send_A_IncrementedNonce(iv,Nonce_encrypted):
    vehicle_key=Vehicle_priv_key*ECA_pub_key
    # print("VEhicle: The received nonce encrypted", )
    Nonce_decrypted, Vehicle_DecKey= AES_Dec_using_Key(vehicle_key,iv,Nonce_encrypted)
    # print("The decrypted received nonce :", Nonce_decrypted)
    Nonce_incremented=Nonce_decrypted+1
    # print("The incremented nonce :", Nonce_incremented)
    ExpiryPeriod=int.from_bytes(os.urandom(1024),'big')%P256.q
    Nonce_incremented_encrypted, Vehicle_EncKey= AES_Enc_using_Key(vehicle_key,iv,Nonce_incremented)

    return A, ExpiryPeriod, Nonce_incremented_encrypted

def computeSigma2_s1(sigma_t, r_1, I_p, B, A, StartTime, ExpiryPeriod, iv):
    r_2 = int.from_bytes(os.urandom(1024),'big')%P256.q
    r_3 = int.from_bytes(os.urandom(1024),'big')%P256.q

    P_1= r_2*PK_g
    P_2= r_2*ECA_C_i
    P_3= r_2*ECA_Y_i
    P_4= r_2*ECA_pub_key
    P_5= r_2*B
    T_1=r_3*PK_g

    I_c=Hash(A.x,A.y,P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,P_5.x,P_5.y,T_1.x,T_1.y)
    sigma_2= (r_2*sigma_t+I_c*r_1)%P256.q
    s_1=(r_3+I_c*r_2)%P256.q

    Msg_to_Send = int.from_bytes(os.urandom(1024),'big')%P256.q
    vehicle_key=r_1*TMA_pub_key
    Msg_encrypted, Vehicle_EncKey= AES_Enc_using_Key(vehicle_key,iv,Msg_to_Send)
    # print("The Msg to encrypt on the vehicle", Msg_to_Send)


    return A, P_1, P_2, P_3, P_4, P_5, T_1, StartTime, ExpiryPeriod, s_1, sigma_2, iv, Msg_encrypted

if __name__ == '__main__':
    Vehicle_program()