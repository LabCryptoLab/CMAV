

from fastecdsa.curve import Curve
from fastecdsa import curve, ecdsa, keys

from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from fastecdsa import curve, ecdsa, keys
from hashlib import sha384
import binascii

import hashlib
import os 
import time

import sys
sys.path.append(r'C:\Users\mahdy\OneDrive\Desktop\python_examples\CPMAVE\mypackage')
import primitives as foo


###############     ECA identity & Keys     ############################# 
ECA_Identity=int.from_bytes(os.urandom(1024),'big')%P256.q
ECA_priv_key, ECA_publicKey_i = keys.gen_keypair(curve.P256)

###############       Sender Vehicle Identity & Keys      ##################### 
Sender_Identity=int.from_bytes(os.urandom(1024),'big')%P256.q
Sender_priv_key, Sender_pub_key = keys.gen_keypair(curve.P256)

###############       Receiver TMA Identity & Keys      #####################
Receiver_Identity=int.from_bytes(os.urandom(1024),'big')%P256.q
Receiver_priv_key, Receiver_pub_key = keys.gen_keypair(curve.P256)

###############     The Generation of the KGC keys      ##################
KGC_1_priv_key, KGC_1_pub_key = keys.gen_keypair(curve.P256)
KGC_2_priv_key, KGC_2_pub_key = keys.gen_keypair(curve.P256)
KGC_3_priv_key, KGC_3_pub_key = keys.gen_keypair(curve.P256)

#############################################################################
##################     ECA_i Registration  with three distributed KGC  ######
#############################################################################

###########     ECA registration with 1st KGC      ##################
C_i_1, sigma_1, ECA_Yi_generated_KGC_1 = foo.Registration_With_KGC(KGC_1_priv_key)

###########     ECA registration with 2nd KGC      ##################
C_i_2, sigma_2, ECA_Yi_generated_KGC_2 = foo.Registration_With_KGC(KGC_2_priv_key)

###########     ECA registration with 3rd KGC      ##################
C_i_3, sigma_3, ECA_Yi_generated_KGC_3 = foo.Registration_With_KGC(KGC_3_priv_key)

###########     ECA credentials     ##################
ECA_sigma=(sigma_1+sigma_2+sigma_3)%P256.q
ECA_C_i=C_i_1+C_i_2+C_i_3
ECA_Y_i=ECA_Yi_generated_KGC_1+ECA_Yi_generated_KGC_2+ECA_Yi_generated_KGC_3

###########     The accumulated Public key      ##################
PK_g=KGC_1_pub_key+KGC_2_pub_key+KGC_3_pub_key

#############################################################################
#######    OBTAINING SIGNATURE FROM ECA   ###################################
#############################################################################

Nonce = int.from_bytes(os.urandom(1024),'big')%P256.q
iv = Random.new().read(AES.block_size)
ECA_key=ECA_priv_key*Sender_pub_key

Nonce_encrypted, ECA_EncKey= foo.AES_Enc_using_Key(ECA_key,iv,Nonce)

ExpiryPeriod=int.from_bytes(os.urandom(1024),'big')%P256.q

r_1 = int.from_bytes(os.urandom(1024),'big')%P256.q
# z_a = int.from_bytes(os.urandom(1024),'big')%P256.q
A = r_1*P256.G

###############     Decryption of the nonce using H(privateVehicle_publicECA)   #########
vehicle_key=Sender_priv_key*ECA_publicKey_i
Nonce_decrypted, Vehicle_DecKey= foo.AES_Dec_using_Key(vehicle_key,iv,Nonce_encrypted)
Nonce_incremented=Nonce_decrypted+1

###############     Encryption of the Nonce+1  on the Vehicle   #############################
Nonce_incremented_encrypted, Vehicle_EncKey= foo.AES_Enc_using_Key(vehicle_key,iv,Nonce_incremented)

#############       Decryption of the nonce on the ECA      ##############################
ReceivedIncrementedNonce, Vehicle_DecKey= foo.AES_Dec_using_Key(ECA_key,iv,Nonce_incremented_encrypted)

############################################################################################
hash_sigma_a=foo.Hash(ECA_sigma)
h_tr=foo.Hash(Receiver_Identity,Sender_Identity,hash_sigma_a,A.x,A.y)
B=h_tr*ECA_publicKey_i

# Compute I_p and sigma_t
StartTime = int.from_bytes(os.urandom(1024),'big')%P256.q
I_p=foo.Hash(Receiver_Identity,StartTime,ExpiryPeriod)
sigma_t=I_p*ECA_sigma+h_tr*ECA_priv_key+ECA_priv_key

print("The verification of the vehicle authentication token",sigma_t*P256.G==(I_p*PK_g+I_p*ECA_C_i+I_p*ECA_Y_i+B+ECA_publicKey_i))

################################################################################
###########   UAV sending Msg to Authority   ###################################
################################################################################

r_2 = int.from_bytes(os.urandom(1024),'big')%P256.q
r_3 = int.from_bytes(os.urandom(1024),'big')%P256.q

Msg_to_Send = int.from_bytes(os.urandom(1024),'big')%P256.q
Msg_encrypted, Vehicle_EncKey= foo.AES_Enc_using_Key(vehicle_key,iv,Msg_to_Send)
print("The Msg to encrypt on the vehicle", Msg_to_Send)


P_1= r_2*PK_g
P_2= r_2*ECA_C_i
P_3= r_2*ECA_Y_i
P_4= r_2*ECA_publicKey_i
P_5= r_2*B
T_1=r_3*PK_g

# The message decrypted
MsgDecrypted, ECA_DecKey= foo.AES_Dec_using_Key(ECA_key,iv,Msg_encrypted)
print("The decrypted Msg on the ECA", MsgDecrypted)


I_c=foo.Hash(A.x,A.y,P_1.x,P_1.y,P_2.x,P_2.y,P_3.x,P_3.y,P_4.x,P_4.y,P_5.x,P_5.y,T_1.x,T_1.y)
sigma_2= (r_2*sigma_t+I_c*r_1)%P256.q
s_1=(r_3+I_c*r_2)%P256.q

print("The verification of s_1",s_1*PK_g==(T_1+I_c*P_1))
print("The verification of sigma_2",sigma_2*P256.G==(I_p*P_1+I_p*P_2+I_p*P_3+P_4+P_5+I_c*A))