# CPMAVE
This is a python implementation of our protocol CP-MAVE: Conditional Privacy-preserving Message Authentication protocol for VANET Emergency message exchange. Our implementation consists of three parts.

## The Cryptographic Overhead Timing
A Python program to calculate the cryptographic overhead time, which comes from the cryptographic primitives in our protocol, such as the SHA-256 hash function, HMAC function, random number generation, AES-CBC mode encryption, Fractional Hamming Distance, EC point addition, EC scalar multiplication, and bilinear pairing. The measurements were reported based on the performance on the Raspberry Pi 4 equipped with a 1.5 GHz 64-bit Quad-core ARM Cortex-A72 processor running Raspbian GNU/Linux 11 (bullseye) with Python 3.9.2.

### Running on Raspberry Pi 4
First, install the requirements:
```
pip install -r requirements.txt
```

Run the cryptographic primitives on the Raspberry Pi 4. The results will be stored in `PrimitiveComputationTime {iteration}.txt`

```
cd "Raspberry Pi 4 Computation"
python3 computationTime.py <# of iterations>
```


## The Protocol Implementation
A Python implementation of the protocol where the registration for an ECA "Enterprise Certificate Authority" is done. Afterwards, the protocol is executed between the sender vehicle and the ECA. Then, the vehicle sends the VANET Emergency message to the TMA "Traffic Managment Agency". This implementation shows the completeness of our the protocol and the receiving of the message by the TMA.

### Running the protocol on the Laptop:
```
cd "CPMAVE Implementation"
python3 CPMVAE.py
```

## The Socket Programming
A Python socket programming implementation of CPMAVE to simulate the flow of our protocol messages between the sender vehicle and the TMA in a real-time experiment and to measure the end-to-end latency. The Raspberry Pi 4 is used to simulate the OBU "On Board Unit" of the sender vehicle while two Lenovo ThinkStations with 16GB of memory and an Intel 8-Core i7-10700 CPU clocked at 2.90GHz acted as the ECA and the TMA, respectively. 

The Raspberry Pi 4 and the two Thinkstations are connected to a local network. The static IP addresses for the TMA, vehicle, and ECA are set to 192.168.122.200, 192.168.122.201, and 192.168.122.202, respectively. Additionally, the communication between the ECA and the vehicle occurs over port 5000, while the communication between the TMA and the vehicle occurs over port 5001.

### Running the Socket Programming
Start the ECA on the ThinkStation. The ECA will listen on port 5001:
```
cd "Socket Programming"
python3 CPMAVE_ECA.py
```
Start the TMA on the ThinkStation. The gateway will listen on port 5000. 
```
cd "Socket Programming"
python3 CPMAVE_TMA.py
```

Start the sender vehicle on the Raspberry Pi 4.
```
cd "Socket Programming"
python3 CPMAVE_Vehicle.py
```
 
