import os
import time
import joblib
import hashlib
from tlib import xorshift, tpcode

rand = xorshift.xorshift()


rand.setSeed(y=0xAF60547AC7ECF07E334A5F27805E0100)
print(hex(rand.xor128()))
#for i in range(10):
#	print(rand.uniform(end=16))

#print(os.urandom(16))


tc=tpcode.tpcord()

message = 'sampletext1234567890abcdefghijklmnopqrstuvwxyz!#$%&()=~-^[]{}/.,:;@'
password = '14.989157233151877'
header = os.environ['USERNAME']
data= tc.encrypt(message.encode(), password.encode(), header.encode())
print(data)

hed_o = hashlib.sha3_256(b"tatra python code key data")

#print(bytes.fromhex(hashlib.sha3_256(b"tatra python code key data").hexdigest()))
print(hed_o)
hed_h=hed_o.hexdigest()
print(hed_h)
hed_b=bytes.fromhex(hed_h)
print(hed_b)
print(b'\xe0\xa2l\xac\xa2T\x1bbs\xf4\x00oM\x1e\xa1a\xc4(\xc7X\x1c\xb7UC\xd7\xdas\x86\xc1\x11\xdcE'.hex())
with open('test.bin', "wb") as f:  
    joblib.dump(data, f, compress=3)

with open('test.bin', "rb") as f:  
    result = joblib.load(f)


print(result) 
version=b'00.01.01'
header=[
    bytes.fromhex("F0 0F 1A 0D 0A 1F 24 0A"),
    b'\xe0\xa2l\xac\xa2T\x1bbs\xf4\x00oM\x1e\xa1a\xc4(\xc7X\x1c\xb7UC\xd7\xdas\x86\xc1\x11\xdcE'
    b'ver.',version
]
print(header)
for b in result:
    print(b.hex())