Yash Divecha
**************************************************************************

PURPOSE: 
To implement Blowfish Algorithm using OpenSSL.
**************************************************************************

OPENSSL VERSION: 
OPENSSL 1.0.2d on Linux-x86_64. 

./Configure --prefix=/home/osboxes/openssl-1.0.2d/compiled linux-x86_64
**************************************************************************

IMPLEMENTATION: 
1. CBC mode using ECB Mode. 

2. CBC mode using BlowFish openssl library function.
**************************************************************************

ALGORITHM: 
1. Read Plain Text.

2. Divide the Plain Text into blocks. 

3. If required padd the characters to get the plain Text into multiple of blocks. 

4. Use ECB mode of encryption to implement CBC with the help of IV. 


5. From the returned Cipher Text, we perform decryption and get the paddded plaintext. 

6. Remove the padding to get the required Plain Text

**************************************************************************
