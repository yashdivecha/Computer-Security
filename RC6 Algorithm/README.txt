Yash Divecha
***********************************************************************************************************************************

PURPOSE: To implement RC6 Symmetric key Block Cipher Algorithm.
***********************************************************************************************************************************

COMPILE: 
Command: make
***********************************************************************************************************************************

EXECUTE: 
java RC6 input.txt output.txt
***********************************************************************************************************************************

CONVENTIONS: 
1. Depending upon the first line, it identifies whether it is an encryption or decryption.
2. Plain Text or User Text or Cipher Text should follow by colon [ : ] 
3. File Reading:Reads arg[0] as the input file and arg[1] as the output file. 
***********************************************************************************************************************************

IMPLEMENTATION: 
-- Checks for the operation in the 1st Line [Encryption/Decryption]

-- IF ENCRYPTION then checks for the colon ":" and puts into plain text
-- checks for the colon in the next line ":" and puts into user key

-- IF DECRYPTION then checks for the colon : and puts into cipher text
-- checks for the colon in the next line ":" and puts into user key
***********************************************************************************************************************************

ALGORITHM:

Major Functions: 

1. KeySchedule
INPUT: UserKey[], Round Value, b bytes
OUTPUT: w-bit round keys S[]
-> Computes L and initialises S
-> Does the Mixing of S

2. Encryption:
INPUT: PlainText[A,B,C,D], S and Round Value
OUTPUT: Cipher Text [A,B,C,D]

3. Decryption
INPUT: CipherText[A,B,C,D], S and Round Value
OUTPUT: PlainText [A,B,C,D]
 
***********************************************************************************************************************************
