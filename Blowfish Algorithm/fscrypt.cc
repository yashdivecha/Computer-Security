#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/blowfish.h"

const int BLOCKSIZE = 8;

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
	
	unsigned char *temp = (unsigned char *) malloc(bufsize*sizeof(unsigned char));
	int blocks = (bufsize-1)/BLOCKSIZE;
	temp = (unsigned char *) plaintext;
	int paddingLength = 0;
	
	//If length of the text is greater than multiple of BLOCKSIZE then padding needs to be done. 
	if((bufsize-1)%BLOCKSIZE > 0){
		paddingLength = (bufsize-1)%BLOCKSIZE;
		blocks++;
	}
	//printf("%d,%d\n",bufsize,paddingLength);
	unsigned char pt[blocks][BLOCKSIZE]; //Multidimentional array for storing bocks
	unsigned char *cipherText = (unsigned char *) malloc((blocks*BLOCKSIZE)*sizeof(unsigned char));
	unsigned char plaint[BLOCKSIZE],ciphert[BLOCKSIZE];
	int a=0,length=0,i=0, j=0, x=0;

	for(i=0;i<blocks;i++){
		for(j=0;j<BLOCKSIZE,a<bufsize-1;j++){
			pt[i][j] = temp[a++];
		}
	//printf("%s\n",pt[0]);
	}

	//Padding Logic
	for(x=paddingLength;x>0 && x<BLOCKSIZE-1;x++){
		pt[blocks-1][x] = (BLOCKSIZE-paddingLength-1) + '0';
	}
	//printf("%s\n",pt[0]);
	
	
	//Initialzing IV
	char iv = '0';
	for(i=0;i<BLOCKSIZE;i++){ ciphert[i] = iv; }
	
	for(a=0;a<blocks;a++){
		for(i=0;i<BLOCKSIZE;i++){
			plaint[i] = ciphert[i]^pt[a][i];
	}

	//Setting up the Key
	BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));
	BF_set_key(key, strlen(keystr),(unsigned char*)keystr);

	//Implementing CBC mode using ECB mode of encryption with the help of blow fish library.
	BF_ecb_encrypt((unsigned char*) plaint, (unsigned char*) ciphert, key, BF_ENCRYPT);

	for(i = 0; i < BLOCKSIZE; i++){ 
		cipherText[length++] = ciphert[i];
	       // printf("%02x ", outbuf[i]);     // Hex Value
		}
	}

	*resultlen = length;
	return (void *)cipherText;
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){
	
	unsigned char *temp = (unsigned char *) malloc(bufsize*sizeof(unsigned char));
	int blocks = (bufsize)/BLOCKSIZE;
	temp = (unsigned char *) ciphertext;
	unsigned char ct[++blocks][BLOCKSIZE]; 
	unsigned char *plainText = (unsigned char *) malloc((blocks*BLOCKSIZE)*sizeof(unsigned char));
	unsigned char plaint[BLOCKSIZE],ciphert[BLOCKSIZE];
	int a=0,y=0,length=0, f=0, b=0;
	char iv = '0';

	//Setting up IV
	for(int i=0;i<BLOCKSIZE;i++){ ct[0][i] = iv; }
	for(int i=1;i<blocks;i++){
		for(int j=0;j<BLOCKSIZE;j++){
			ct[i][j] = temp[a++];
		}
	}

	for(a=1;a<blocks;a++){
		for(int i=0;i<BLOCKSIZE;i++){
			ciphert[i] = ct[a][i];
		}
	
	//Setting up the Key
	BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));
	BF_set_key(key, strlen(keystr),(unsigned char*)keystr);

	//Implementing CBC mode using ECB mode with the help of blow fish library.
	BF_ecb_encrypt((unsigned char*) ciphert, (unsigned char*) plaint, key, BF_DECRYPT);
	
	for(int i=0;i<BLOCKSIZE;i++){ ciphert[i] = plaint[i]^ct[a-1][i]; }		
	
        for(int i = 0; i < BLOCKSIZE; i++){
		plainText[length++] = ciphert[i];
//	        printf("%02x ", outbuf[i]);     // Hex Value
		}
	}

	*resultlen = length+1;
if(length<8){ return (void *)plainText; }

	//Removing the padded characters logic
	int paddedChar = plainText[length-2] - '0';
	int paddedText = 0;
	length--;
	for(a=paddedChar;a>0;a--){
		if((plainText[--length]-'0')!=paddedChar){
			paddedText = 1;
			break;
		}
	}
	if(paddedText==1){return (void *)plainText; }
	else{
		unsigned char *finalPlainText = (unsigned char*) malloc(sizeof(unsigned char));
		for(b=0;b<length;b++){ 	finalPlainText[b] = plainText[b]; }
		*resultlen = length+1;
		return (void *)finalPlainText;
	}
}
