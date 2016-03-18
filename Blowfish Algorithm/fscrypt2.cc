#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/blowfish.h"

const int BLOCKSIZE = 8;

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
	unsigned char *temp = (unsigned char *) malloc(bufsize--);
	int paddingLength = 0;
	temp = (unsigned char *) plaintext;
	int x=0,i=0,len=0,totLen=0;

	if((bufsize)%BLOCKSIZE > 0){
		paddingLength = (bufsize)%BLOCKSIZE;
		len=BLOCKSIZE-paddingLength;
	}
	totLen=bufsize+len;
	unsigned char pt[totLen];
	unsigned char *cipherText = (unsigned char *) malloc((totLen)*sizeof(unsigned char));
	unsigned char ivec[BLOCKSIZE];

	for(x=0;x<bufsize;x++){ pt[x]=temp[x]; }

	//Padding Logic
	i=bufsize;
	for(x=0;x<len;x++){
		pt[i++] = len + '0';
	}
	for(i=0;i<BLOCKSIZE;i++){ ivec[i] = '0'; }

	BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));
	BF_set_key(key, strlen(keystr),(unsigned char*) keystr);

	BF_cbc_encrypt((unsigned char *) pt, (unsigned char *) cipherText, bufsize, key, ivec, BF_ENCRYPT);

	*resultlen = totLen;
	return (void *) cipherText;
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){
	unsigned char *plainText = (unsigned char *) malloc(bufsize*sizeof(unsigned char));
	unsigned char ivec[BLOCKSIZE];
	plainText = (unsigned char *) ciphertext;
	
	for(int i=0;i<BLOCKSIZE;i++){	ivec[i] = '0';	}

	BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));
	BF_set_key(key, strlen(keystr),(unsigned char*) keystr);

	BF_cbc_encrypt((unsigned char*) plainText, (unsigned char*) plainText, bufsize, key, ivec, BF_DECRYPT);

	*resultlen = strlen((char *)plainText)+1;
	return (void *) plainText;
}
