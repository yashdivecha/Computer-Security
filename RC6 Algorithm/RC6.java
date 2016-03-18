
/***** 	Implementation : RC6 
 * 		Author: YASH DIVECHA
 * 	   	Email : ydivech1@binghamton.edu 
 *****/

import java.io.*;
import java.util.Scanner;

public class RC6 {
	static int r = 20, w=32;
	static int A,B,C,D;
	static int P32=0xb7e15163, Q32=0x9e3779b9;
	static int t = 2 * r + 4;
	static int S[];
	static int u = w/8;  

	private static int rotRight(int value, int shift)
	{
	return (value >>> shift) | (value << (32-shift));
	}
	
	private static int rotLeft(int value, int shift)
	{
	return (value << shift) | (value >>> (32-shift));
	}
	
	public static int[] KeySchedule(int userKey[], int r, int b){
	
		int u = w/8; 		// number of bytes/word
		int c = b/u; 		// Words
	
		/******* Generation of L *********/
		int [] L = new int[c];
		for(int i=0;i<c;i++)
		{L[i] = 0x00;}
	
		for (int i = 0, counter = 0; i < c; i++){
		L[i] = ((userKey[counter++] )) | ((userKey[counter++] ) << 8)| ((userKey[counter++] ) << 16) | ((userKey[counter++] ) << 24);
		}
		
		/******* Initialization the Array S *********/
		int[] S = new int[t];
		
		S[0] = P32;
		for(int i=1; i<t; i++){
			S[i] = S[i-1] + Q32; 
		}
		
		/******** Mixing in the Secret Key *****/
		 A = 0;
		 B = 0;
		int i=0, j = 0;
		
		int v = 3 * Math.max(L.length, S.length);
		for (int s = 0; s < v; s++) {
			A = S[i] = rotLeft((S[i] + A + B), 3);
			B = L[j] = rotLeft(L[j] + A + B, A + B);
			i = (i + 1) % S.length;
			j = (j + 1) % L.length;
		}
		return S;
}
	
	/*** As Cipher Text displays in the reverse order post Encryption, this function rearranges Cipher Text.  ***/	
	public static int arrangePostEncrypt(int data){ 	
		int block = 0x00;		
		for(int i=0;i<4;i++){
			block = ((data>>24)& 255) + ((data<<8)&(255*256*256)) 
					+ ((data>>8)& (255*256)) + ((data<<24)&255*256*256*256); 
		}
		return block;
	}
	
	/*** As  Test is in the reverse order decryption, this function rearranges Text ***/
	public static int arrangeText(int data){ 
		int block = (data << 24) >> 0;

		for(int i=2;i<=4;i++){
		block = ((data<<24)&(255*256*256*256)) + ((data>>8)& (255*256)) 
				+ ((data<<8)&(255*256*256)) + ((data>>24)& 255); 
		}
		return block;
	}

	public static int[] Encryption(int A, int B, int C, int D, int S[], int r){ 
		
		A = arrangeText(A);
		B = arrangeText(B);
		C = arrangeText(C);
		D = arrangeText(D);
		
		B = B + S[0];
		D = D + S[1];
		
		for(int i=1; i<=r; i++)
		{
			t = rotLeft( B *(2 * B + 1), 5 );
			u = rotLeft( D *(2 * D + 1), 5 );
			A = rotLeft((A ^ t), u ) + S[2 * i];
			C = rotLeft((C ^ u), t ) + S[2 * i + 1];
			t = A; A=B; B=C; C=D; D=t;
		}
		
		A = A + S[2*r+2];
		C = C + S[2*r+3];		
		//System.out.print(Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");
		
		//As Cipher Text doesn't come in the proper sequence, we need to rearrange to get the desired Cipher Text 
		A = arrangePostEncrypt(A);
		B = arrangePostEncrypt(B);
		C = arrangePostEncrypt(C);
		D = arrangePostEncrypt(D);
		
		//System.out.print(Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");			
		
		return new int[] { A, B, C, D }; 
	}
	
	public static int[] Decryption(int A, int B, int C, int D, int S[], int r){ 
		
		A = arrangeText(A);
		B = arrangeText(B);
		C = arrangeText(C);
		D = arrangeText(D);
	
//		System.out.print(Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");
		C = C - S[2*r+3];
		A = A - S[2*r+2];
		for(int i=2*r+2;i>2;)
		{
			t = D; D = C; C = B; B = A; A = t;
			u = rotLeft( D*(2*D+1), 5 );
			t = rotLeft( B*(2*B+1), 5 );
			C = rotRight( C-S[--i], t ) ^ u;
			A = rotRight( A-S[--i], u ) ^ t;
		}
		D = D - S[1];
		B = B - S[0]; 
		
		A = arrangeText(A);
		B = arrangeText(B);
		C = arrangeText(C);
		D = arrangeText(D);
		
//		System.out.print(Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");
		return (new int[] { A, B, C, D });
	}
	
	public static void main(String [] args) throws Exception{
	
		/****** Reading File *****/
		Scanner rd = new Scanner(new FileInputStream(args[0]));
		String operation = rd.nextLine();    // Reads Encryption/Decryption
		
		if(!operation.replaceAll(" ", "").startsWith("Decryption") && !operation.replaceAll(" ", "").startsWith("Encryption"))
			{ System.out.println("Please enter a valid operation (Encryption/Decryption) in the first Line.");System.exit(1); }
	
		/****** PlainText ******/
		String plainTextFull = rd.nextLine().replaceAll("\\s","");
		String plainText = plainTextFull.substring(plainTextFull.indexOf(":")+1);
//		String plainText = "52 4e 19 2f 47 15 c6 23 1f 51 f6 36 7e a4 3f 18".replaceAll("\\s", "");
//		String plainText = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replaceAll("\\s", "");
	
		
		/****** User Key ******/
		String userKeyFull = rd.nextLine().replaceAll("\\s","");
		String userKey = userKeyFull.substring(userKeyFull.indexOf(":")+1);
//		String userKey = "01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78 89 9a ab bc cd de ef f0 10 32 54 76 98 ba dc fe".replaceAll("\\s", "");
//		String userKey = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replaceAll("\\s", "");
		
		/*** This divides given String into Integer String [1 byte each] and stores into ukInput. ***/ 
		int b = (userKey.length()/2);
		int ukInput[] = new int[b];
		for(int i=0;i<userKey.length()/2;i++){
			ukInput[i] = Integer.parseInt(userKey.charAt(i*2) + "" , 16 );
			ukInput[i] = rotLeft( ukInput[i], 4);
			ukInput[i] = ukInput[i] + Integer.parseInt( userKey.charAt(i*2+1) + "", 16);
		}
	
		int K[] = ukInput;
		S = KeySchedule(K,r, b);
		
		rd.close();
	
	/*** This divides given String into Integer String [1 byte each] and stores into ptInput. ***/ 
		int num = plainText.length()/2;
		int [] ptInput = new int[num];
		for(int i=0;i<num;i++)
		{
			ptInput[i] = Integer.parseInt(plainText.charAt(i*2) + "" , 16 );
			ptInput[i] = rotLeft(ptInput[i], 4);	
			ptInput[i] = ptInput[i] + Integer.parseInt(plainText.charAt(i*2+1) + "", 16);
		}

		int length = ptInput.length/4;
			
		/*** Generation of  A ***/
		A = 0x00;
		for(int i=0;i<length;i++){
			A = rotLeft(A, 8) + ptInput[i];
		}
		//System.out.println("A = "+ Integer.toHexString(A));
		
		/*** Generation of  B ***/
		B = 0x00;
		for(int i = length; i<length*2;i++){
			B = rotLeft(B, 8) + ptInput[i];
		}
		//System.out.println("B = "+ Integer.toHexString(B));
		
		/*** Generation of  C ***/
		C = 0x00;
		for(int i=length*2 ;i<length*3;i++){
			C = rotLeft(C, 8) + ptInput[i];
		}
		//System.out.println("C = "+ Integer.toHexString(C));
		
		/*** Generation of  D ***/
		D = 0x00;
		for(int i=length*3;i<length*4;i++){
			D = rotLeft(D, 8) + ptInput[i];
		}
		//System.out.println("D = "+ Integer.toHexString(D));
		
		if(operation.replaceAll(" ", "").startsWith("Encryption"))
			{
				int ct[] = Encryption(A, B, C, D ,S, r);
		
				StringBuffer outStr = new StringBuffer("Ciphertext:");
				for(int i=0;i<ct.length;i++){
					for(int j=0;j<7;j++){
						outStr.append(" ").append(Integer.toHexString(ct[i]).substring(j, j+2) );
						j++;
					}
				}
		
				File outFile = new File(args[1]);
				FileOutputStream fout = new FileOutputStream(outFile);
				fout.write(outStr.toString().getBytes());
				fout.close();
			
//				System.out.println(outStr);
			}
		else if(operation.replaceAll(" ", "").startsWith("Decryption"))
			{
//		System.out.print(Integer.toHexString(A)+" "+Integer.toHexString(B)+" "+Integer.toHexString(C)+" "+Integer.toHexString(D)+" \n");
				int pt[] = Decryption(A, B, C, D ,S, r);
		
				StringBuffer outStr = new StringBuffer("Plaintext:");
				
				for(int i=0;i<pt.length;i++){
					int outTextLen = 0;
					for(int k= Integer.toHexString(pt[i]).length() ;k<8;k++){
						if( (outTextLen) %2 == 0)
						{	outStr.append(" 0");
							outTextLen++;
						}
						else
						{	outStr.append("0");
							outTextLen++;
						}
					}
					
					for(int j=0;j<Integer.toHexString(pt[i]).length();j++){
						if( (outTextLen) %2 == 0){
							outStr.append(" ").append(Integer.toHexString(pt[i]).substring(j, j+1));
							outTextLen++;
						}else{
							outStr.append( Integer.toHexString(pt[i]).substring(j, j+1) );
							outTextLen++;
						}
					}
					
				}
				File outFile = new File(args[1]);
				FileOutputStream fout = new FileOutputStream(outFile);
				fout.write(outStr.toString().getBytes());
				fout.close();
				
//				System.out.println(outStr);
			}
	}
}
