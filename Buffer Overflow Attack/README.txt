Yash Divecha
Buffer OverFlow Attack

Buffer overflow, is an anomaly where a program, while writing data to a buffer, overruns the buffer's boundary and overwrites adjacent memory locations.
***********************************************************************************************************************************************
How to Compile:
Created make file 
	gcc ./vuln_program.c -fno-stack-protector -z execstack -static -o vuln_program
	gcc -g -o ./attack.string attack.string.c

and make clean
	rm -rf attack.string vuln_program attack.input

***********************************************************************************************************************************************
How to Run: 

Use below mentioned commands: 
//(Target address can be changed according to the system and attack string contains number of string that can be used to overflow the buffer)
$  --> ./attack.string $'\x1c\x8c\x04\x08' > attack.input   

// Provide attach.input to the executable to overflow the buffer.
$  --> ./vuln_program <  attack.input 			    

***********************************************************************************************************************************************









