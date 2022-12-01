all: KN_Cipher

KN_Cipher:
	gcc -o KN_Cipher main.c

clean:
	rm KN_Cipher
