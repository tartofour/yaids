main : main.c
	gcc -Wall -o main main.c populate.c -lpcap -lz
