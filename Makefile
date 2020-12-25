main : main.c
	gcc -Wall -o yaids main.c populate.c -lpcap -lpcre
