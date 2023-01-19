dwhooks-preload-clone:
	gcc -c -Wall -fPIC -g dwhooks-ptrace-clone.c -o dwhooks-ptrace-clone.o
	gcc -shared -g -o libdw-clone.so -lcapstone dwhooks-ptrace-clone.o

clean:
	-rm *.o *.so
