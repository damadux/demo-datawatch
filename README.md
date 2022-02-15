Compile this with these commands:



gcc -c -Wall -fPIC dwhooks-clean.c -o dwhooks-clean.o

gcc -shared -o libdw.so dwhooks-clean.o

export LD_LIBRARY_PATH=/path-here/demo-datawatch:$LD_LIBRARY_PATH

gcc -L/path-here/demo-datawatch -Wall -Wextra -o test-malloc test.c -ldw

./test-malloc
