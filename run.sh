gcc -c -Wall -fPIC -g dwhooks.c -o dwhooks.o
gcc -shared -g -o libdw.so dwhooks.o
#export LD_LIBRARY_PATH=/home/nassirim/projects/datawatch
gcc -L . -Wall -Wextra -g -o test-malloc test.c -ldw
