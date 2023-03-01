LD_PRELOAD=./libdw-clone.so DW_POINTER_METHOD=5 DW_TRACE_SYSCALL=1 DW_ADDRESS_METHOD=$1 tar cvf toto.tgz *.c 2>errors1.tmp

