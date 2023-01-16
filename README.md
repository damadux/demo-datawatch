 - The folder ptrace-implementation contains the necessary files for the datawatch implementation using ptrace and the fork system call.
 - The folder ptrace-clone-implementation contains the necessary files for the datawatch implementation using ptrace and the clone system call.
 
 
 For each different implementation, steps to run it are the same:
 
 - Use the makefile ("make") to generate the static library.
 - <div>Export the LD_LIBRARY_PATH to this directory, such that the static library can be linked correctly.</div> 
 - Run the run.sh shell script to execute a small example using the library.
 
 
Dependencies:

 - Capstone
 
