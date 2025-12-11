oys103@hwsec7:~/week1/uarch/io$ cat g.sh 
#!/bin/bash

# Compile with optimization and native architecture support
# -pthread is needed because the code uses thread/process management
gcc giovi.c -o giovi -O2 -no-pie -march=native -pthread

if [ $? -ne 0 ]; then
    echo "[-] Compilation failed."
    exit 1
fi

# Run the executable
# The C code handles core pinning internally!
./giovi
