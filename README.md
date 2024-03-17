# Rainbow-Table-Generator

This project is a Rainbow Table Generator. A Rainbow Table is a precomputed table for reversing cryptographic hash functions, usually for cracking password hashes. This generator will allow you to create your own rainbow tables based on your specific needs. It's designed to be efficient and easy to use, providing a valuable tool for cybersecurity professionals and enthusiasts alike.It supports SHA1, SHA256, SHA512 hashing styles.

## Complie
To complie this project with `g++` compiler
```
g++ .\rainbow_table_gen.C -o rainbow_gen -lssl -lcrypto -fopenmp
```
You may need to add some other flags to indicate the complier complies the code using different parallel lib. For example, you need to add the flag `-fopenmp` to use OpenMP

For the Mpi implementation:
MPI is not scanf friendly so we implemented it in a such a way that the user will have to add the input on the command line while running the code. e.g compile with the command: 
```
mpicc rainbowtable_mpi.c -o rainbowtable_mpi -lcrypto 
```
To run the compiled binary file use the command:
mpirun  <num_processor> <./binary_file_name> <length> <algorithm> <n_chains> <chain_length> e.g
```
 mpirun -np 5 ./rainbowtable_mpi 8 sha1 1000 100
```

## Usage
Runing parameters:
- The lengh of the password: The password length that the program should randomly init from '0-9a-zA-Z'. This is fixed set of chars, you can modify it in the code based on your needs.
- Hashing algorithm: Choosing from 'sha1, sha256, sha512', which hash style you want to use.
- Number of chains: The size of Rainbow table the program should generate.
- Chain length: The length of each chain.

## Pesudo code
```
    For each chain
        Generate a random password
        For each link in the chain
            Hash the password
            Reduce the hash
            Store the password and the hash
            Repeat until the chain length is reached
    Store the last password and the hash
    Write the initial password and the last hast into file
```

