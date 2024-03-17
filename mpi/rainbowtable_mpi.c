#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <mpi.h>

#define MAX_LENGTH 100

// Structure to represent a password-hash pair
typedef struct {
    char password[MAX_LENGTH];
    char hash[SHA512_DIGEST_LENGTH * 2 + 1];
} PasswordHashPair;

// Function to reduce the hash to a password
char* reduce(char* hash, char* chars, int chars_len, int length) {
    // Convert hash to int
    unsigned long hash_int = 0;
    for (int k = 0; k < SHA512_DIGEST_LENGTH; k++) {
        hash_int += hash_int * 256 + (unsigned long) hash[k];
    }

    // Reduce the hash to a password
    static char password[MAX_LENGTH];
    for (int i = 0; i < length; i++) {
        password[i] = chars[hash_int % chars_len];
        hash_int /= chars_len;
    }
    password[length] = '\0';
    return password;
}

// Function to generate a random password
char* random_password(char* chars, int length) {
    static char password[MAX_LENGTH];
    for (int i = 0; i < length; i++) {
        password[i] = chars[rand() % strlen(chars)];
    }
    password[length] = '\0';
    return password;
}

// Function to generate hash for a given password using different algorithms
void generate_hash(const char *password, const char *algorithm, char *hash) {
    if (strcmp(algorithm, "sha1") == 0) {
        // SHA-1 hashing
        SHA_CTX sha1_context;
        SHA1_Init(&sha1_context);
        SHA1_Update(&sha1_context, password, strlen(password));
        SHA1_Final((unsigned char *)hash, &sha1_context);
    } else if (strcmp(algorithm, "sha256") == 0) {
        // SHA-256 hashing
        SHA256_CTX sha256_context;
        SHA256_Init(&sha256_context);
        SHA256_Update(&sha256_context, password, strlen(password));
        SHA256_Final((unsigned char *)hash, &sha256_context);
    } else if (strcmp(algorithm, "sha512") == 0) {
        // SHA-512 hashing
        SHA512_CTX sha512_context;
        SHA512_Init(&sha512_context);
        SHA512_Update(&sha512_context, password, strlen(password));
        SHA512_Final((unsigned char *)hash, &sha512_context);
    } else {
        // Invalid hashing algorithm
        printf("Invalid hashing algorithm\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc != 5) {
        if (rank == 0) {
            printf("Usage: %s <length> <algorithm> <n_chains> <chain_length>\n", argv[0]);
        }
        MPI_Finalize();
        exit(EXIT_FAILURE);
    }

    int length = atoi(argv[1]);
    const char *algorithm = argv[2];
    int n_chains = atoi(argv[3]);
    int chain_length = atoi(argv[4]);

    srand(time(NULL) + rank);

    char* chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int chars_len = strlen(chars);

    // Determine workload for each process
    int chunk_size = n_chains / size;
    int remainder = n_chains % size;
    int my_start = rank * chunk_size + (rank < remainder ? rank : remainder);
    int my_end = my_start + chunk_size + (rank < remainder ? 1 : 0);

    // Create an array to store password-hash pairs
    PasswordHashPair *pairs = (PasswordHashPair *)malloc(chunk_size * sizeof(PasswordHashPair));
    if (pairs == NULL) {
        perror("Memory allocation error");
        MPI_Finalize();
        exit(EXIT_FAILURE);
    }

    clock_t start_time, end_time;
    double computation_time;

    // Start measuring time
    start_time = clock();

    for (int i = 0; i < chunk_size; i++) {
        // Use private variables for each process
        char* p = random_password(chars, length);
        strcpy(pairs[i].password, p);

        for (int j = 0; j < chain_length; j++) {
            // Hashing and reducing
            char hash[SHA512_DIGEST_LENGTH * 2 + 1];
            generate_hash(p, algorithm, hash);
            strcpy(p, reduce(hash, chars, chars_len, length));
        }
        generate_hash(p, algorithm, pairs[i].hash);
    }

    // End measuring time
    end_time = clock();

    // Gather all pairs to rank 0
    PasswordHashPair *all_pairs = NULL;
    if (rank == 0) {
        all_pairs = (PasswordHashPair *)malloc(n_chains * sizeof(PasswordHashPair));
        if (all_pairs == NULL) {
            perror("Memory allocation error");
            MPI_Finalize();
            exit(EXIT_FAILURE);
        }
    }

    MPI_Gather(pairs, chunk_size * sizeof(PasswordHashPair), MPI_BYTE, all_pairs, chunk_size * sizeof(PasswordHashPair), MPI_BYTE, 0, MPI_COMM_WORLD);
    free(pairs);

    // Print the number of processes used
    if (rank == 0) {
        printf("Number of Processes: %d\n", size);

        // Save the sorted password-hash pairs to the file
        FILE *output_file = fopen("rainbow_table.txt", "w");
        if (output_file == NULL) {
            perror("Error opening output file");
            MPI_Finalize();
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < n_chains; ++i) {
            fprintf(output_file, "Password: %s, Last Hash: %s\n", all_pairs[i].password, all_pairs[i].hash);
        }

        fclose(output_file);
        free(all_pairs);

        // Print the size of the generated file
        FILE *file = fopen("rainbow_table.txt", "r");
        if (file == NULL) {
            perror("Error opening file");
            MPI_Finalize();
            exit(EXIT_FAILURE);
        }

        fseek(file, 0L, SEEK_END);
        long size = ftell(file);
        fclose(file);

        printf("Size of File Generated: %ld bytes\n", size);

        // Calculate and print the computation time
        computation_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
        printf("Rainbow table generation time: %.4f seconds\n", computation_time);
    }

    MPI_Finalize();
    return 0;
}
