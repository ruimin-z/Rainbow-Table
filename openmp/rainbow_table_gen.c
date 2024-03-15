#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <omp.h>


#define MAX_LENGTH 100

// Structure to represent a password-hash pair
typedef struct {
    char password[50];
    char hash[SHA512_DIGEST_LENGTH * 2 + 1];
} PasswordHashPair;

// Function to reduce the hash to a password
char* reduce(char* hash, char* chars, int chars_len, int length) {
    // Convert hash to int
    int hash_int = 0;
    for (int k = 0; k < SHA512_DIGEST_LENGTH; k++) {
        hash_int += hash_int * 256 + (int) hash[k];
    }
    // printf("-> hash_int: %d\n", hash_int);

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


int main() {
    srand(time(NULL));
    char* chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int chars_len = strlen(chars);

    int length;
    printf("Enter the length of the password: ");
    scanf("%d", &length);

    char algorithm[10];
    printf("Enter the hashing algorithm (sha1, sha256, sha512):");
    scanf("%s", algorithm);

    int n_chains;
    printf("Enter the number of chains: ");
    scanf("%d", &n_chains);

    int chain_length;
    printf("Enter the chain length: ");
    scanf("%d", &chain_length);

    // Create an array to store password-hash pairs
    PasswordHashPair *pairs = (PasswordHashPair *)malloc(n_chains * sizeof(PasswordHashPair));
    if (pairs == NULL) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }

    clock_t start_time, end_time;
    double computation_time;

    start_time = clock();

    // Parallelize the generation of password-hash pairs
    #pragma omp parallel for
    for (int i = 0; i < n_chains; i++) {
        char* p = random_password(chars, length);
        // printf("Password: %s\n", p);
        strcpy(pairs[i].password, p);
        
        for (int j = 0; j < chain_length; j++) {
            // Hashing and reducing
            char hash[SHA512_DIGEST_LENGTH];
            generate_hash(p, algorithm, hash);
            // printf("-> hash: %s\n", hash);
            p = reduce(hash, chars, chars_len, length);
            // printf("-> reduced password: %s\n", p);
        }
        char hash[SHA512_DIGEST_LENGTH];
        generate_hash(p, algorithm, hash);

        strcpy(pairs[i].hash, hash);
    }
    end_time = clock();

    // Save the sorted password-hash pairs to the file
    FILE *output_file = fopen("rainbow_table.txt", "w");
    if (output_file == NULL) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < n_chains; ++i) {
        fprintf(output_file, "Password: %s, Last Hash: %s\n", pairs[i].password, pairs[i].hash);
    }

    fclose(output_file);
    free(pairs);

    // Calculate and print the computation time
    computation_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Rainbow table generation time: %.4f seconds\n", computation_time);

    return 0;
}