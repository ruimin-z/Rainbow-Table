#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/blowfish.h>

// Structure to represent a password-hash pair
typedef struct {
    char password[50];
    char hash[SHA512_DIGEST_LENGTH * 2 + 1];
} PasswordHashPair;

// Comparison function for sorting PasswordHashPair array based on passwords
int comparePasswordHashPair(const void *a, const void *b) {
    return strcmp(((PasswordHashPair *)a)->password, ((PasswordHashPair *)b)->password);
}

// Function to generate a random password
void generate_random_password(char *password, int password_length) {
    const char *char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}[];:'<>,.?/";

    // Generate a random password using characters from the specified set
    for (int i = 0; i < password_length; ++i) {
        password[i] = char_set[rand() % (strlen(char_set))];
    }
    password[password_length] = '\0';  // Null-terminate the password string
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
    } else if (strcmp(algorithm, "blowfish") == 0) {
        // Blowfish hashing
        BF_KEY key;
        BF_set_key(&key, strlen(password), (const unsigned char *)password);
        BF_ecb_encrypt((const unsigned char *)password, (unsigned char *)hash, &key, BF_ENCRYPT);
    } else {
        // Invalid hashing algorithm
        printf("Invalid hashing algorithm\n");
        exit(EXIT_FAILURE);
    }
}

// Function to generate a reduction of a given password
void generate_reduction(const char *input, int reduction_length, const char *char_set, char *reduced_password) {
    int char_set_length = strlen(char_set);
    // Apply the reduction function formula: r_i(x) = r(x+i)
    for (int i = 0; i < reduction_length; ++i) {
        reduced_password[i] = char_set[(input[i] + i) % char_set_length];
    }
    reduced_password[reduction_length] = '\0';  // Null-terminate the reduced password string
}

// Function to generate a rainbow table and save it to a file
void generate_rainbow_table(const char *algorithm, int reduction_length, const char *char_set, int password_length,
                             int chain_length, int num_chains) {
    srand(time(NULL));

    // Create an array to store password-hash pairs
    PasswordHashPair *pairs = malloc(num_chains * sizeof(PasswordHashPair));
    if (pairs == NULL) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }

    // Generate the rainbow table
    clock_t start_time, end_time;
    double computation_time;

    start_time = clock();

    for (int i = 0; i < num_chains; ++i) {
        char password[password_length + 1];
        generate_random_password(password, password_length);

        char hash[SHA512_DIGEST_LENGTH * 2 + 1];
        char current_hash[SHA512_DIGEST_LENGTH * 2 + 1];

        generate_hash(password, algorithm, hash);

        for (int j = 0; j < chain_length; ++j) {
            int reduction_index = j % reduction_length;

            char reduced_password[password_length + 1];
            generate_reduction(hash, reduction_length, char_set, reduced_password);

            generate_hash(reduced_password, algorithm, current_hash);

            strcpy(hash, current_hash);
        }

        strcpy(pairs[i].password, password);
        strcpy(pairs[i].hash, hash);
    }

    end_time = clock();

    // Sort the array based on passwords
    qsort(pairs, num_chains, sizeof(PasswordHashPair), comparePasswordHashPair);

    // Save the sorted password-hash pairs to the file
    FILE *output_file = fopen("rainbow_table.txt", "w");
    if (output_file == NULL) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_chains; ++i) {
        fprintf(output_file, "Password: %s, Last Hash: %s\n", pairs[i].password, pairs[i].hash);
    }

    fclose(output_file);
    free(pairs);

    // Calculate and print the computation time
    computation_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Rainbow table generation time: %.4f seconds\n", computation_time);
}

int main() {
    char algorithm[20];
    int reduction_length, password_length, chain_length, num_chains;

    // User inputs
    printf("Enter the hashing algorithm (sha1, sha256, sha512, blowfish): ");
    scanf("%s", algorithm);

    printf("Enter the length of reduction function: ");
    scanf("%d", &reduction_length);

    printf("Enter the character set (e.g., alphanumeric): ");
    char char_set[50];
    scanf("%s", char_set);

    printf("Enter the password length: ");
    scanf("%d", &password_length);

    printf("Enter the chain length: ");
    scanf("%d", &chain_length);

    printf("Enter the number of chains: ");
    scanf("%d", &num_chains);

    // Generate rainbow table
    generate_rainbow_table(algorithm, reduction_length, char_set, password_length, chain_length, num_chains);

    return 0;
}
