#include <cuda_runtime.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 100
#define SHA512_DIGEST_LENGTH 64


typedef struct {
    char password[MAX_LENGTH];
    char hash[SHA512_DIGEST_LENGTH * 2 + 1]; // Simplified for demo
} PasswordHashPair;


__device__ void cuda_hash(const char *input, char *output, int length) {
    // A simple hash function
    for (int i = 0; i < length; i++) {
        output[i] = (input[i] + 1) % 256;
    }
}


__device__ void cuda_reduce(const char *hash, char *output, int length, char *chars, int chars_len) {
    // A simple reduce function
    for (int i = 0; i < length; i++) {
        int hash_val = hash[i] % chars_len;
        output[i] = chars[hash_val];
    }
    output[length] = '\0';
}

__device__ void cuda_strcpy(char *dst, const char *src) {
    while(*src != '\0') {
        *dst = *src;
        dst++;
        src++;
    }
    *dst = '\0'; // Null-terminate the destination
}

__global__ void generateRainbowTableKernel(char *chars, int chars_len, int password_len, int chain_length, int n_chains, PasswordHashPair *pairs) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < n_chains) {
        char current_password[MAX_LENGTH];
        char current_hash[SHA512_DIGEST_LENGTH * 2 + 1];

        // Initialize with a simple pattern or use a global seed to generate
        for (int i = 0; i < password_len; i++) {
            current_password[i] = chars[(idx + i) % chars_len];
        }
        current_password[password_len] = '\0';

        // Copy initial password to the pair
        cuda_strcpy(pairs[idx].password, current_password);

        // Perform chain generation
        for (int j = 0; j < chain_length; j++) {
            cuda_hash(current_password, current_hash, password_len);
            cuda_reduce(current_hash, current_password, password_len, chars, chars_len);
        }

        cuda_strcpy(pairs[idx].hash, current_hash);
    }
}



void generateRainbowTableCUDA(char *chars, int chars_len, int password_len, int chain_length, int n_chains) {
    PasswordHashPair *dev_pairs;
    char *dev_chars;

    size_t pairs_size = n_chains * sizeof(PasswordHashPair);
    cudaMalloc((void **)&dev_pairs, pairs_size);
    cudaMalloc((void **)&dev_chars, chars_len);
    cudaMemcpy(dev_chars, chars, chars_len, cudaMemcpyHostToDevice);

    int threadsPerBlock = 256;
    int blocksPerGrid = (n_chains + threadsPerBlock - 1) / threadsPerBlock;

    generateRainbowTableKernel<<<blocksPerGrid, threadsPerBlock>>>(dev_chars, chars_len, password_len, chain_length, n_chains, dev_pairs);

    // Copy the array back to the host
    PasswordHashPair *pairs = (PasswordHashPair *)malloc(pairs_size);
    cudaMemcpy(pairs, dev_pairs, pairs_size, cudaMemcpyDeviceToHost);

    // Print all generated pairs
    for (int i = 0; i < n_chains; i++) {
        printf("Password: %s, Hash: %s\n", pairs[i].password, pairs[i].hash);
    }

    // Cleanup
    cudaFree(dev_pairs);
    cudaFree(dev_chars);
    free(pairs);
}

int main() {
    char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int chars_len = sizeof(chars) - 1;
    int password_len = 20;
    int chain_length = 1000;
    int n_chains = 500;

    generateRainbowTableCUDA(chars, chars_len, password_len, chain_length, n_chains);

    return 0;
}