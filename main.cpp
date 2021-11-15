#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"
#include <ctime>
#include <stdlib.h>

static int test_encrypt_cbc(int);
static int test_decrypt_cbc(void);

int main(void)
{
    printf("\nTesting AES64\n\n");
    for (int j = 0; j < 100; j++)
        for (int i = 0; i < 1024; i++)
            test_encrypt_cbc(j);

    /*
    printf("Encryption speed: ");
    clock_t begin = clock();
    long j = 0;
    for (j = 0; ; j++) {
        double time_spent = (double)(clock() - begin) / CLOCKS_PER_SEC;
        if (time_spent > 3) break;
        test_encrypt_cbc();
    }
    printf("%ld in 3 seconds for 64 size block.\n\n", j);

    printf("Decryption speed: ");
    begin = clock();
    for (j = 0; ; j++) {
        double time_spent = (double)(clock() - begin) / CLOCKS_PER_SEC;
        if (time_spent > 3) break;
        test_decrypt_cbc();
    }
    printf("%ld in 3 seconds for 64 size block.\n\n", j);
    */

    return 0;
}

#pragma region CBC

static int test_encrypt_cbc(int iteration)
{
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6 };
    uint8_t out[] = { 0xed, 0xcc, 0x78, 0xe6, 0xbd, 0x2f, 0xc9, 0x18 };

    //uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    uint8_t iv[8];
    for (int i = 0; i < 8; i++) {
        iv[i] = (uint8_t)(rand() % 16);
    }

    uint8_t in[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96 };
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 1024, iteration);
    
    return 1;
}

static int test_decrypt_cbc(void)
{
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6 };
    uint8_t in[]  = { 0xed, 0xcc, 0x78, 0xe6, 0xbd, 0x2f, 0xc9, 0x18 };

    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96 };
    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, in, 64);

    return 0;
}

#pragma endregion
