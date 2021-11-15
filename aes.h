#define _AES_H_

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCKLEN 8 // Block length in bytes - AES is 128b block only

#define AES_KEYLEN 8   // Key length in bytes
#define AES_keyExpSize 88

struct AES_ctx
{
    uint8_t RoundKey[11][8]; // 11 rounds, 8 bytes in every
    uint8_t Iv[AES_BLOCKLEN];
};

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);


void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length, int iteration);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
