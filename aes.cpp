#include <string.h> // CBC mode, for memset
#include "aes.h";
#include <cstdio>
#include<iostream>
#include<fstream>

#define Nb 4

#define Nk 4        
#define Nr 10       // The number of rounds in AES Cipher.

using namespace std;

typedef uint8_t state_t[2][4];


static const uint8_t sbox[16] = {
    //0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F 
      0x5, 0xA, 0x0, 0x9, 0x3, 0x6, 0x1, 0xB, 0x8, 0xC, 0xD, 0x2, 0x4, 0xF, 0x7, 0xE };

static const uint8_t inverse_box[16] = {
    //0     1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
      0x2,  0x6, 0xB, 0x4, 0xC, 0x0, 0x5, 0xE, 0x8, 0x3, 0x1, 0x7, 0x9, 0xA, 0xF, 0xD };

static const uint8_t Rcon[10] = {
  0x01, 0x2, 0x4, 0x8, 0x3, 0x6, 0xC, 0xB, 0x5, 0xA };

#define getSBoxValue(num) (sbox[(num)])

static void KeyExpansion(uint8_t RoundKey[11][8], const uint8_t* Key)
{
    unsigned round, j, k;
    uint8_t tempa[8]; 

    RoundKey[0][0] = Key[0];
    RoundKey[0][1] = Key[1];
    RoundKey[0][2] = Key[2];
    RoundKey[0][3] = Key[3];
    RoundKey[0][4] = Key[4];
    RoundKey[0][5] = Key[5];
    RoundKey[0][6] = Key[6];
    RoundKey[0][7] = Key[7];

    for (round = 1; round < Nr; ++round)
    {
        {
            RoundKey[round][0] = RoundKey[round - 1][0] ^ getSBoxValue(RoundKey[round - 1][7]) ^ Rcon[round - 1];

            RoundKey[round][1] = RoundKey[round - 1][1] ^ RoundKey[round][0];
            RoundKey[round][2] = RoundKey[round - 1][2] ^ RoundKey[round][1];
            RoundKey[round][3] = RoundKey[round - 1][3] ^ RoundKey[round][2];
            RoundKey[round][4] = RoundKey[round - 1][4] ^ RoundKey[round][3];
            RoundKey[round][5] = RoundKey[round - 1][5] ^ RoundKey[round][4];
            RoundKey[round][6] = RoundKey[round - 1][6] ^ RoundKey[round][5];
            RoundKey[round][7] = RoundKey[round - 1][7] ^ RoundKey[round][6];
        }
    }
}

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
    KeyExpansion(ctx->RoundKey, key);
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

static void AddRoundKey(uint8_t round, uint8_t state[8], const uint8_t RoundKey[11][8])
{
    const uint8_t *current_round_key = RoundKey[round];
    
    for (int i = 0; i < 8; i++) 
        state[i] ^= current_round_key[i];
}

static void NibbleSub(uint8_t state[8])
{
    for (int i = 0; i < 8; i += 2)
    {
        uint8_t first_4_bits = getSBoxValue((state[i]) >> 4);   // get first 4 bits 
        uint8_t  last_4_bits = getSBoxValue((state[i]) & 0x0F); // get last 4 bits

        uint8_t first_4_bits_2 = getSBoxValue((state[i + 1]) >> 4);   // get first 4 bits 
        uint8_t  last_4_bits_2 = getSBoxValue((state[i + 1]) & 0x0F); // get last 4 bits

        state[i]     = (first_4_bits   << 4) | last_4_bits;
        state[i + 1] = (first_4_bits_2 << 4) | last_4_bits_2;
    }
}

static void ShiftRows(uint8_t state[8])
{
    for (int i = 0; i < 8; i += 2)
    {
        uint8_t first_4_bits = (state[i]) >> 4;   // get first 4 bits 
        uint8_t  last_4_bits = (state[i]) & 0x0F; // get last 4 bits

        uint8_t first_4_bits_2 = (state[i + 1]) >> 4;   // get first 4 bits 
        uint8_t  last_4_bits_2 = (state[i + 1]) & 0x0F; // get last 4 bits

        state[i]     = (first_4_bits   << 4) | last_4_bits_2;
        state[i + 1] = (first_4_bits_2 << 4) | last_4_bits;
    }
}

int Multiply(int a, int b) {
    int sum = 0;
    while (b > 0) {
        if (b & 1) sum = sum ^ a;    
        b = b >> 1;                  
        a = a << 1;                  
        if (a > 15) a = a ^ 0x13;    
    }
    return sum;
}

static void MixColumns(uint8_t state[8])
{
    for (int i = 0; i < 8; i += 2)
    {
        // calculating first column of 4 bits
        uint8_t c0 = state[i] >> 4;
        uint8_t c1 = state[i] & 0x0F;

        uint8_t x1 = Multiply(3, c0);
        uint8_t x2 = Multiply(2, c1);
        uint8_t x3 = Multiply(2, c0);
        uint8_t x4 = Multiply(3, c1);
        
        uint8_t d0 = x1 ^ x2;
        uint8_t d1 = x3 ^ x4;

        // calculating second column of 4 bits
        uint8_t c2 = state[i + 1] & 0x0F;
        uint8_t c3 = state[i + 1] & 0x0F;

        x1 = Multiply(3, c2);
        x2 = Multiply(2, c3);
        x3 = Multiply(2, c3);
        x4 = Multiply(3, c3);

        uint8_t d2 = x1 ^ x2;
        uint8_t d3 = x3 ^ x4;

        // combining result values together
        state[i] = (d0 << 4) | (d1 & 0x0F);
        state[i + 1] = (d2 << 4) | (d3 & 0x0F);
    }
}

#define getSBoxInvert(num) (inverse_box[(num)])

static void InvMixColumns(uint8_t state[8])
{
    MixColumns(state);
}

static void InvNibbleSub(uint8_t state[8])
{
    uint8_t i, j;
    for (i = 0; i < 8; ++i)
        state[i] = getSBoxInvert(state[i]);
}

static void InvShiftRows(uint8_t state[8])
{
    for (int i = 0; i < 8; i += 2)
    {
        uint8_t first_4_bits = (state[i]) >> 4;   // get first 4 bits 
        uint8_t  last_4_bits = (state[i]) & 0x0F; // get last 4 bits

        uint8_t first_4_bits_2 = (state[i + 1]) >> 4;   // get first 4 bits 
        uint8_t  last_4_bits_2 = (state[i + 1]) & 0x0F; // get last 4 bits

        state[i] = (first_4_bits << 4) | last_4_bits_2;
        state[i + 1] = (first_4_bits_2 << 4) | last_4_bits;
    }
}

static void Cipher(uint8_t state[8], const uint8_t RoundKey[11][8])
{
    uint8_t round = 0;

    AddRoundKey(0, state, RoundKey);

    for (round = 1; ; ++round)
    {
        NibbleSub(state);
        ShiftRows(state);
        if (round == Nr) break;
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }

    AddRoundKey(Nr, state, RoundKey);
}

static void InvCipher(uint8_t state[8], const uint8_t RoundKey[11][8])
{
    uint8_t round = 0;

    AddRoundKey(Nr, state, RoundKey);

    for (round = (Nr - 1); ; --round)
    {
        InvShiftRows(state);
        InvNibbleSub(state);
        AddRoundKey(round, state, RoundKey);
        if (round == 0) break;
        InvMixColumns(state);
    }

}

static void XorWithIv(uint8_t state[8], const uint8_t* Iv)
{
    for (int i = 0; i < 8; ++i)
        state[i] ^= Iv[i];
}

void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length, int iteration)
{
    size_t i;
    uint8_t* Iv = ctx->Iv;

    for (i = 0; i < length; i += AES_BLOCKLEN) 
    {
        uint8_t state[8] = { buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7] };

        XorWithIv(state, Iv);
        Cipher(state, ctx->RoundKey);

        char file_name[100] = "results/";
        char it[10];
        strcat(file_name, _itoa(iteration, it, 10));
        strcat(file_name, ".dat");
        ofstream wf(file_name, ios::out | ios::binary | ios::app);
        for (int j = 0; j < 8; j++)
            wf.write((char*)&state[j], sizeof(uint8_t));

        Iv = buf;
        buf += AES_BLOCKLEN;
    }
    /* store Iv in ctx for next call */
    memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
    size_t i;
    uint8_t storeNextIv[AES_BLOCKLEN];

    uint8_t state[8] = { buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7] };

    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        memcpy(storeNextIv, buf, AES_BLOCKLEN);
        InvCipher(state, ctx->RoundKey);
        XorWithIv(state, ctx->Iv);
        memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }
}
