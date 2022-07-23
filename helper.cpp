#include "helper.h"
#include <stdlib.h>

void reverseArray(unsigned char *state, int i1, int i2)
{
	while (i1 < i2)
	{
		unsigned char temp = state[i1];
		state[i1] = state[i2];
		state[i2] = temp;
		i1++;
		i2--;
	}
}


void leftRotate(unsigned char* state, int d, int n)
{
        reverseArray(state, 0, d - 1);
        reverseArray(state, d, n - 1);
        reverseArray(state, 0, n - 1);
}


void aesAddRoundKey(unsigned char state[AES_BLOCK_SIDE][AES_BLOCK_SIDE], unsigned char subkey[AES_BLOCK_SIDE][AES_BLOCK_SIDE])
{
	for (int i = 0; i < AES_BLOCK_SIDE; i++)
	{
		for (int j = 0; j < AES_BLOCK_SIDE; j++)
		{
			state[i][j] = state[i][j] ^ subkey[i][j];
		}
	}
}

unsigned char * aesAddRoundKey1(unsigned char *state, unsigned char subkey[AES_BLOCK_SIDE][AES_BLOCK_SIDE])
{
    for (int i = 0; i < AES_BLOCK_SIDE; i++)
    {
        for (int j = 0; j < AES_BLOCK_SIDE; j++)
        {
           // *(state + )
                * (state + i * AES_BLOCK_SIDE + j) = *(state + i * AES_BLOCK_SIDE + j) ^ subkey[i][j];
            //state[i][j] = state[i][j] ^ subkey[i][j];
        }
    }
    return state;
}

unsigned char* aesInverseAddRoundKey1(unsigned char* state, unsigned char subkey[AES_BLOCK_SIDE][AES_BLOCK_SIDE])
{
    return aesAddRoundKey1(state, subkey);
}


void aesByteSub(unsigned char state[AES_BLOCK_SIDE][AES_BLOCK_SIDE])
{
    // substitute each byte using the s-box
    for (int r = 0; r < AES_BLOCK_SIDE; r++)
    {
        for (int c = 0; c < AES_BLOCK_SIDE; c++)
        {
            state[r][c] =  aes_s_box[state[r][c]];
        }
    }
}


void aesByteSub1(unsigned char *state)
{
    // substitute each byte using the s-box
    for (int r = 0; r < AES_BLOCK_SIDE; r++)
    {
        for (int c = 0; c < AES_BLOCK_SIDE; c++)
        {
            //state[r][c] = aes_s_box[state[r][c]];
            *(state + r * AES_BLOCK_SIDE + c) = aes_s_box[*(state + r * AES_BLOCK_SIDE + c)];
        }
    }
}

void aesShiftRows(unsigned char state[AES_BLOCK_SIDE][AES_BLOCK_SIDE])
{
	// rotate each row according to its position
	for (int r = 0; r < AES_BLOCK_SIDE; r++)
	{
		leftRotate(state[r], r, AES_BLOCK_SIDE);
	}
}

void aesShiftRows1(unsigned char *state)
{
    // rotate each row according to its position
    for (int r = 0; r < AES_BLOCK_SIDE; r++)
    {
        leftRotate(&state[r*AES_BLOCK_SIDE], r, AES_BLOCK_SIDE);   
    }
}

// perform Galois Field multiplication of two bytes in GF(2^8)
unsigned char galoisMul(unsigned char g1, unsigned char g2)
{
    // taken and documented from https://en.wikipedia.org/wiki/Rijndael_MixColumns
    unsigned char p = 0;

    for (int i = 0; i < 8; i++)
    {
        if (g2 & 0x01) // if LSB is active (equivalent to a '1' in the polynomial of g2)
        {
            p ^= g1; // p += g1 in GF(2^8)
        }

        bool hiBit = (g1 & 0x80); // g1 >= 128 = 0100 0000
        g1 <<= 1;                 // rotate g1 left (multiply by x in GF(2^8))
        if (hiBit)
        {
            // must reduce
            g1 ^= AES_IRREDUCIBLE; // g1 -= 00011011 == mod(x^8 + x^4 + x^3 + x + 1) = AES irreducible
        }
        g2 >>= 1; // rotate g2 right (divide by x in GF(2^8))
    }

    return p;
}


void aesMixCols(unsigned char state[AES_BLOCK_SIDE][AES_BLOCK_SIDE])
{
    unsigned char out[AES_BLOCK_SIDE][AES_BLOCK_SIDE];

    // matrix multiplication in GF(2^8)
    // * => galoisMul, + => ^
    for (int r = 0; r < AES_BLOCK_SIDE; r++)
    {
        for (int c = 0; c < AES_BLOCK_SIDE; c++)
        {
            out[r][c] = 0x00;
            // dot product of row r of the mixColMat and the col c of the state
            for (int i = 0; i < AES_BLOCK_SIDE; i++)
            {
                out[r][c] ^= galoisMul(aes_mixColMat[r][i], state[i][c]);
            }
        }
    }

    for (int i = 0; i < AES_BLOCK_SIDE; i++)
    {
        for (int j = 0; j < AES_BLOCK_SIDE; j++)
        {
            std::cout << std::hex << (int)out[i][j] << " ";
        }
        std::cout << "\n";
    }

    std::cout << "\n";
   
}

unsigned char * shiftStateRows(unsigned char state[AES_BLOCK_SIDE][AES_BLOCK_SIDE]) 
{
    unsigned char* out = new unsigned char[AES_BLOCK_SIDE * AES_BLOCK_SIDE];

    // matrix multiplication in GF(2^8)
  // * => galoisMul, + => ^
    for (int r = 0; r < AES_BLOCK_SIDE; r++)
    {
        for (int c = 0; c < AES_BLOCK_SIDE; c++)
        {
            * (out + r * AES_BLOCK_SIDE + c) = 0x00;
            // dot product of row r of the mixColMat and the col c of the state
            for (int i = 0; i < AES_BLOCK_SIDE; i++)
            {
                *(out + r * AES_BLOCK_SIDE + c) ^= galoisMul(aes_mixColMat[r][i], state[i][c]);
            }
        }
    }

    return out;
}


unsigned char* shiftStateRows2(unsigned char *state)
{
    unsigned char* out = new unsigned char[AES_BLOCK_SIDE * AES_BLOCK_SIDE];

    // matrix multiplication in GF(2^8)
  // * => galoisMul, + => ^
    for (int r = 0; r < AES_BLOCK_SIDE; r++)
    {
        for (int c = 0; c < AES_BLOCK_SIDE; c++)
        {
            *(out + r * AES_BLOCK_SIDE + c) = 0x00;
            // dot product of row r of the mixColMat and the col c of the state
            for (int i = 0; i < AES_BLOCK_SIDE; i++)
            {
               *(out + r * AES_BLOCK_SIDE + c) ^= galoisMul(aes_mixColMat[r][i], *(state+i*AES_BLOCK_SIDE+c));
               // *(state + i * AES_BLOCK_SIDE + c) ^= galoisMul(aes_mixColMat[r][i], *(state + i * AES_BLOCK_SIDE + c));
            }
        }
    }

    return out;
}

void rightRotate(unsigned char *arr,int d,int n)
{
    leftRotate(arr,n-d,n);
}

void aesInvShiftRows(unsigned char* state)
{
    // rotate each row according to its position
    for (int i = 0; i < AES_BLOCK_SIDE; i++)
    {
        rightRotate(&state[i*AES_BLOCK_SIDE], i, AES_BLOCK_SIDE);
    }
}


void aesInverseByteSub(unsigned char *state)
{
    // substitute each byte in the state using the inverse s-box
    for (int i = 0; i < AES_BLOCK_SIDE; i++)
    {
        for (int j = 0; j < AES_BLOCK_SIDE; j++)
        {
            *(state + i * AES_BLOCK_SIDE + j) = aes_inv_s_box[*(state + i * AES_BLOCK_SIDE + j)];
        }
    }
}


unsigned char* aesInverseMixCols(unsigned char* state)
{
    unsigned char* out = new unsigned char[AES_BLOCK_SIDE * AES_BLOCK_SIDE];

    // matrix multiplication in GF(2^8)
    // * => galoisMul, + => ^
    for (int r = 0; r < AES_BLOCK_SIDE; r++)
    {
        for (int c = 0; c < AES_BLOCK_SIDE; c++)
        {
            *(out + r * AES_BLOCK_SIDE + c) = 0x00;
            //out[r][c] = 0x00;
            // dot product between the row r of the invMixColMat and col c of the state
            for (int i = 0; i < AES_BLOCK_SIDE; i++)
            {
                *(out + r * AES_BLOCK_SIDE + c) ^= galoisMul(aes_inv_mixColMat[r][i], *(state + i * AES_BLOCK_SIDE + c));
               // out[r][c] ^= galoisMul(aes_inv_mixColMat[r][i], state[i][c]);
            }
        }
    }

    for (int r = 0; r < AES_BLOCK_SIDE; r++)
    {
        for (int c = 0; c < AES_BLOCK_SIDE; c++)
        {
            *(state + r * AES_BLOCK_SIDE + c) = *(out + r * AES_BLOCK_SIDE + c);
        }
    }

    return out;
}