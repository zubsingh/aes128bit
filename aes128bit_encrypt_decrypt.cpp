#include <iostream>
#include <string>
#include <memory>
#include <stdlib.h>
#include <string>
#include "helper.h"
#include <chrono>
#include <thread>

void aesDecryptBlock(std::string& in_cipher, int n, unsigned char subkeys[][AES_BLOCK_SIDE][AES_BLOCK_SIDE]);

void printState(unsigned char *state) {
    std::cout << "\n";

    for (int i = 0; i < AES_BLOCK_SIDE; i++) {
       for (int j = 0; j < AES_BLOCK_SIDE; j++) {

           // Print values of the
            // memory block
            std::cout << std::hex << int(*(state + i * AES_BLOCK_SIDE + j))
                << " ";
        }
        std::cout << std::endl;
    }
}

std::string aesEncryptBlock(std::string& in_text, int n,
    unsigned char subkeys[][AES_BLOCK_SIDE][AES_BLOCK_SIDE])
{
    std::string cipher;
    // represent the state and key as a 4x4 table (read into columns)
    unsigned char* state = new unsigned char[AES_BLOCK_SIDE * AES_BLOCK_SIDE];
    std::cout << in_text;
    std::cout << "len " << n <<"\n";
    char endOfText = 0x03;
    int i = 0;
    for (int c = 0; c < AES_BLOCK_SIDE; c++)
    {
        for (int r = 0; r < AES_BLOCK_SIDE; r++)
        {
            // use padding
            *(state + r*AES_BLOCK_SIDE +c) = (i < n) ? in_text[i] : endOfText;
            i++;
        }
    }
    printState(state);
    int count = 0;
   // std::cout << "\niteration  round " << count++ << "\n";

    // ROUND 0
   aesAddRoundKey1(state, subkeys[0]);

   unsigned char* ss= 0;
   for (int i =1; i < 10; i++)
   {
       //std::cout << "\niteration  round " << count << "\n";
       if (i == 1) {
           aesByteSub1(state);
           aesShiftRows1(state);
           unsigned char* pp = shiftStateRows2(state);
           ss = aesAddRoundKey1(pp, subkeys[i]); 
       }
       else {
           aesByteSub1(ss);
           aesShiftRows1(ss);
           unsigned char* pp = shiftStateRows2(ss);
           ss = aesAddRoundKey1(pp, subkeys[i]);
       }
       count++;
   }

  // std::cout << "\niteration  round " << count << "\n";
   aesByteSub1(ss);
   aesShiftRows1(ss);
   ss = aesAddRoundKey1(ss, subkeys[10]);

   unsigned char *output = new unsigned char[AES_BLOCK_SIDE * AES_BLOCK_SIDE];
   i = 0;
   for (int c = 0; c < AES_BLOCK_SIDE; c++)
   {
       for (int r = 0; r < AES_BLOCK_SIDE; r++)
       {
           output[i++] = (int)*(ss + r * AES_BLOCK_SIDE + c);
           cipher += *(ss + r * AES_BLOCK_SIDE + c);
       }
   }
  
   std::cout << "\n";
   for (int f = 0; f < AES_BLOCK_SIDE*AES_BLOCK_SIDE;f++) {
       std::cout << std::hex << (int)output[f];
   }
   std::cout << "\n";
   return cipher;
}

void aesGenerateKeySchedule(std::string& key, int keylen,unsigned char subkeys[(AES_128_NR + 1)][AES_BLOCK_SIDE][AES_BLOCK_SIDE])
{
    int i = 0;
    for (int c = 0; c < AES_BLOCK_SIDE; c++)
    {
        for (int r = 0; r < AES_BLOCK_SIDE; r++)
        {
            subkeys[0][r][c] = key[i++];
        }
    }

    // generate each round
    //unsigned char roundCoeff = 0x01;
    /*
        Round 1: x^0 = 1
        Round 2: x^1 = x
        Round 3: x^2
        ...
        Round 9: x^8 def x^8 mod P(x)
    */
    for (i = 1; i <= 10; i++)
    {
        // transform key
        unsigned char g[4] = {
            aes_s_box[subkeys[i - 1][1][3]],
            aes_s_box[subkeys[i - 1][2][3]],
            aes_s_box[subkeys[i - 1][3][3]],
            aes_s_box[subkeys[i - 1][0][3]] };

        int h = 0;
        for (int r = 0; r < AES_BLOCK_SIDE; r++)
        {
            subkeys[i][r][0] = subkeys[i - 1][r][0] ^ g[r] ^ ((int)Rcon[i-1][h++]);
        }

        for (int c = 1; c < AES_BLOCK_SIDE; c++)
        
            for (int r = 0; r < AES_BLOCK_SIDE; r++)
            {
                subkeys[i][r][c] = subkeys[i - 1][r][c] ^ subkeys[i][r][c - 1];
            }
    }

 /*   std::cout << "\nkey generation started----\n";

    for (int k = 0; k < 11;k++) {

        for (int i = 0; i < AES_BLOCK_SIDE; i++)
        {
            for (int j = 0; j < AES_BLOCK_SIDE; j++)
            {
                std::cout << std::hex << (int)subkeys[k][i][j] << " ";
            }
            std::cout << std::endl;
        }
        std::cout << std::endl;
    }
    std::cout << "\nkey generation ended----\n";*/

}


int aesEncrypt(std::string & input, int len, std::string & key, int keylen) 
{
    unsigned char subkeys[(AES_128_NR + 1)][AES_BLOCK_SIDE][AES_BLOCK_SIDE];

    aesGenerateKeySchedule(key,keylen,subkeys);
    std::string cipher= aesEncryptBlock(input, len, subkeys);
    aesDecryptBlock(cipher, len, subkeys);
    return 0;
}

int main(int argc, char** argv)
{
   if (argc <= 1) {
        std::cout << "no text provided for encryption\n";
        return 0;
    }

    std::string strParameter;
    for (int i = 1; i < argc; i++)
    {
        strParameter = strParameter + std::string(argv[i]) + " ";
    }
    if (strParameter.size() <= 0 || strParameter.size() > 16 ) {
        std::cout << "\nOnly upto 16 character allowed\n";
        return 0;
    }
    std::cout << "input text:- " <<strParameter << "\n";

    // hardcoded key
    std::string key = "Thats my Kung Fu";
    int keylen = key.size();
    int txtlen =  strParameter.size()-1;

    int encryptlen = aesEncrypt(strParameter, txtlen, key,keylen);
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));

}



void aesDecryptBlock(std::string& in_cipher, int n, unsigned char subkeys[][AES_BLOCK_SIDE][AES_BLOCK_SIDE]) 
{
    std::cout << "\ndecrypt block started\n";
    // read cipher into state matrix
    unsigned char* state = new unsigned char[AES_BLOCK_SIDE * AES_BLOCK_SIDE];

    int i = 0;
    for (int c = 0; c < AES_BLOCK_SIDE; c++)
    {
        for (int r = 0; r < AES_BLOCK_SIDE; r++)
        {
            *(state + r * AES_BLOCK_SIDE + c) = in_cipher[i];
            i++;
        }
    }

    aesInverseAddRoundKey1(state, subkeys[10]);
    aesInvShiftRows(state);
    aesInverseByteSub(state);

    // INVERSE ROUNDS NR-1 --> 1
    for (i = 9; i > 0; i--)
    {  
       aesInverseAddRoundKey1(state, subkeys[i]);
       aesInverseMixCols(state);
       aesInvShiftRows(state);
       aesInverseByteSub(state);
    }

    aesInverseAddRoundKey1(state, subkeys[0]);
    std::cout << "\noutput\n";
    printState(state);

    std::string outputText;
    for (int i = 0; i < AES_BLOCK_SIDE; i++) {
        for (int j = 0; j < AES_BLOCK_SIDE; j++) {

            if ((int)*(state + j * AES_BLOCK_SIDE + i) == 0x03) {
                break;
            }
            outputText += (int)*(state + j * AES_BLOCK_SIDE + i);
        }
        std::cout << std::endl;
    }
    std::cout << "\noutput Plain Text is:- " << outputText;
}
