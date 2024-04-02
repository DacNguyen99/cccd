/**
   Copyright (c) 2011, 2012, 2013 Research In Motion Limited.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**/
#include <Wire.h>
#include <SPI.h>
#include <Adafruit_PN532.h>

// If using the breakout with SPI, define the pins for SPI communication.
#define PN532_SCK (27)
#define PN532_MOSI (25)
#define PN532_SS (33)
#define PN532_MISO (26)

// If using the breakout or shield with I2C, define just the pins connected
// to the IRQ and reset lines.  Use the values below (2, 3) for the shield!
// #define PN532_IRQ (2)
// #define PN532_RESET (3) // Not connected by default on the NFC Shield

// Uncomment just _one_ line below depending on how your breakout or shield
// is connected to the Arduino:

// // Use this line for a breakout with a SPI connection:
// Adafruit_PN532 nfc(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);

// #define PN532_SSs (5)
SPIClass SPIi(VSPI);
HardwareSerial hsu(2);

Adafruit_PN532 nfc(5, &SPIi);

// Use this line for a breakout with a hardware SPI connection.  Note that
// the PN532 SCK, MOSI, and MISO pins need to be connected to the Arduino's
// hardware SPI SCK, MOSI, and MISO pins.  On an Arduino Uno these are
// SCK = 13, MOSI = 11, MISO = 12.  The SS line can be any digital IO pin.
// Adafruit_PN532 nfc(PN532_SS);

// Or use this line for a breakout or shield with an I2C connection:
// Adafruit_PN532 nfc(PN532_IRQ, PN532_RESET);

// // PWM LED will be on the following PINs.
// #define R_PIN (9)
// #define G_PIN (10)
// #define B_PIN (11)

// // Initial values of RGB.
// uint8_t r = 0x00;
// uint8_t g = 0x00;
// uint8_t b = 0x7f;

// /**
//  * Write the current color to the output pins.
//  */
// void showColor()
// {
//     analogWrite(R_PIN, r);
//     analogWrite(G_PIN, g);
//     analogWrite(B_PIN, b);
// }

#include <DES.h>

/* Key for cipher */
uint8_t key_enc[24];

DES des;

int calc_size(int size)
{
    size = size + (8 - (size % 8)) - 1;
    return size;
}

// uint8_t message[] = {0x09,0x80,0x02,0x69,0x73,0x98, 0x06,0x15,0x73,0x80,0x61,0x55};

uint8_t message[] = {0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
uint8_t active_command[] = {0x0C, 0x44, 0x00, 0x00};
uint8_t read_command[] = {0x00, 0xB0, 0x1E, 0x00};
uint8_t none_challenge_command[] = {0x00, 0x84, 0x00, 0x00, 0x08};
// uint8_t auth_command[]={0x00,0x82,0x00,0x00,0x09,0x80,0x02,0x69,0x73,0x98,0x06,0x15,0x73,0x80,0x61,0x55};
// uint8_t auth_command[]={0x00,0x82,0x00,0x00,0,9,8,0,0,2,6,9,7,3,9,8, 0,6,1,5,7,3,8,0,6,1,5,5};

uint8_t auth_command[] = {0x00, 0x82, 0x00, 0x00, 9, 80, 02, 69, 73, 98, 06, 15, 73, 80, 61, 55};

uint8_t reverse[100];
uint8_t out[100];
uint8_t in[32] = {0x78, 0x17, 0x23, 0x86, 0x0C, 0x06, 0xC2, 0x26, 0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12, 0x0B, 0x79, 0x52, 0x40, 0xCB, 0x70, 0x49, 0xB0, 0x1C, 0x19, 0xB3, 0x3E, 0x32, 0x80, 0x4F, 0x0B};
uint8_t k_enc[16] = {0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2};
uint8_t K_enc_24[24];
unsigned long ms;

uint8_t S_auth[] = {0, 0, 0, 0, 0, 0, 0, 0, 0xe9, 0x71, 0xe3, 0x24, 0xf3, 0xf3, 0x40, 0xde, 0x45, 0x2b, 0xe4, 0x1f, 0x8e, 0xbb, 0xa7, 0x03, 0x81, 0x06, 0xae, 0x76, 0x3a, 0x64, 0x95, 0x78};
uint8_t S_auth_ori[] = {0x78, 0x17, 0x23, 0x86, 0x0C, 0x06, 0xC2, 0x26, 0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12, 0x0B, 0x79, 0x52, 0x40, 0xCB, 0x70, 0x49, 0xB0, 0x1C, 0x19, 0xB3, 0x3E, 0x32, 0x80, 0x4F, 0x0B};

uint8_t E_IDF[] = {0x72, 0xC2, 0x9C, 0x23, 0x71, 0xCC, 0x9B, 0xDB, 0x65, 0xB7, 0x79, 0xB8, 0xE8, 0xD3, 0x7B, 0x29, 0xEC, 0xC1, 0x54, 0xAA, 0x56, 0xA8, 0x79, 0x9F, 0xAE, 0x2F, 0x49, 0x8F, 0x76, 0xED, 0x92, 0xF2, 0x80, 0, 0, 0, 0, 0, 0, 0};
// uint8_t K_mac[] = {0x79, 0x62, 0xD9, 0xEC, 0xE0, 0x3D, 0x1A, 0xCD, 0x4C, 0x76, 0x08, 0x9D, 0xCE, 0x13, 0x15, 0x43};
// uint8_t K_mac_24[24];

uint8_t K_enc_m_24[24];

uint8_t K_enc_m[] = {0x9d, 0xdf, 0x8a, 0x10, 0x32, 0xa7, 0x9b, 0x23, 0x5d, 0xcd, 0x3b, 0x68, 0xae, 0x2a, 0xe3, 0x92};
// uint8_t K_mac_m[] = {0x2a, 0x5b, 0x0d, 0x61, 0x6e, 0x80, 0x79, 0xda, 0x04, 0xf2, 0x94, 0x62, 0x79, 0x8c, 0xc7, 0x97};
// uint8_t S_m[] = {0, 0, 0, 0, 0, 0, 0, 0, 0xe9, 0x71, 0xe3, 0x24, 0xf3, 0xf3, 0x40, 0xde, 0x45, 0x2b, 0xe4, 0x1f, 0x8e, 0xbb, 0xa7, 0x03, 0x81, 0x06, 0xae, 0x76, 0x3a, 0x64, 0x95, 0x78};
uint8_t E_ifd_m[32];
// uint8_t E_ifd_m_buffer[40];
uint8_t M_ifd_m[8];
uint8_t cmd_data_m[50];

// #include "Hash.h"
// #include <Crypto.h>
// #include <sha1.h>

// // SHA1    sha1;
// Sha1 sha1;

#include "mbedtls/md.h"
#include "mbedtls/sha1.h"

#define SIZE_READ (231) // 128+32vs2000 ok //128+32+32 vs500 // 231 vs340

uint8_t K_enc[16]; /* key enc of card */
uint8_t K_mac[16]; /* key mac of card */

uint8_t RND_ifd[8]; /* random from host */
uint8_t RND_ic[8];  /* random from card */
uint8_t K_ifd[16];  /* random from host */

uint8_t S[32];
uint8_t KS_enc[16];
uint8_t KS_mac[16];

uint8_t APDU_data[200];
uint8_t APDU_len;

/* page 39 LDS1 eMRTD Application ICAO_p10 */
const uint8_t APDU_LDS1_eMRTD_Application[] = {0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};
const uint8_t APDU_Get_Challenge[] = {0x00, 0x84, 0x00, 0x00, 0x08};
const uint8_t APPU_Change_Baudrate[] = {03, 03};

uint8_t response[256];
uint8_t responseLength = sizeof(response);

uint8_t EF_data[20000];
uint16_t EF_len = 0;

union SSC
{
    uint8_t raw[8];
    unsigned long long int counter;
} ssc;

void print_arr(char *ps, uint8_t *arr, int size)
{
    Serial.println(ps);
    for (int i = 0; i < size; i++)
    {
        Serial.print(arr[i] < 16 ? "0" : "");
        Serial.print(arr[i], HEX);
    }
}

void generate_random_and_concatenate_S(uint8_t *rnd_ic)
{
    /* create random */
    for (uint8_t i = 0; i < 32; i++)
        S[i] = random();

    /* concatenate_S */
    memcpy(&S[8], rnd_ic, 8);
    memcpy(RND_ic, rnd_ic, 8);
    memcpy(RND_ifd, S, 8);
    memcpy(K_ifd, &S[16], 16);
}

void adjust_parity_bits(uint8_t *input, uint8_t *output)
{
    uint8_t byte;
    uint8_t cnt_odd;
    for (uint8_t i = 0; i < 16; i++)
    {
        byte = input[i];
        cnt_odd = 0;
        for (uint8_t k = 7; k > 0; k--)
            if (((byte >> k) & 0x01) == 0x01)
                cnt_odd++;

        if (cnt_odd % 2 == 0)
            byte = byte | 0x01;
        else
            byte = byte & 0xfe;

        output[i] = byte;
    }
}

void caculator_key_for_MRZ(char *mrz)
{

    uint8_t sha1_mrz[20];
    uint8_t sha1_out[20];

    mbedtls_sha1_ret((const unsigned char *)mrz, strlen(mrz), sha1_mrz);
    memset(&sha1_mrz[16], 0, 4);
    /* Kenc */
    sha1_mrz[19] = 0x01;
    mbedtls_sha1_ret((const unsigned char *)sha1_mrz, sizeof(sha1_mrz), sha1_out);
    adjust_parity_bits(sha1_out, K_enc);

    /* Kmac */
    sha1_mrz[19] = 0x02;
    mbedtls_sha1_ret((const unsigned char *)sha1_mrz, sizeof(sha1_mrz), sha1_out);
    adjust_parity_bits(sha1_out, K_mac);
}

// void create_key_3des(void)
// {
//     memcpy(K_enc_24, k_enc, 16);
//     memcpy(&K_enc_24[16], k_enc, 8);

//     memcpy(K_mac_24, K_mac, 16);
//     memcpy(&K_mac_24[16], K_mac, 8);
// }

// void compute_mac_over_Eidf_Kmac(uint8_t *Eidf, uint8_t *Kmac, uint8_t *Midf)
// {
//     uint8_t E_idf[40];
//     memset(E_idf, 0x00, 40);
//     memcpy(E_idf, Eidf, 32);
//     E_idf[32] = 0x80;

//     uint8_t h5decrypt[8];
//     uint8_t int2[8];
//     uint8_t int3[8];
//     uint8_t int4[8];
//     uint8_t int5[8];
//     uint8_t h1[8];
//     uint8_t h2[8];
//     uint8_t h3[8];
//     uint8_t h4[8];
//     uint8_t h5[8];

//     des.calc_size_n_pad(9);

//     des.encrypt(&h1[0], &E_idf[0], (uint8_t *)Kmac + 0);
//     for (int i = 0; i < 8; i++)
//         int2[i] = (byte)(h1[i] ^ E_idf[8 + i]);

//     des.encrypt(&h2[0], &int2[0], (uint8_t *)Kmac + 0);
//     for (int i = 0; i < 8; i++)
//         int3[i] = (byte)(h2[i] ^ E_idf[16 + i]);

//     des.encrypt(&h3[0], &int3[0], (uint8_t *)Kmac + 0);
//     for (int i = 0; i < 8; i++)
//         int4[i] = (byte)(h3[i] ^ E_idf[24 + i]);

//     des.encrypt(&h4[0], &int4[0], (uint8_t *)Kmac + 0);
//     for (int i = 0; i < 8; i++)
//         int5[i] = (byte)(h4[i] ^ E_idf[32 + i]);

//     des.encrypt(h5, int5, (uint8_t *)Kmac + 0);
//     des.decrypt(h5decrypt, h5, (uint8_t *)Kmac + 8);
//     des.encrypt(Midf, h5decrypt, (uint8_t *)Kmac + 0);
// }

// void compute_mac_over_Eidf_Kmac2(void)
// {
//     uint8_t Eidf[] = {0x88, 0x70, 0x22, 0x12, 0x0C, 0x06, 0xC2, 0x27, 0x0C, 0xA4, 0x02, 0x0C, 0x80, 0x00, 0x00, 0x00, 0x87, 0x09, 0x01, 0x63, 0x75, 0x43, 0x29, 0x08, 0xC0, 0x44, 0xF6};
//     uint8_t Kmac[16] = {0xF1, 0xCB, 0x1F, 0x1F, 0xB5, 0xAD, 0xF2, 0x08, 0x80, 0x6B, 0x89, 0xDC, 0x57, 0x9D, 0xC1, 0xF8};

//     uint8_t E_idf[40];
//     memset(E_idf, 0x00, 40);
//     memcpy(E_idf, Eidf, sizeof(Eidf));
//     E_idf[27] = 0x80;

//     uint8_t h5decrypt[8];
//     uint8_t int2[8];
//     uint8_t int3[8];
//     uint8_t int4[8];
//     uint8_t int5[8];
//     uint8_t h1[8];
//     uint8_t h2[8];
//     uint8_t h3[8];
//     uint8_t h4[8];
//     uint8_t h5[8];

//     des.calc_size_n_pad(9);

//     des.encrypt(&h1[0], &E_idf[0], (uint8_t *)Kmac + 0);
//     for (int i = 0; i < 8; i++)
//         int2[i] = (byte)(h1[i] ^ E_idf[8 + i]);

//     des.encrypt(&h2[0], &int2[0], (uint8_t *)Kmac + 0);
//     for (int i = 0; i < 8; i++)
//         int3[i] = (byte)(h2[i] ^ E_idf[16 + i]);

//     des.encrypt(&h3[0], &int3[0], (uint8_t *)Kmac + 0);
//     for (int i = 0; i < 8; i++)
//         int4[i] = (byte)(h3[i] ^ E_idf[24 + i]);

//     // des.encrypt(&h4[0], &int4[0], (uint8_t *)Kmac + 0);
//     // for (int i = 0; i < 8; i++)
//     //     int5[i] = (byte)(h4[i] ^ E_idf[32 + i]);

//     des.encrypt(h5, int4, (uint8_t *)Kmac + 0);
//     des.decrypt(h5decrypt, h5, (uint8_t *)Kmac + 8);
//     uint8_t Midf[8];
//     des.encrypt(Midf, h5decrypt, (uint8_t *)Kmac + 0);
//     print_arr("\r\n Kmac", Kmac, 16);
//     print_arr("\r\n Eidf", Eidf, 27);
//     print_arr("\r\n Midf", Midf, 8);
// }

void compute_mac(uint8_t *input, uint8_t len, uint8_t *key, uint8_t *output)
{
    uint8_t time_enc = len / 8;
    uint8_t mac_input[(time_enc + 1) * 8];
    memset(mac_input, 0x00, sizeof(mac_input));
    memcpy(mac_input, input, len);
    mac_input[len] = 0x80;

    uint8_t h_[time_enc + 1][8];
    uint8_t int_[time_enc][8];

    des.encrypt(h_[0], &mac_input[0], (uint8_t *)key + 0);
    for (int i = 0; i < 8; i++)
        int_[0][i] = (byte)(h_[0][i] ^ mac_input[8 * 1 + i]);

    for (uint8_t k = 1; k < time_enc; k++)
    {
        des.encrypt(h_[k], int_[k - 1], (uint8_t *)key + 0);
        for (int i = 0; i < 8; i++)
            int_[k][i] = (byte)(h_[k][i] ^ mac_input[8 * (k + 1) + i]);
    }

    uint8_t h5decrypt[8];
    des.encrypt(h_[time_enc], int_[time_enc - 1], (uint8_t *)key + 0);
    des.decrypt(h5decrypt, h_[time_enc], (uint8_t *)key + 8);
    des.encrypt(output, h5decrypt, (uint8_t *)key + 0);
}

/* Set key for encrypt and decrypt */
void set_key_cipher(uint8_t *newkey, uint8_t len)
{
    if (len == 24)
    {
        memcpy(key_enc, newkey, 24);
    }
    if (len == 16)
    {
        memcpy(key_enc, newkey, 16);
        memcpy(&key_enc[16], newkey, 8);
    }
    if (len == 8)
    {
        memcpy(key_enc, newkey, 8);
        memcpy(&key_enc[8], newkey, 8);
        memcpy(&key_enc[16], newkey, 8);
    }
}

/* RAPDU authentication and establishment of session key */
int RAPDU_auth_est_session_key(uint8_t *rapdu, uint8_t len)
{
    if (len < 42)
        return 0;

    /* get 7&8 page 90/9303_p11 ICAO */
    uint8_t Mic[8];
    uint8_t Eic[32];
    memcpy(Eic, rapdu, 32);
    memcpy(Mic, &rapdu[32], 8);

    /* Caculator R by decrypt */
    uint8_t R[32];
    memset(R, 0x00, sizeof(R));
    set_key_cipher(K_enc_m, sizeof(K_enc_m));
    des.do_3des_decrypt(Eic, sizeof(Eic), R, key_enc, 0);

    /* Get SSC */
    for (uint8_t i = 0; i < 4; i++)
        ssc.raw[i] = R[15 - i];
    for (uint8_t i = 0; i < 4; i++)
        ssc.raw[4 + i] = R[7 - i];

    /* Get Kic & Kseed */
    uint8_t K_ic[16];
    memcpy(K_ic, &R[16], 16);
    uint8_t K_seed_ex[20];
    memset(K_seed_ex, 0x00, 20);
    for (uint8_t i = 0; i < 16; i++)
        K_seed_ex[i] = K_ic[i] ^ K_ifd[i];

    uint8_t sha1_out[20];
    /* KS enc */
    K_seed_ex[19] = 0x01;
    mbedtls_sha1_ret((const unsigned char *)K_seed_ex, sizeof(K_seed_ex), sha1_out);
    adjust_parity_bits(sha1_out, KS_enc);

    /* KS mac */
    K_seed_ex[19] = 0x02;
    mbedtls_sha1_ret((const unsigned char *)K_seed_ex, sizeof(K_seed_ex), sha1_out);
    adjust_parity_bits(sha1_out, KS_mac);

    // print_arr("\r\n rapdu",rapdu,40);
    // print_arr("\r\n R",R,32);
    // print_arr("\r\n K_ic",K_ic,16);
    // print_arr("\r\n K_ifd",K_ifd,16);
    // print_arr("\r\n ssc",ssc.raw,8);
    // print_arr("\r\n K_seed_ex",K_seed_ex,20);
    // print_arr("\r\n KS enc",KS_enc,16);
    // print_arr("\r\n KS_mac",KS_mac,16);
    // print_arr("\r\n K enc",K_enc,16);
    // print_arr("\r\n K_mac",K_mac,16);

    return 1;
}

// #define SHORT_EF 0x010B
// #define ADR 4
// #define SIZE 20
// #define P1 0x02 // 0x02

// void select_EF_COM(void)
// {
//     uint8_t pad_data[8];
//     memset(pad_data, 0x00, 8);
//     pad_data[0] = (SHORT_EF >> 8) & 0xff;
//     pad_data[1] = SHORT_EF & 0xff; /* 1D ra gì đó */
//     pad_data[2] = 0x80;

//     uint8_t N[32];
//     memset(N, 0x00, 32);
//     ssc.counter++;
//     for (uint8_t i = 0; i < 8; i++)
//         N[i] = ssc.raw[7 - i];

//     /* Concatenate CmdHeader in Step e) */
//     N[8] = 0x0c;
//     N[9] = 0xa4;
//     N[10] = P1;
//     N[11] = 0x0c;
//     N[12] = 0x80;

//     /* Build DO‘87' in step d) */
//     uint8_t DO87[11];
//     DO87[0] = 0x87;
//     DO87[1] = 0x09;
//     DO87[2] = 0x01;

//     /* Encrypt data with KSEnc in step c) */
//     set_key_cipher(KS_enc, sizeof(KS_enc));
//     des.do_3des_encrypt(pad_data, sizeof(pad_data) + 1, &DO87[3], key_enc, 0);
//     memcpy(&N[16], DO87, 11);

//     // /* Add 0x80 to end block , not necessary */
//     // N[27] = 0x80;

//     /* Compute MAC over N with KSMAC in f) iii) & g) */
//     uint8_t DO8E[10];
//     DO8E[0] = 0x8E;
//     DO8E[1] = 0x80;
//     compute_mac(N, 27, KS_mac, &DO8E[2]);
//     /* Finally */
//     memset(APDU_data, 0x00, sizeof(APDU_data));
//     APDU_data[0] = 0x0c;
//     APDU_data[1] = 0xa4;
//     APDU_data[2] = P1;
//     APDU_data[3] = 0x0c;
//     APDU_data[4] = 0x15;
//     memcpy(&APDU_data[5], DO87, 11);
//     memcpy(&APDU_data[16], DO8E, 10);
//     APDU_len = 27;
//     // print_arr("\r\n N", N, 32);
//     // print_arr("\r\n APDU_data", APDU_data, 27);
// }

void select_EF_COM(uint16_t ef)
{
    uint8_t pad_data[8];
    memset(pad_data, 0x00, 8);
    pad_data[0] = (ef >> 8) & 0xff;
    pad_data[1] = ef & 0xff; /* 1D ra gì đó */

    // pad_data[0] = 01;
    // pad_data[1] = 01; /* 1D ra gì đó */
    pad_data[2] = 0x80;

    uint8_t N[32];
    memset(N, 0x00, 32);
    ssc.counter++;
    for (uint8_t i = 0; i < 8; i++)
        N[i] = ssc.raw[7 - i];

    /* Concatenate CmdHeader in Step e) */
    N[8] = 0x0c;
    N[9] = 0xa4;
    N[10] = 0x02;
    N[11] = 0x0c;
    N[12] = 0x80;

    /* Build DO‘87' in step d) */
    uint8_t DO87[11];
    DO87[0] = 0x87;
    DO87[1] = 0x09;
    DO87[2] = 0x01;

    /* Encrypt data with KSEnc in step c) */
    set_key_cipher(KS_enc, sizeof(KS_enc));
    des.do_3des_encrypt(pad_data, sizeof(pad_data) + 1, &DO87[3], key_enc, 0);
    memcpy(&N[16], DO87, 11);

    // /* Add 0x80 to end block , not necessary */
    // N[27] = 0x80;

    /* Compute MAC over N with KSMAC in f) iii) & g) */
    uint8_t DO8E[10];
    DO8E[0] = 0x8E;
    DO8E[1] = 0x80;
    compute_mac(N, 27, KS_mac, &DO8E[2]);
    /* Finally */
    memset(APDU_data, 0x00, sizeof(APDU_data));
    APDU_data[0] = 0x0c;
    APDU_data[1] = 0xa4;
    APDU_data[2] = 0x02;
    APDU_data[3] = 0x0c;
    APDU_data[4] = 0x15;
    memcpy(&APDU_data[5], DO87, 11);
    memcpy(&APDU_data[16], DO8E, 10);
    APDU_len = 27;
}

// void prepare_read_first_4_bytes(void)
// {
//     uint8_t N[24];
//     memset(N, 0, 24);

//     /* step a) b) c) */
//     uint8_t M[11];
//     memset(M, 0x00, 11);
//     M[0] = 0x0c;
//     M[1] = 0xb0;
//     M[4] = 0x80;
//     M[8] = 0x97;
//     M[9] = 0x01;
//     M[10] = 0x04;

//     /* step d) i) */
//     ssc.counter++; /* for response of card */
//     ssc.counter++; /* for increase of reader */
//     for (uint8_t i = 0; i < 8; i++)
//         N[i] = ssc.raw[7 - i];

//     /* step d) ii) */
//     memcpy(&N[8], M, 11);
//     N[19] = 0x80;

//     /* step d) iii) & e) */
//     uint8_t DO8E[10];
//     DO8E[0] = 0x8E;
//     DO8E[1] = 0x08;
//     compute_mac(N, 19, KS_mac, &DO8E[2]);

//     /* Finally */
//     memset(APDU_data, 0x00, sizeof(APDU_data));
//     APDU_data[0] = 0x0c;
//     APDU_data[1] = 0xb0;
//     APDU_data[4] = 0x0d;
//     APDU_data[5] = 0x97;
//     APDU_data[6] = 0x01;
//     APDU_data[7] = 0x04;
//     memcpy(&APDU_data[8], DO8E, 10);
//     APDU_len = 19;
// }

uint16_t get_sizeof_EF(uint8_t *rappu, uint16_t len)
{
    // print_arr("RAPDU", rappu, len);
    /* prepare data enc */
    uint8_t data_enc[rappu[1]];
    memcpy(data_enc, &rappu[3], sizeof(data_enc));

    /* prepare data des */
    uint8_t size_des = rappu[1];
    if (size_des % 8 != 0)
        size_des = (size_des / 8 + 1) * 8;
    uint8_t data_des[500];
    memset(data_des, 0x00, sizeof(data_des));

    /* descrypt data */
    set_key_cipher(KS_enc, 16);
    des.do_3des_decrypt(data_enc, sizeof(data_enc), data_des, key_enc, 0);
    print_arr("\r\n data 4 bytes:", data_des, size_des);

    /* caculator size */
    uint16_t size;
    if (data_des[1] == 0x82)
        size = data_des[2] << 8 | data_des[3];
    else
        size = data_des[1];
    return size;
}

void prepare_read_data_EF(uint16_t from, uint8_t size)
{
    // printf("read from %u to %u\r\n", from, size);
    uint8_t N[24];
    memset(N, 0, 24);

    /* step a) b) c) */
    uint8_t M[11];
    memset(M, 0x00, 11);
    M[0] = 0x0c;
    M[1] = 0xb0;
    M[2] = (from >> 8) & 0xff;
    M[3] = from & 0xff; // FROM
    M[4] = 0x80;
    M[8] = 0x97;
    M[9] = 0x01;
    M[10] = size; // SIZE

    /* step d) i) */
    ssc.counter++; /* for response of card */
    ssc.counter++; /* for increase of reader */
    for (uint8_t i = 0; i < 8; i++)
        N[i] = ssc.raw[7 - i];

    /* step d) ii) */
    memcpy(&N[8], M, 11);
    N[19] = 0x80;

    /* step d) iii) & e) */
    uint8_t DO8E[10];
    DO8E[0] = 0x8E;
    DO8E[1] = 0x08;
    compute_mac(N, 19, KS_mac, &DO8E[2]);

    /* Finally */
    memset(APDU_data, 0x00, sizeof(APDU_data));
    APDU_data[0] = 0x0c;
    APDU_data[1] = 0xb0;
    APDU_data[2] = (from >> 8) & 0xff;
    APDU_data[3] = from & 0xff; // FROM
    APDU_data[4] = 0x0d;
    APDU_data[5] = 0x97;
    APDU_data[6] = 0x01;
    APDU_data[7] = size; // SIZE
    memcpy(&APDU_data[8], DO8E, 10);
    APDU_len = 19;
}

void descrypt_data_EF(uint8_t *rappu, uint8_t len)
{
    /* prepare data des */
    uint8_t size_des = rappu[1];
    if (size_des % 8 != 0)
        size_des = (size_des / 8 + 1) * 8;
    uint8_t data_des[size_des];
    memset(data_des, 0x00, sizeof(data_des));

    /* data enscrypt */
    uint8_t size_enc = rappu[1];
    // if (size_enc % 8 != 0)
    //     size_enc = (size_des / 8 + 1) * 8;
    uint8_t data_enc[size_enc];
    // memset(data_enc,0x00,size_enc);
    memcpy(data_enc, &rappu[3], size_enc);

    /* descript data */
    set_key_cipher(KS_enc, 16);
    des.do_3des_decrypt(data_enc, size_enc, data_des, key_enc, 0);

    memcpy(&EF_data[EF_len], data_des, SIZE_READ);
    EF_len = EF_len + SIZE_READ;
    // printf("size_des %u  rappu[1] %u\r\n", size_des, size_enc);

    // print_arr("\r\n enc:", data_enc, size_enc);
    // print_arr("\r\n data 4 bytes:", data_des, size_des);
}

void prepare_eMRTD_Application(void)
{
    APDU_len = sizeof(APDU_LDS1_eMRTD_Application);
    memcpy(APDU_data, APDU_LDS1_eMRTD_Application, APDU_len);
}

void prepare_get_challenge(void)
{
    APDU_len = sizeof(APDU_Get_Challenge);
    memcpy(APDU_data, APDU_Get_Challenge, APDU_len);
}

void prepare_external_authenticate(uint8_t *RAPDU, uint8_t RAPDU_len)
{
    /* Step 2 page 89 p11_ICAO */
    generate_random_and_concatenate_S(RAPDU);
    /* Step 4 Encrypt S with 3DES key KEnc */
    set_key_cipher(K_enc, 16);
    des.do_3des_encrypt(S, sizeof(S) + 1, E_ifd_m, key_enc, 0);
    /* Step 5 Compute MAC over EIFD with 3DES key KMAC*/
    compute_mac(E_ifd_m, 32, K_mac, M_ifd_m);
    /* Step 6 Construct command */
    memset(APDU_data, 0x00, sizeof(APDU_data));
    APDU_data[0] = 0x00;
    APDU_data[1] = 0x82;
    APDU_data[2] = 0x00;
    APDU_data[3] = 0x00;
    APDU_data[4] = 0x28;
    memcpy(&APDU_data[5], E_ifd_m, 32);
    memcpy(&APDU_data[5 + 32], M_ifd_m, 8);
    APDU_data[5 + 40] = 0x28;
    APDU_len = 46;
}

void read_remain_data_in_EF(uint16_t size)
{
    // Serial.print("\r\n size read:");
    // Serial.print(size);

    unsigned long startMicros = millis();

    //   // Gọi hàm cần đo thời gian ở đây
    //   yourFunctionToMeasure();

    EF_len = 0;
    for (uint32_t index = 0; index < size; index = index + SIZE_READ)
    {
        prepare_read_data_EF(index + 4, SIZE_READ);
        nfc.inDataExchange(APDU_data, APDU_len, response, &responseLength);
        // descrypt_data_EF(response, responseLength);
    }

    unsigned long endMicros = millis();
    unsigned long executionTimeMicros = endMicros - startMicros;

    Serial.print("\r\nExecution time: ");
    Serial.print(executionTimeMicros);
    Serial.println(" microseconds");

    // print_arr("\r\n DATA FINAL :", EF_data, EF_len);
    // uint16_t index = 4;
    // for (uint8_t k = 0; k < 10; k++)
    // {
    //     prepare_read_data_EF(index, 20);
    //     nfc.inDataExchange(APDU_data, APDU_len, response, &responseLength);
    //     descrypt_data_EF(response, responseLength);
    //     index = index + 20;
    // }
}

// #include "esp32/rtc_clk.h"
void setup()
{
    Serial.begin(921600);
    delay(1000);
    while (!Serial)
        delay(10);

    // Serial.print(getCpuFrequencyMhz());
    // setCpuFrequencyMhz(80);

    Serial.println("Init PN532");
    nfc.begin();
    uint32_t versiondata = nfc.getFirmwareVersion();
    if (!versiondata)
    {
        Serial.println("Did not find the shield - locking up");
        while (true)
        {
        }
    }
    Serial.print("Found chip PN5");
    Serial.println((versiondata >> 24) & 0xFF, HEX);
    Serial.print("Firmware ver. ");
    Serial.print((versiondata >> 16) & 0xFF, DEC);
    Serial.print('.');
    Serial.println((versiondata >> 8) & 0xFF, DEC);
    delay(1000);

    // compute_mac_over_Eidf_Kmac2();
    // create_key_3des();
    des.init(key_enc, (unsigned long long int)0);
    caculator_key_for_MRZ((char *)"098002697398061573806155");
    // nfc.startPassiveTargetIDDetection(02);
}

void loop(void)
{
    // if (0)
    // {
    //     des.do_3des_encrypt(S_auth_ori, sizeof(S_auth_ori) + 1, out, K_enc_24, 0);
    //     des.do_3des_decrypt(out, sizeof(in), reverse, K_enc_24, 0);
    // }

    // compute_mac_over_Eidf_Kmac(E_IDF,K_mac,cmd_data_m);

    // delay(2000);

    // S_auth_test
    // K_mac

    // byte[] h2 = des1.CreateEncryptor().TransformFinalBlock(int2, 0, 8);

    if (nfc.inListPassiveTarget())
    {
        // nfc.startPassiveTargetIDDetection(00);
        // for (uint8_t i = 0; i < 32; i++)
        // {
        //     S_m[i] = random();
        // }

        Serial.println("Change Baudrate\r\n");
        // prepare_eMRTD_Application();
        memcpy(APDU_data, APPU_Change_Baudrate, 2);
        nfc.change_baudrate(APDU_data, sizeof(APPU_Change_Baudrate), response, &responseLength);
        // print_arr("check", response, responseLength);

        Serial.println("Select ePassport application APDU\r\n");
        prepare_eMRTD_Application();
        nfc.inDataExchange(APDU_data, APDU_len, response, &responseLength);

        Serial.println("Challenge APDU\r\n");
        prepare_get_challenge();
        nfc.inDataExchange(APDU_data, APDU_len, response, &responseLength);

        /* get 8 byte RND.IFD */
        Serial.println("Authenticate APDU\r\n");
        prepare_external_authenticate(response, responseLength);
        nfc.inDataExchange(APDU_data, APDU_len, response, &responseLength);

        RAPDU_auth_est_session_key(response, responseLength); /* colect ssc */

        uint16_t list_rq[] = {0x0101, 0x0102, 0x010D, 0x010E, 0x010F};
        for (uint8_t i = 0; i < 5; i++)
        {
            Serial.println("\r\n#################################################\r\n");
            Serial.println(list_rq[i], HEX);

            // /* select EF.COM */
            Serial.println("select EF.COM\r\n");
            select_EF_COM(list_rq[i]); /* inc ssc */
            nfc.inDataExchange(APDU_data, APDU_len, response, &responseLength);

            /* Read Binary of first four bytes */
            Serial.println("Read first 4 bytes in EF\r\n");
            prepare_read_data_EF(0, 4); /* receive -> inc ssc, prepare -> inc ssc */
            nfc.inDataExchange(APDU_data, APDU_len, response, &responseLength);

            /* Read Binary of remain */
            Serial.println("Check and read remain in EF\r\n");
            uint16_t size_EF = get_sizeof_EF(response, responseLength);
            read_remain_data_in_EF(size_EF);
            ssc.counter++;
        }
    }
    delay(1000);
}
