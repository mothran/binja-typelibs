struct crypt_data {
    char keysched[128];
    char sb0[32768];
    char sb1[32768];
    char sb2[32768];
    char sb3[32768];
    char crypt_3_buf[14];
    char current_salt[2];
    long int current_saltbits;
    int  direction, initialized;
};

void setkey(const char *key);
void encrypt(char block[64], int edflag);
void setkey_r(const char *key, struct crypt_data *data);
void encrypt_r(char *block, int edflag, struct crypt_data *data);
