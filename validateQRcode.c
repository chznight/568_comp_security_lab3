#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "lib/sha1.h"

int compute_OTP (char * secret_hex, long long int counter) {
	SHA1_INFO ctx;
	uint8_t sha1[SHA1_DIGEST_LENGTH];
	uint8_t sha2[SHA1_DIGEST_LENGTH];
	sha1_init (&ctx);

	//edit: lab handout probably had a typo @pad with leading zeroes
    uint8_t pad[21] = {0};
    memset (pad, '0', 20);
    for (int i = 0; i < strlen(secret_hex); ++i) {
       	pad[i] = secret_hex[i];
    }

    //binary value of secret
    char * pos = pad;
    uint8_t c[8];
    uint8_t val[10] = {0};
    size_t i = 0;
    for (i = 0; i < 10; i++){
        sscanf(pos, "%2hhx", &val[i]);
        pos += 2;
    }
    /*
    for (int i = 0; i < 10; ++i) {
    	printf("%x ", val[i]);
    }*/

    uint8_t val_ipad[64];
    uint8_t val_opad[64];
    memset( val_ipad, 0, sizeof(val_ipad));
    memset( val_opad, 0, sizeof(val_opad));
    memcpy( val_ipad, val, 10);
    memcpy( val_opad, val, 10);

    for (int i = 0; i < 64; ++i)
    {
    	val_ipad[i] = val_ipad[i] ^ 0x36;
    	val_opad[i] = val_opad[i] ^ 0x5c;
    }

    //binary value of counter, 64 bits
    for (int i=7; i>=0; i--) {
    	c[i] = (uint8_t) counter & 0xff;
    	counter = counter >> 8;
    }

    sha1_update (&ctx, val_ipad, 64);
	sha1_update (&ctx, c, 8);
	//sha1_update (&ctx, total_i, 18);
    sha1_final (&ctx, sha1);

    sha1_init (&ctx);
    sha1_update(&ctx, val_opad, 64);
    sha1_update(&ctx, sha1, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, sha2);

    int offset = sha2[SHA1_DIGEST_LENGTH-1] & 0xf;
    int binary = ((sha2[offset] & 0x7f) << 24) 
    			| ((sha2[offset+1] & 0xff) << 16) 
    			| ((sha2[offset+2] & 0xff) << 8) 
    			| ((sha2[offset+3] & 0xff));

   	int otp = binary % 1000000;
   	return otp;
}

void covert_to_string (int otp, char*out, int size) {
	memset (out, 0, size+1);
	for (int i = 0; i < size; i++) {
		int digit = otp % 10;
		out[size-i-1] = digit + '0';
		otp = otp /10;
	}
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	//printf ("otp: %d\n", compute_OTP (secret_hex, 1));
	int otp = compute_OTP (secret_hex, 1);
	char otp_calc[7];
	covert_to_string(otp, otp_calc, 6);
	//printf("HOTP %s\n", otp_calc);
	if (strcmp (otp_calc, HOTP_string) == 0) {
		return 1;
	} else {
		return 0;
	}
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	long long current_time = (long long) time (NULL);
	current_time = current_time / 30;
	//printf("%ld\n", current_time);
	int otp = compute_OTP (secret_hex, current_time);
	//printf("%d\n", otp);
	char totp_calc[7];
	covert_to_string(otp, totp_calc, 6);
	//printf("TOTP %s\n", totp_calc);
	if (strcmp (totp_calc, TOTP_string) == 0) {
		return 1;
	} else {
		return 0;
	}
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);



	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
