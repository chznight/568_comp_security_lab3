#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);
        
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

        //padding the secret hex if less than 20 characters were provided
        uint8_t pad[21] = {0};
        memset (pad, '0', 20);
        for (int i = 0; i < strlen(secret_hex); ++i) {
        	pad[i] = secret_hex[i];
        }
        
        const char * encodedAccountName = urlEncode(accountName);
        const char * encodedIssuer = urlEncode(issuer);

        //changing the hex string to a byte array
        char * pos = pad;
        uint8_t val[10];
        size_t i = 0;
        for (i = 0; i < sizeof(val)/sizeof(val[0]); i++){
            sscanf(pos, "%2hhx", &val[i]);
            pos += 2;
        }
                
        //printf("asdas d sa %x\n", val);
        uint8_t encodedSecretHex[20] = {0};
        
        //int encodedSecret =base32_encode(secret_hex, strlen(secret_hex), encodedSecretHex, 20);
        //printf("%s\n",encodedSecretHex);
        
//        printf("%d\n",strlen("\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90"));
        int encodedSecret = base32_encode(val, 10, encodedSecretHex, 20);
//        printf("encodedSecretHex is %s\n",encodedSecretHex);
        
        char HOTPuri[200] = {0};
        strcat(HOTPuri, "otpauth://hotp/"); //15
        strcat(HOTPuri, encodedAccountName);
        strcat(HOTPuri, "?issuer=");//8
        strcat(HOTPuri, encodedIssuer);
        strcat(HOTPuri, "&secret=");//8
        strcat(HOTPuri, encodedSecretHex);
        strcat(HOTPuri, "&counter=1");//10

        displayQRcode(HOTPuri);
        
        char TOTPuri[200] = {0};
        strcat(TOTPuri, "otpauth://totp/"); //15
        strcat(TOTPuri, encodedAccountName);
        strcat(TOTPuri, "?issuer=");//8
        strcat(TOTPuri, encodedIssuer);
        strcat(TOTPuri, "&secret=");//8
        strcat(TOTPuri, encodedSecretHex);
        strcat(TOTPuri, "&period=30");//10
        
        displayQRcode(TOTPuri);
        
        
	return (0);
}
