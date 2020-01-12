/***********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: testing code for cryptographic functions based on FourQ 
************************************************************************************/   
#include "../FourQ_api.h"
#include "../FourQ_params.h"
#include "test_extras.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypto_main.h"

bool SAVETODISK(unsigned char * address, unsigned char * targetAddress, unsigned int size, unsigned char * source) {
	/* write them back */
	FILE *f = fopen(address, "wb");
	fwrite(source, sizeof(*source), size, f);
	fclose(f);
	rename(address, targetAddress);
	return true;
}

ECCRYPTO_STATUS generateSecretAgreement(unsigned char * PrivateKey, unsigned char * PublicKey, unsigned char * SecretAgreement) {
	ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
	Status = CompressedSecretAgreement(PrivateKey, PublicKey, SecretAgreement);
	if (Status != ECCRYPTO_SUCCESS) {
		return Status;
	}

}



/* should only be called during start up */
ECCRYPTO_STATUS generatePublicKey() {
	unsigned char PrivateKey[32], PublicKey[32];
	ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;

	// generating private key & public key
	Status = CompressedKeyGeneration(PrivateKey, PublicKey);
	if (Status != ECCRYPTO_SUCCESS) {
		printf("Error at key generation");
		return Status;
	}
	/* persist for recovery & fault tolerance
	potential exposure if physical hardware is tampered/compromised;
	in alternative implementations the binary file might get further encrypted or memory mapped instead. Or have no persistent mode.
	*/
	SAVETODISK(NEW_PUBLIC_LOCATION, PUBLIC_LOCATION, 32, PublicKey);
	SAVETODISK(NEW_PRIVATE_LOCATION, PRIVATE_LOCATION, 32, PrivateKey);
	return Status;
}


/*  retrieves either persisted public key or the generates a new key */
void getPublicKey(unsigned char * PublicKey) {
	FILE * f = fopen(PUBLIC_LOCATION, "rb");
	if (f == 0) {
		fclose(f);
		generatePublicKey(); // could also fail instead of generating new key if preferred
		return getPublicKey(PublicKey);
	}
	fread(PublicKey, sizeof(*PublicKey), 32, f);
    fclose(f);
	return;
}

/* prints the private key*/
void getPrivateKey(unsigned char * PrivateKey) {
	FILE * f = fopen(PRIVATE_LOCATION, "rb");
	fread(PrivateKey, sizeof(*PrivateKey), 32, f);
	fclose(f);
}

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


// Base 64 encoder
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length){
	*output_length = 4 * ((input_length + 2) / 3);
	
	char *encoded_data = malloc(*output_length);
	if(encoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;){
		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3f];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3f];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3f];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3f];
	}

	for (int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';
	return encoded_data;
}

// Base 64 decoder
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length){
	if(decoding_table == NULL) build_decoding_table();

	if(input_length % 4 != 0) return NULL;

	*output_length = input_length / 4 * 3;
	if(data[input_length - 1] == '=') (*output_length)--;
	if(data[input_length - 2] == '=') (*output_length)--;

	unsigned char *decoded_data = malloc(*output_length);
	if(decoded_data == NULL) return NULL;

	for(int i = 0, j = 0; i < input_length;){
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

		uint32_t triple = (sextet_a << 3 * 6)
		+ (sextet_b << 2 * 6)
		+ (sextet_c << 1 * 6)
		+ (sextet_d << 0 * 6);

		if(j<*output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if(j<*output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if(j<*output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}
	return decoded_data;
}

void build_decoding_table() {
	decoding_table = malloc(256);
	for(int i = 0; i < 64; i++){
		decoding_table[(unsigned char) encoding_table[i]] = i;
	}
}

size_t b64_encoded_size(size_t inlen){
	size_t ret;
	ret = inlen;
	if(inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;
	return ret;
}

/* TO-DO: Pick a library or a self implementation, for encoding the newly generated SecretAgreement to base64 encoding for easier transfer over the wire in json
When validating the secretagreement presented by the the 'other party' I can decode from base64 and compare the
secretagreements to return a success status
*/
int main(int argc, char **argv)
{
	// this can be called in multiple modes as per functions below. use cases to complete with python integration: 1-> return public key (server), 2-> return a new secretagreement for a given public key, 3 -> validate a secret agreement for a given public key + secret agreement
	unsigned char PublicKey[32], PrivateKey[32], SecretAgreement[32], PresentedSecretAgreement[32];
	unsigned char *presentedSecretAgreementDecoded;
	if (argc == 1) {
		getPublicKey(PublicKey);
		printf(PublicKey);
	}
	if (argc == 2) {
		getPrivateKey(PrivateKey);
		//need to write a converter function for base64 to 32 bytes conversion (Decoder)
		//decoding the received base64 encoded public key
		unsigned char receivedPublicKey = *base64_decode(argv[1], sizeof(argv[1]), 32);
		generateSecretAgreement(PrivateKey, receivedPublicKey, SecretAgreement);
		//encoding the generatedSecretAgreement with base64 to be sent over an api call in Python
		size_t secretSize = sizeof(SecretAgreement);
		size_t b64EncodedSecretSize = b64_encoded_size(secretSize);
		printf(*base64_encode(SecretAgreement, secretSize, b64EncodedSecretSize));
	}

	if (argc == 3) {
		// running on validation mode (could be ported to python)
		getPrivateKey(PrivateKey);
		//need to write a converter function for base64 to 32 bytes conversion (Decoder)
		unsigned char receivedPublicKey = *base64_decode(argv[1], sizeof(argv[1]), 32);
		generateSecretAgreement(PrivateKey, argv[1], SecretAgreement);
		bool passed = true;
		// PresentedSecretAgreement = argv[2] decoded from base64 to 32 bytes
		presentedSecretAgreementDecoded = *base64_decode(argv[2], sizeof(argv[2]), 32);
		for (int i = 0; i < 32; i++) {
			if (presentedSecretAgreementDecoded[i] != SecretAgreement[i]) {
				passed = false;
				printf("ERROR!");
				break;
			}
		}
		printf("SUCCESS");
	}
	return 0;
}

