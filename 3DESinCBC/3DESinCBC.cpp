#include <stdio.h>
#include < stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include "openssl/applink.c"

DES_cblock key1 = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
DES_cblock key2 = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
DES_cblock key3 = { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 };
DES_key_schedule Schkey1, Schkey2, Schkey3;

void print_data(const char *tittle, const void* data, int len);

int main() {
	unsigned char input_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };

	DES_cblock iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	DES_set_odd_parity(&iv);

	if (-2 == (DES_set_key_checked(&key1, &Schkey1) || DES_set_key_checked(&key2, &Schkey2) || DES_set_key_checked(&key3, &Schkey3))) {
		printf("Weak key....\n");
		return 1;
	}

	unsigned char* cipher[sizeof(input_data)];
	unsigned char* text[sizeof(input_data)];

	DES_ede3_cbc_encrypt((unsigned char*)input_data, (unsigned char*)cipher, sizeof(input_data), &Schkey1, &Schkey2, &Schkey3, &iv, DES_DECRYPT);

	print_data("\n Original ", input_data, sizeof(input_data));
	print_data("\n Encrypted", cipher, sizeof(input_data));
	print_data("\n Decrypted", text, sizeof(input_data));

	return 0;

}
void print_data(const char *tittle, const void* data, int len) {
	printf("%s: ", tittle);
	const unsigned char * p = (const unsigned char*)data;
	int i = 0;

	for (;i < len;++i)
		printf("%02x ", *p++);

	printf("\n");
}