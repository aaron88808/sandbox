#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <string.h>

int main (int ac, char **av) {
    if (ac < 4) {
	fprintf(stderr, "usage: %s {key (256-bits)} {iv (128-bits)} {plaintext}\n", av[0]);
	exit(1);
    }

    unsigned char *key = (unsigned char *) av[1];
    unsigned char *iv  = (unsigned char *) av[2];
    unsigned char *plaintext  = (unsigned char *) av[3];
    
    int plaintext_len = strlen(plaintext);
    int buffer_len = 2 * plaintext_len;
    unsigned char *ciphertext = (unsigned char *) malloc(buffer_len);
    if (ciphertext == NULL) {
	fprintf(stderr, "%s: failed to malloc %d bytes for ciphertext\n", av[0], buffer_len);
	exit(1);
    }
    memset(ciphertext, '\0', buffer_len);

    unsigned char *decrypted_text = (unsigned char *) malloc(buffer_len);
    if (decrypted_text == NULL) {
	fprintf(stderr, "%s: failed to malloc %d bytes for decrypted_text\n", av[0], buffer_len);
	exit(1);
    }
    memset(decrypted_text, '\0', buffer_len);
    

    int ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext);

    printf("%s: ciphertext: '", av[0]);
    int i;
    for (i = 0; i < ciphertext_len; i++) {
	printf(" %02X", ciphertext[i]);
    }
    printf("'\n");

    int decrypted_text_len = decrypt(ciphertext, ciphertext_len, key, iv, decrypted_text);

    decrypted_text[decrypted_text_len] = '\0';

    printf("%s: decrypted text: '%s'\n", av[0], decrypted_text);
    
    free(decrypted_text);
    free(ciphertext);

    return 0;
}

void handleErrors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int encrypt(unsigned char *plaintext,
	    int plaintext_len,
	    unsigned char *key,
	    unsigned char *iv,
	    unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
	handleErrors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
	handleErrors();
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
	handleErrors();
    }

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
	handleErrors();
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext,
	    int ciphertext_len,
	    unsigned char *key,
	    unsigned char *iv,
	    unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
	handleErrors();
    }

    int len = 0;
    int plaintext_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
	handleErrors();
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
	handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
	handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
