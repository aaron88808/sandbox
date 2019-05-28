#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <string.h>

int main (int ac, char **av) {
    if (ac < 2) {
	fprintf(stderr, "usage: %s {salt-length}\n", av[0]);
	exit(1);
    }

    char *salt_length_str = av[1];

    int salt_length = 0;

    sscanf(salt_length_str, "%d", &salt_length);
    
    if (salt_length <= 0) {
      fprintf(stderr, "%s: salt length must be greater than 0\n", av[0]);
      exit(1);
    }

    char *salt = malloc(salt_length);
    if (salt == NULL) {
      fprintf(stderr, "%s: could not allocate memory for salt of length %d\n", av[0], salt_length);
      exit(1);
    }
    int ok = RAND_bytes(salt, salt_length);
    if (!ok) {
      char errbuf[1024];
      ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
      fprintf(stderr, "%s: could not generate %d random bytes: '%s'\n", av[0], salt_length, errbuf);
      exit(1);
    }

    BIO *bio, *b64;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_push(b64, bio);
    BIO_write(b64, salt, salt_length);
    BIO_flush(b64);
    fprintf(stdout, "\n");

    BIO_free_all(b64);    

    free(salt);

    return 0;
}

