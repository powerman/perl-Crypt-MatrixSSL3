#define PERL_constant_NOTFOUND	1
#define PERL_constant_NOTDEF	2
#define PERL_constant_ISIV	3
#define PERL_constant_ISNO	4
#define PERL_constant_ISNV	5
#define PERL_constant_ISPV	6
#define PERL_constant_ISPVN	7
#define PERL_constant_ISSV	8
#define PERL_constant_ISUNDEF	9
#define PERL_constant_ISUV	10
#define PERL_constant_ISYES	11

#ifndef NVTYPE
typedef double NV; /* 5.6 and later define NVTYPE, and typedef NV to it.  */
#endif
#ifndef aTHX_
#define aTHX_ /* 5.6 or later define this for threading support.  */
#endif
#ifndef pTHX_
#define pTHX_ /* 5.6 or later define this for threading support.  */
#endif

static int
constant_11 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     PS_ARG_FAIL PS_MEM_FAIL TLS_MAJ_VER TLS_MIN_VER */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'A':
    if (memEQ(name, "TLS_MAJ_VER", 11)) {
    /*                    ^            */
#ifdef TLS_MAJ_VER
      *iv_return = TLS_MAJ_VER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "PS_ARG_FAIL", 11)) {
    /*                    ^            */
#ifdef PS_ARG_FAIL
      *iv_return = PS_ARG_FAIL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "TLS_MIN_VER", 11)) {
    /*                    ^            */
#ifdef TLS_MIN_VER
      *iv_return = TLS_MIN_VER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "PS_MEM_FAIL", 11)) {
    /*                    ^            */
#ifdef PS_MEM_FAIL
      *iv_return = PS_MEM_FAIL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_12 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SSL2_MAJ_VER SSL3_MAJ_VER SSL3_MIN_VER */
  /* Offset 3 gives the best switch position.  */
  switch (name[3]) {
  case '2':
    if (memEQ(name, "SSL2_MAJ_VER", 12)) {
    /*                  ^               */
#ifdef SSL2_MAJ_VER
      *iv_return = SSL2_MAJ_VER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '3':
    if (memEQ(name, "SSL3_MAJ_VER", 12)) {
    /*                  ^               */
#ifdef SSL3_MAJ_VER
      *iv_return = SSL3_MAJ_VER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SSL3_MIN_VER", 12)) {
    /*                  ^               */
#ifdef SSL3_MIN_VER
      *iv_return = SSL3_MIN_VER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_15 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     MATRIXSSL_ERROR TLS_1_1_MIN_VER TLS_1_2_MIN_VER */
  /* Offset 6 gives the best switch position.  */
  switch (name[6]) {
  case '1':
    if (memEQ(name, "TLS_1_1_MIN_VER", 15)) {
    /*                     ^               */
#ifdef TLS_1_1_MIN_VER
      *iv_return = TLS_1_1_MIN_VER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '2':
    if (memEQ(name, "TLS_1_2_MIN_VER", 15)) {
    /*                     ^               */
#ifdef TLS_1_2_MIN_VER
      *iv_return = TLS_1_2_MIN_VER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "MATRIXSSL_ERROR", 15)) {
    /*                     ^               */
#ifdef MATRIXSSL_ERROR
      *iv_return = MATRIXSSL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_21 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SSL_ALERT_LEVEL_FATAL SSL_MAX_PLAINTEXT_LEN SSL_RSA_WITH_NULL_MD5
     SSL_RSA_WITH_NULL_SHA */
  /* Offset 19 gives the best switch position.  */
  switch (name[19]) {
  case 'A':
    if (memEQ(name, "SSL_ALERT_LEVEL_FATAL", 21)) {
    /*                                  ^        */
#ifdef SSL_ALERT_LEVEL_FATAL
      *iv_return = SSL_ALERT_LEVEL_FATAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SSL_RSA_WITH_NULL_MD5", 21)) {
    /*                                  ^        */
#ifdef SSL_RSA_WITH_NULL_MD5
      *iv_return = SSL_RSA_WITH_NULL_MD5;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SSL_MAX_PLAINTEXT_LEN", 21)) {
    /*                                  ^        */
#ifdef SSL_MAX_PLAINTEXT_LEN
      *iv_return = SSL_MAX_PLAINTEXT_LEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "SSL_RSA_WITH_NULL_SHA", 21)) {
    /*                                  ^        */
#ifdef SSL_RSA_WITH_NULL_SHA
      *iv_return = SSL_RSA_WITH_NULL_SHA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_22 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     MATRIXSSL_REQUEST_RECV MATRIXSSL_REQUEST_SEND SSL_ALERT_CLOSE_NOTIFY
     SSL_ALERT_DECODE_ERROR */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'C':
    if (memEQ(name, "MATRIXSSL_REQUEST_RECV", 22)) {
    /*                                   ^        */
#ifdef MATRIXSSL_REQUEST_RECV
      *iv_return = MATRIXSSL_REQUEST_RECV;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "SSL_ALERT_CLOSE_NOTIFY", 22)) {
    /*                                   ^        */
#ifdef SSL_ALERT_CLOSE_NOTIFY
      *iv_return = SSL_ALERT_CLOSE_NOTIFY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "MATRIXSSL_REQUEST_SEND", 22)) {
    /*                                   ^        */
#ifdef MATRIXSSL_REQUEST_SEND
      *iv_return = MATRIXSSL_REQUEST_SEND;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SSL_ALERT_DECODE_ERROR", 22)) {
    /*                                   ^        */
#ifdef SSL_ALERT_DECODE_ERROR
      *iv_return = SSL_ALERT_DECODE_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_23 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     MATRIXSSL_REQUEST_CLOSE MATRIXSSL_VERSION_MAJOR MATRIXSSL_VERSION_MINOR
     MATRIXSSL_VERSION_PATCH SSL_ALERT_ACCESS_DENIED SSL_ALERT_DECRYPT_ERROR
     SSL_ALERT_LEVEL_WARNING SSL_NULL_WITH_NULL_NULL */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'I':
    if (memEQ(name, "SSL_ALERT_ACCESS_DENIED", 23)) {
    /*                                   ^         */
#ifdef SSL_ALERT_ACCESS_DENIED
      *iv_return = SSL_ALERT_ACCESS_DENIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SSL_ALERT_LEVEL_WARNING", 23)) {
    /*                                   ^         */
#ifdef SSL_ALERT_LEVEL_WARNING
      *iv_return = SSL_ALERT_LEVEL_WARNING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'J':
    if (memEQ(name, "MATRIXSSL_VERSION_MAJOR", 23)) {
    /*                                   ^         */
#ifdef MATRIXSSL_VERSION_MAJOR
      *iv_return = MATRIXSSL_VERSION_MAJOR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "MATRIXSSL_VERSION_MINOR", 23)) {
    /*                                   ^         */
#ifdef MATRIXSSL_VERSION_MINOR
      *iv_return = MATRIXSSL_VERSION_MINOR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "MATRIXSSL_REQUEST_CLOSE", 23)) {
    /*                                   ^         */
#ifdef MATRIXSSL_REQUEST_CLOSE
      *iv_return = MATRIXSSL_REQUEST_CLOSE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SSL_ALERT_DECRYPT_ERROR", 23)) {
    /*                                   ^         */
#ifdef SSL_ALERT_DECRYPT_ERROR
      *iv_return = SSL_ALERT_DECRYPT_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "MATRIXSSL_VERSION_PATCH", 23)) {
    /*                                   ^         */
#ifdef MATRIXSSL_VERSION_PATCH
      *iv_return = MATRIXSSL_VERSION_PATCH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "SSL_NULL_WITH_NULL_NULL", 23)) {
    /*                                   ^         */
#ifdef SSL_NULL_WITH_NULL_NULL
      *iv_return = SSL_NULL_WITH_NULL_NULL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_24 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     MATRIXSSL_RECEIVED_ALERT SSL_ALERT_BAD_RECORD_MAC SSL_ALERT_INTERNAL_ERROR
     SSL_ALERT_NO_CERTIFICATE SSL_MAX_DISABLED_CIPHERS SSL_RSA_WITH_RC4_128_MD5
     SSL_RSA_WITH_RC4_128_SHA */
  /* Offset 23 gives the best switch position.  */
  switch (name[23]) {
  case '5':
    if (memEQ(name, "SSL_RSA_WITH_RC4_128_MD", 23)) {
    /*                                      5      */
#ifdef SSL_RSA_WITH_RC4_128_MD5
      *iv_return = SSL_RSA_WITH_RC4_128_MD5;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'A':
    if (memEQ(name, "SSL_RSA_WITH_RC4_128_SH", 23)) {
    /*                                      A      */
#ifdef SSL_RSA_WITH_RC4_128_SHA
      *iv_return = SSL_RSA_WITH_RC4_128_SHA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "SSL_ALERT_BAD_RECORD_MA", 23)) {
    /*                                      C      */
#ifdef SSL_ALERT_BAD_RECORD_MAC
      *iv_return = SSL_ALERT_BAD_RECORD_MAC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SSL_ALERT_NO_CERTIFICAT", 23)) {
    /*                                      E      */
#ifdef SSL_ALERT_NO_CERTIFICATE
      *iv_return = SSL_ALERT_NO_CERTIFICATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SSL_ALERT_INTERNAL_ERRO", 23)) {
    /*                                      R      */
#ifdef SSL_ALERT_INTERNAL_ERROR
      *iv_return = SSL_ALERT_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SSL_MAX_DISABLED_CIPHER", 23)) {
    /*                                      S      */
#ifdef SSL_MAX_DISABLED_CIPHERS
      *iv_return = SSL_MAX_DISABLED_CIPHERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "MATRIXSSL_RECEIVED_ALER", 23)) {
    /*                                      T      */
#ifdef MATRIXSSL_RECEIVED_ALERT
      *iv_return = MATRIXSSL_RECEIVED_ALERT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_25 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SSL_ALERT_BAD_CERTIFICATE SSL_ALERT_RECORD_OVERFLOW
     SSL_ALLOW_ANON_CONNECTION SSL_OPTION_FULL_HANDSHAKE */
  /* Offset 11 gives the best switch position.  */
  switch (name[11]) {
  case 'A':
    if (memEQ(name, "SSL_ALERT_BAD_CERTIFICATE", 25)) {
    /*                          ^                    */
#ifdef SSL_ALERT_BAD_CERTIFICATE
      *iv_return = SSL_ALERT_BAD_CERTIFICATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SSL_ALERT_RECORD_OVERFLOW", 25)) {
    /*                          ^                    */
#ifdef SSL_ALERT_RECORD_OVERFLOW
      *iv_return = SSL_ALERT_RECORD_OVERFLOW;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "SSL_OPTION_FULL_HANDSHAKE", 25)) {
    /*                          ^                    */
#ifdef SSL_OPTION_FULL_HANDSHAKE
      *iv_return = SSL_OPTION_FULL_HANDSHAKE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SSL_ALLOW_ANON_CONNECTION", 25)) {
    /*                          ^                    */
#ifdef SSL_ALLOW_ANON_CONNECTION
      *iv_return = SSL_ALLOW_ANON_CONNECTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_27 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SSL_ALERT_DECRYPTION_FAILED SSL_ALERT_HANDSHAKE_FAILURE
     SSL_ALERT_ILLEGAL_PARAMETER */
  /* Offset 10 gives the best switch position.  */
  switch (name[10]) {
  case 'D':
    if (memEQ(name, "SSL_ALERT_DECRYPTION_FAILED", 27)) {
    /*                         ^                       */
#ifdef SSL_ALERT_DECRYPTION_FAILED
      *iv_return = SSL_ALERT_DECRYPTION_FAILED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "SSL_ALERT_HANDSHAKE_FAILURE", 27)) {
    /*                         ^                       */
#ifdef SSL_ALERT_HANDSHAKE_FAILURE
      *iv_return = SSL_ALERT_HANDSHAKE_FAILURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SSL_ALERT_ILLEGAL_PARAMETER", 27)) {
    /*                         ^                       */
#ifdef SSL_ALERT_ILLEGAL_PARAMETER
      *iv_return = SSL_ALERT_ILLEGAL_PARAMETER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_28 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     MATRIXSSL_HANDSHAKE_COMPLETE SSL_ALERT_UNEXPECTED_MESSAGE
     TLS_RSA_WITH_AES_128_CBC_SHA TLS_RSA_WITH_AES_256_CBC_SHA */
  /* Offset 17 gives the best switch position.  */
  switch (name[17]) {
  case '1':
    if (memEQ(name, "TLS_RSA_WITH_AES_128_CBC_SHA", 28)) {
    /*                                ^                 */
#ifdef TLS_RSA_WITH_AES_128_CBC_SHA
      *iv_return = TLS_RSA_WITH_AES_128_CBC_SHA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '2':
    if (memEQ(name, "TLS_RSA_WITH_AES_256_CBC_SHA", 28)) {
    /*                                ^                 */
#ifdef TLS_RSA_WITH_AES_256_CBC_SHA
      *iv_return = TLS_RSA_WITH_AES_256_CBC_SHA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "MATRIXSSL_HANDSHAKE_COMPLETE", 28)) {
    /*                                ^                 */
#ifdef MATRIXSSL_HANDSHAKE_COMPLETE
      *iv_return = MATRIXSSL_HANDSHAKE_COMPLETE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SSL_ALERT_UNEXPECTED_MESSAGE", 28)) {
    /*                                ^                 */
#ifdef SSL_ALERT_UNEXPECTED_MESSAGE
      *iv_return = SSL_ALERT_UNEXPECTED_MESSAGE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_29 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SSL_ALERT_CERTIFICATE_EXPIRED SSL_ALERT_CERTIFICATE_REVOKED
     SSL_ALERT_CERTIFICATE_UNKNOWN SSL_RSA_WITH_3DES_EDE_CBC_SHA */
  /* Offset 26 gives the best switch position.  */
  switch (name[26]) {
  case 'K':
    if (memEQ(name, "SSL_ALERT_CERTIFICATE_REVOKED", 29)) {
    /*                                         ^         */
#ifdef SSL_ALERT_CERTIFICATE_REVOKED
      *iv_return = SSL_ALERT_CERTIFICATE_REVOKED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SSL_ALERT_CERTIFICATE_UNKNOWN", 29)) {
    /*                                         ^         */
#ifdef SSL_ALERT_CERTIFICATE_UNKNOWN
      *iv_return = SSL_ALERT_CERTIFICATE_UNKNOWN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SSL_ALERT_CERTIFICATE_EXPIRED", 29)) {
    /*                                         ^         */
#ifdef SSL_ALERT_CERTIFICATE_EXPIRED
      *iv_return = SSL_ALERT_CERTIFICATE_EXPIRED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SSL_RSA_WITH_3DES_EDE_CBC_SHA", 29)) {
    /*                                         ^         */
#ifdef SSL_RSA_WITH_3DES_EDE_CBC_SHA
      *iv_return = SSL_RSA_WITH_3DES_EDE_CBC_SHA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant (pTHX_ const char *name, STRLEN len, IV *iv_return) {
  /* Initially switch on the length of the name.  */
  /* When generated this function returned values for the list of names given
     in this section of perl code.  Rather than manually editing these functions
     to add or remove constants, which would result in this comment and section
     of code becoming inaccurate, we recommend that you edit this section of
     code, and use it to regenerate a new set of constant functions which you
     then use to replace the originals.

     Regenerate these constant functions by feeding this entire source file to
     perl -x

#!/usr/bin/perl5.12.4 -w
use ExtUtils::Constant qw (constant_types C_constant XS_constant);

my $types = {map {($_, 1)} qw(IV)};
my @names = (qw(MATRIXSSL_APP_DATA MATRIXSSL_ERROR MATRIXSSL_HANDSHAKE_COMPLETE
	       MATRIXSSL_RECEIVED_ALERT MATRIXSSL_REQUEST_CLOSE
	       MATRIXSSL_REQUEST_RECV MATRIXSSL_REQUEST_SEND MATRIXSSL_SUCCESS
	       MATRIXSSL_VERSION_MAJOR MATRIXSSL_VERSION_MINOR
	       MATRIXSSL_VERSION_PATCH PS_ARG_FAIL PS_CERT_AUTH_FAIL PS_FAILURE
	       PS_FALSE PS_LIMIT_FAIL PS_MEM_FAIL PS_PARSE_FAIL
	       PS_PLATFORM_FAIL PS_PROTOCOL_FAIL PS_SUCCESS PS_TRUE
	       PS_UNSUPPORTED_FAIL SSL2_MAJ_VER SSL3_MAJ_VER SSL3_MIN_VER
	       SSL_ALERT_ACCESS_DENIED SSL_ALERT_BAD_CERTIFICATE
	       SSL_ALERT_BAD_RECORD_MAC SSL_ALERT_CERTIFICATE_EXPIRED
	       SSL_ALERT_CERTIFICATE_REVOKED SSL_ALERT_CERTIFICATE_UNKNOWN
	       SSL_ALERT_CLOSE_NOTIFY SSL_ALERT_DECODE_ERROR
	       SSL_ALERT_DECOMPRESSION_FAILURE SSL_ALERT_DECRYPTION_FAILED
	       SSL_ALERT_DECRYPT_ERROR SSL_ALERT_HANDSHAKE_FAILURE
	       SSL_ALERT_ILLEGAL_PARAMETER SSL_ALERT_INTERNAL_ERROR
	       SSL_ALERT_LEVEL_FATAL SSL_ALERT_LEVEL_WARNING SSL_ALERT_NONE
	       SSL_ALERT_NO_CERTIFICATE SSL_ALERT_NO_RENEGOTIATION
	       SSL_ALERT_PROTOCOL_VERSION SSL_ALERT_RECORD_OVERFLOW
	       SSL_ALERT_UNEXPECTED_MESSAGE SSL_ALERT_UNKNOWN_CA
	       SSL_ALERT_UNSUPPORTED_CERTIFICATE
	       SSL_ALERT_UNSUPPORTED_EXTENSION SSL_ALLOW_ANON_CONNECTION
	       SSL_MAX_DISABLED_CIPHERS SSL_MAX_PLAINTEXT_LEN
	       SSL_NULL_WITH_NULL_NULL SSL_OPTION_FULL_HANDSHAKE
	       SSL_RSA_WITH_3DES_EDE_CBC_SHA SSL_RSA_WITH_NULL_MD5
	       SSL_RSA_WITH_NULL_SHA SSL_RSA_WITH_RC4_128_MD5
	       SSL_RSA_WITH_RC4_128_SHA TLS_1_1_MIN_VER TLS_1_2_MIN_VER
	       TLS_EMPTY_RENEGOTIATION_INFO_SCSV TLS_MAJ_VER TLS_MIN_VER
	       TLS_RSA_WITH_AES_128_CBC_SHA TLS_RSA_WITH_AES_256_CBC_SHA));

print constant_types(), "\n"; # macro defs
foreach (C_constant ("Crypt::MatrixSSL3", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "\n#### XS Section:\n";
print XS_constant ("Crypt::MatrixSSL3", $types);
__END__
   */

  switch (len) {
  case 7:
    if (memEQ(name, "PS_TRUE", 7)) {
#ifdef PS_TRUE
      *iv_return = PS_TRUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 8:
    if (memEQ(name, "PS_FALSE", 8)) {
#ifdef PS_FALSE
      *iv_return = PS_FALSE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 10:
    /* Names all of length 10.  */
    /* PS_FAILURE PS_SUCCESS */
    /* Offset 8 gives the best switch position.  */
    switch (name[8]) {
    case 'R':
      if (memEQ(name, "PS_FAILURE", 10)) {
      /*                       ^        */
#ifdef PS_FAILURE
        *iv_return = PS_FAILURE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'S':
      if (memEQ(name, "PS_SUCCESS", 10)) {
      /*                       ^        */
#ifdef PS_SUCCESS
        *iv_return = PS_SUCCESS;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 11:
    return constant_11 (aTHX_ name, iv_return);
    break;
  case 12:
    return constant_12 (aTHX_ name, iv_return);
    break;
  case 13:
    /* Names all of length 13.  */
    /* PS_LIMIT_FAIL PS_PARSE_FAIL */
    /* Offset 3 gives the best switch position.  */
    switch (name[3]) {
    case 'L':
      if (memEQ(name, "PS_LIMIT_FAIL", 13)) {
      /*                  ^                */
#ifdef PS_LIMIT_FAIL
        *iv_return = PS_LIMIT_FAIL;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'P':
      if (memEQ(name, "PS_PARSE_FAIL", 13)) {
      /*                  ^                */
#ifdef PS_PARSE_FAIL
        *iv_return = PS_PARSE_FAIL;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 14:
    if (memEQ(name, "SSL_ALERT_NONE", 14)) {
#ifdef SSL_ALERT_NONE
      *iv_return = SSL_ALERT_NONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 15:
    return constant_15 (aTHX_ name, iv_return);
    break;
  case 16:
    /* Names all of length 16.  */
    /* PS_PLATFORM_FAIL PS_PROTOCOL_FAIL */
    /* Offset 10 gives the best switch position.  */
    switch (name[10]) {
    case 'L':
      if (memEQ(name, "PS_PROTOCOL_FAIL", 16)) {
      /*                         ^            */
#ifdef PS_PROTOCOL_FAIL
        *iv_return = PS_PROTOCOL_FAIL;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'M':
      if (memEQ(name, "PS_PLATFORM_FAIL", 16)) {
      /*                         ^            */
#ifdef PS_PLATFORM_FAIL
        *iv_return = PS_PLATFORM_FAIL;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 17:
    /* Names all of length 17.  */
    /* MATRIXSSL_SUCCESS PS_CERT_AUTH_FAIL */
    /* Offset 6 gives the best switch position.  */
    switch (name[6]) {
    case 'S':
      if (memEQ(name, "MATRIXSSL_SUCCESS", 17)) {
      /*                     ^                 */
#ifdef MATRIXSSL_SUCCESS
        *iv_return = MATRIXSSL_SUCCESS;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "PS_CERT_AUTH_FAIL", 17)) {
      /*                     ^                 */
#ifdef PS_CERT_AUTH_FAIL
        *iv_return = PS_CERT_AUTH_FAIL;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 18:
    if (memEQ(name, "MATRIXSSL_APP_DATA", 18)) {
#ifdef MATRIXSSL_APP_DATA
      *iv_return = MATRIXSSL_APP_DATA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 19:
    if (memEQ(name, "PS_UNSUPPORTED_FAIL", 19)) {
#ifdef PS_UNSUPPORTED_FAIL
      *iv_return = PS_UNSUPPORTED_FAIL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 20:
    if (memEQ(name, "SSL_ALERT_UNKNOWN_CA", 20)) {
#ifdef SSL_ALERT_UNKNOWN_CA
      *iv_return = SSL_ALERT_UNKNOWN_CA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 21:
    return constant_21 (aTHX_ name, iv_return);
    break;
  case 22:
    return constant_22 (aTHX_ name, iv_return);
    break;
  case 23:
    return constant_23 (aTHX_ name, iv_return);
    break;
  case 24:
    return constant_24 (aTHX_ name, iv_return);
    break;
  case 25:
    return constant_25 (aTHX_ name, iv_return);
    break;
  case 26:
    /* Names all of length 26.  */
    /* SSL_ALERT_NO_RENEGOTIATION SSL_ALERT_PROTOCOL_VERSION */
    /* Offset 22 gives the best switch position.  */
    switch (name[22]) {
    case 'S':
      if (memEQ(name, "SSL_ALERT_PROTOCOL_VERSION", 26)) {
      /*                                     ^          */
#ifdef SSL_ALERT_PROTOCOL_VERSION
        *iv_return = SSL_ALERT_PROTOCOL_VERSION;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "SSL_ALERT_NO_RENEGOTIATION", 26)) {
      /*                                     ^          */
#ifdef SSL_ALERT_NO_RENEGOTIATION
        *iv_return = SSL_ALERT_NO_RENEGOTIATION;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 27:
    return constant_27 (aTHX_ name, iv_return);
    break;
  case 28:
    return constant_28 (aTHX_ name, iv_return);
    break;
  case 29:
    return constant_29 (aTHX_ name, iv_return);
    break;
  case 31:
    /* Names all of length 31.  */
    /* SSL_ALERT_DECOMPRESSION_FAILURE SSL_ALERT_UNSUPPORTED_EXTENSION */
    /* Offset 18 gives the best switch position.  */
    switch (name[18]) {
    case 'S':
      if (memEQ(name, "SSL_ALERT_DECOMPRESSION_FAILURE", 31)) {
      /*                                 ^                   */
#ifdef SSL_ALERT_DECOMPRESSION_FAILURE
        *iv_return = SSL_ALERT_DECOMPRESSION_FAILURE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "SSL_ALERT_UNSUPPORTED_EXTENSION", 31)) {
      /*                                 ^                   */
#ifdef SSL_ALERT_UNSUPPORTED_EXTENSION
        *iv_return = SSL_ALERT_UNSUPPORTED_EXTENSION;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 33:
    /* Names all of length 33.  */
    /* SSL_ALERT_UNSUPPORTED_CERTIFICATE TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
    /* Offset 0 gives the best switch position.  */
    switch (*name++) {
    case 'S':
      if (memEQ(name, "SL_ALERT_UNSUPPORTED_CERTIFICATE", 32)) {
      /*                S                                       */
#ifdef SSL_ALERT_UNSUPPORTED_CERTIFICATE
        *iv_return = SSL_ALERT_UNSUPPORTED_CERTIFICATE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "LS_EMPTY_RENEGOTIATION_INFO_SCSV", 32)) {
      /*                T                                       */
#ifdef TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        *iv_return = TLS_EMPTY_RENEGOTIATION_INFO_SCSV;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

