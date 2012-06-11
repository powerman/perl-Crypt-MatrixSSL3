#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "matrixssl-3-3-open/core/coreApi.h"
#include "matrixssl-3-3-open/crypto/cryptoApi.h"
#include "matrixssl-3-3-open/matrixssl/matrixssllib.h"
#include "matrixssl-3-3-open/matrixssl/matrixsslApi.h"
#include "matrixssl-3-3-open/matrixssl/version.h"

#include "const-c.inc"

/******************************************************************************/

typedef struct sslKeys_t	Crypt_MatrixSSL3_Keys;
typedef struct sslSessionId_t	Crypt_MatrixSSL3_SessID;
typedef struct ssl_t		Crypt_MatrixSSL3_Sess;
typedef struct tlsExtension_t	Crypt_MatrixSSL3_HelloExt;

static int objects = 0;

void
add_obj()
{
    int		rc;

    if(objects == 0){
	rc = matrixSslOpen();
	if(rc != PS_SUCCESS)
	    croak("%d", rc);
    }
    objects++;
}

void
del_obj()
{
    objects--;
    if(objects == 0){
	matrixSslClose();
    }
    else if(objects < 0)
	croak("del_obj: internal error");
}

/*
 * my_hv_store() helper macro to avoid writting hash key names twice or
 * hardcoding their length
#define myVAL_LEN(k)	    (k), strlen((k))
 */

#define my_hv_store(myh1,myh2,myh3,myh4)	hv_store((myh1),(myh2),(strlen((myh2))),(myh3),(myh4))

/*
 * Hash which will contain perl's certValidate CODEREF
 * between matrixSslNew*Session() and matrixSslDeleteSession().
 * 
 * Hash format:
 *  key     integer representation of $ssl (ssl_t *)
 *  value   \&cb_certValidate
 */
static HV *	certValidatorArg = NULL;

int
appCertValidator(ssl_t *ssl, psX509Cert_t *certInfo, int alert)
{
	dSP;
	SV *	key;
	SV *	callback;
	AV *	certs;
	int	res;

	ENTER;
	SAVETMPS;
	
	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	callback = HeVAL(hv_fetch_ent(certValidatorArg, key, 0, 0));
	
	/* Convert (psX509Cert_t *) structs into array of hashes. */
	certs = (AV *)sv_2mortal((SV *)newAV());
	for (; certInfo != NULL; certInfo=certInfo->next) {
		HV *	sslCertInfo;
		HV *	subjectAltName;
		HV *	subject;
		HV *	issuer;

		subjectAltName = newHV();

		subject = newHV();
		if (certInfo->subject.country != NULL)
			my_hv_store(subject, "country",
				newSVpv(certInfo->subject.country, 0), 0);
		if (certInfo->subject.state != NULL)
			my_hv_store(subject, "state",
				newSVpv(certInfo->subject.state, 0), 0);
		if (certInfo->subject.locality != NULL)
			my_hv_store(subject, "locality",
				newSVpv(certInfo->subject.locality, 0), 0);
		if (certInfo->subject.organization != NULL)
			my_hv_store(subject, "organization",
				newSVpv(certInfo->subject.organization, 0), 0);
		if (certInfo->subject.orgUnit != NULL)
			my_hv_store(subject, "orgUnit",
				newSVpv(certInfo->subject.orgUnit, 0), 0);
		if (certInfo->subject.commonName != NULL)
			my_hv_store(subject, "commonName",
				newSVpv(certInfo->subject.commonName, 0), 0);

		issuer = newHV();
		if (certInfo->issuer.country != NULL)
			my_hv_store(issuer, "country",
				newSVpv(certInfo->issuer.country, 0), 0);
		if (certInfo->issuer.state != NULL)
			my_hv_store(issuer, "state",
				newSVpv(certInfo->issuer.state, 0), 0);
		if (certInfo->issuer.locality != NULL)
			my_hv_store(issuer, "locality",
				newSVpv(certInfo->issuer.locality, 0), 0);
		if (certInfo->issuer.organization != NULL)
			my_hv_store(issuer, "organization",
				newSVpv(certInfo->issuer.organization, 0), 0);
		if (certInfo->issuer.orgUnit != NULL)
			my_hv_store(issuer, "orgUnit",
				newSVpv(certInfo->issuer.orgUnit, 0), 0);
		if (certInfo->issuer.commonName != NULL)
			my_hv_store(issuer, "commonName",
				newSVpv(certInfo->issuer.commonName, 0), 0);

		sslCertInfo = newHV();
		if (certInfo->notBefore != NULL)
			my_hv_store(sslCertInfo, "notBefore",
				newSVpv(certInfo->notBefore, 0), 0);
		if (certInfo->notAfter != NULL)
			my_hv_store(sslCertInfo, "notAfter",
				newSVpv(certInfo->notAfter, 0), 0);
		my_hv_store(sslCertInfo, "subjectAltName",
			newRV(sv_2mortal((SV *)subjectAltName)), 0);
		my_hv_store(sslCertInfo, "subject",
			newRV(sv_2mortal((SV *)subject)), 0);
		my_hv_store(sslCertInfo, "issuer",
			newRV(sv_2mortal((SV *)issuer)), 0);
		my_hv_store(sslCertInfo, "authStatus",
			newSViv(certInfo->authStatus), 0);
		
		// TODO There is a lot more (less useful) fields available…

		av_push(certs, newRV(sv_2mortal((SV *)sslCertInfo)));
	}
	
	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newRV((SV *)certs)));
	XPUSHs(sv_2mortal(newSViv(alert)));
	PUTBACK;

	res = call_sv(callback, G_EVAL|G_SCALAR);
	
	SPAGAIN;
	
	if (res != 1)
		croak("Internal error: perl callback doesn't return 1 scalar!");
	
	if (SvTRUE(ERRSV)) {
		warn("%s", SvPV_nolen(ERRSV));
		warn("die() in certValidate callback not allowed, continue...\n");
		POPs;
		res = -1;
	} else {
		res = POPi;
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return res;
}

/*
 * Hash which will contain perl's extCallback CODEREF
 * between matrixSslNew*Session() and matrixSslDeleteSession().
 * 
 * Hash format:
 *  key     integer representation of $ssl (ssl_t *)
 *  value   \&cb_certValidate
 */
static HV *	extensionCbackArg = NULL;

int
appExtensionCback(ssl_t *ssl, unsigned short type, unsigned short len, void *data)
{
	dSP;
	SV *	key;
	SV *	callback;
	SV *	ext;
	int	res;

	ENTER;
	SAVETMPS;

	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	callback = HeVAL(hv_fetch_ent(extensionCbackArg, key, 0, 0));

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSViv(type)));
	XPUSHs(sv_2mortal(newSVpvn(data, len)));
	PUTBACK;

	res = call_sv(callback, G_EVAL|G_SCALAR);
	
	SPAGAIN;
	
	if (res != 1)
		croak("Internal error: perl callback doesn't return 1 scalar!");
	
	if (SvTRUE(ERRSV)) {
		warn("%s", SvPV_nolen(ERRSV));
		warn("die() in extensionCback callback not allowed, continue...\n");
		POPs;
		res = -1;
	} else {
		res = POPi;
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return res;
}


MODULE = Crypt::MatrixSSL3		PACKAGE = Crypt::MatrixSSL3		

INCLUDE: const-xs.inc

PROTOTYPES: ENABLE


int
set_cipher_suite_enabled_status(cipherId, status);
	short				cipherId;
	int				status;
    CODE:
	add_obj();
	RETVAL = matrixSslSetCipherSuiteEnabledStatus(NULL, cipherId, status);
    OUTPUT:
	RETVAL


MODULE = Crypt::MatrixSSL3	PACKAGE = Crypt::MatrixSSL3::KeysPtr	PREFIX = keys_


Crypt_MatrixSSL3_Keys *
keys_new()
    INIT:
	sslKeys_t *			keys;
	int				rc;
    CODE:
	add_obj();
	rc = matrixSslNewKeys(&keys);
	if(rc != PS_SUCCESS){
	    del_obj();
	    croak("%d", rc);
	}
	RETVAL = (Crypt_MatrixSSL3_Keys *)keys;
    OUTPUT:
	RETVAL


void
keys_DESTROY(keys);
	Crypt_MatrixSSL3_Keys *		keys;
    CODE:
	matrixSslDeleteKeys((sslKeys_t *)keys);
	del_obj();
    OUTPUT:


int
keys_load_rsa(keys, certFile, privFile, privPass, trustedCAcertFiles)
	Crypt_MatrixSSL3_Keys *		keys;
	char *				certFile = SvOK(ST(1)) ? SvPV_nolen(ST(1)) : NULL;
	char *				privFile = SvOK(ST(2)) ? SvPV_nolen(ST(2)) : NULL;
	char *				privPass = SvOK(ST(3)) ? SvPV_nolen(ST(3)) : NULL;
	char *				trustedCAcertFiles = SvOK(ST(4)) ? SvPV_nolen(ST(4)) : NULL;
    CODE:
	RETVAL = matrixSslLoadRsaKeys((sslKeys_t *)keys, certFile, privFile, privPass, trustedCAcertFiles);
    OUTPUT:
	RETVAL


int
keys_load_rsa_mem(keys, cert, priv, trustedCA)
	Crypt_MatrixSSL3_Keys *		keys;
	SV *				cert;
	SV *				priv;
	SV *				trustedCA;
    INIT:
	unsigned char *			certBuf;
	unsigned char *			privBuf;
	unsigned char *			trustedCABuf;
	STRLEN				certLen		= 0;
	STRLEN				privLen		= 0;
	STRLEN				trustedCALen	= 0;
    CODE:
	/* All bufs can contain \0, so SvPV must be used instead of strlen() */
	certBuf     = SvOK(cert)	? SvPV(cert, certLen)		: NULL;
	privBuf     = SvOK(priv)	? SvPV(priv, privLen)		: NULL;
	trustedCABuf= SvOK(trustedCA)	? SvPV(trustedCA, trustedCALen) : NULL;
	RETVAL = matrixSslLoadRsaKeysMem((sslKeys_t *)keys, certBuf, certLen, privBuf, privLen,
			trustedCABuf, trustedCALen);
    OUTPUT:
	RETVAL


int
keys_load_pkcs12(keys, p12File, importPass, macPass, flags)
	Crypt_MatrixSSL3_Keys *		keys;
	char *				p12File    = SvOK(ST(1)) ? SvPV_nolen(ST(1)) : NULL;
	SV *				importPass;
	SV *				macPass;
	int				flags;
    INIT:
	unsigned char *			importPassBuf;
	unsigned char *			macPassBuf;
	STRLEN				importPassLen	= 0;
	STRLEN				macPassLen	= 0;
    CODE:
	importPassBuf= SvOK(importPass) ? SvPV(importPass, importPassLen)	: NULL;
	macPassBuf   = SvOK(macPass)	? SvPV(macPass, macPassLen)		: NULL;
	RETVAL = matrixSslLoadPkcs12((sslKeys_t *)keys, p12File, importPassBuf, importPassLen,
			macPassBuf, macPassLen, flags);
    OUTPUT:
	RETVAL


MODULE = Crypt::MatrixSSL3	PACKAGE = Crypt::MatrixSSL3::SessIDPtr	PREFIX = sessid_


Crypt_MatrixSSL3_SessID *
sessid_new()
    INIT:
	sslSessionId_t *		sessionId;
    CODE:
	add_obj();
	sessionId = (sslSessionId_t *)malloc(sizeof(sslSessionId_t));
	if(sessionId == NULL){
	    del_obj();
	    croak("%d", PS_MEM_FAIL);
	}
	matrixSslInitSessionId((*sessionId));
	RETVAL = (Crypt_MatrixSSL3_SessID *)sessionId;
    OUTPUT:
	RETVAL


void
sessid_DESTROY(sessionId)
	Crypt_MatrixSSL3_SessID *	sessionId;
    CODE:
	free(sessionId);
	del_obj();
    OUTPUT:


void
sessid_init(sessionId)
	Crypt_MatrixSSL3_SessID *	sessionId;
    CODE:
	matrixSslInitSessionId((*(sslSessionId_t *)sessionId));
    OUTPUT:


MODULE = Crypt::MatrixSSL3	PACKAGE = Crypt::MatrixSSL3::SessPtr	PREFIX = sess_


Crypt_MatrixSSL3_Sess *
sess_new_client(keys, sessionId, cipherSuite, certValidator, extensions, extensionCback)
	Crypt_MatrixSSL3_Keys *		keys;
	Crypt_MatrixSSL3_SessID *	sessionId;
	unsigned int			cipherSuite;
	SV *				certValidator;
	Crypt_MatrixSSL3_HelloExt *	extensions;
	SV *				extensionCback;
    INIT:
	ssl_t *				ssl;
	SV *				key;
	int				rc;
    CODE:
	add_obj();
	rc = matrixSslNewClientSession(&ssl, 
			(sslKeys_t *)keys, (sslSessionId_t *)sessionId, cipherSuite,
			(SvOK(certValidator) ? appCertValidator : NULL),
			(tlsExtension_t *)extensions,
			(SvOK(extensionCback) ? appExtensionCback : NULL));
	if(rc != MATRIXSSL_REQUEST_SEND){
	    del_obj();
	    croak("%d", rc);
	}
	RETVAL = (Crypt_MatrixSSL3_Sess *)ssl;
	// keep real callback in global hash: $certValidatorArg{ssl}=certValidator
	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	if(certValidatorArg==NULL)
		certValidatorArg = newHV();
	if(SvOK(certValidator))
		hv_store_ent(certValidatorArg, key, SvREFCNT_inc(SvRV(certValidator)), 0);
	// keep real callback in global hash: $extensionCbackArg{ssl}=extensionCback
	if(extensionCbackArg==NULL)
		extensionCbackArg = newHV();
	if(SvOK(extensionCback))
		hv_store_ent(extensionCbackArg, key, SvREFCNT_inc(SvRV(extensionCback)), 0);
    OUTPUT:
	RETVAL


Crypt_MatrixSSL3_Sess *
sess_new_server(keys, certValidator)
	Crypt_MatrixSSL3_Keys *		keys;
	SV *				certValidator;
    INIT:
	ssl_t *				ssl;
	SV *				key;
	int				rc;
    CODE:
	add_obj();
	rc = matrixSslNewServerSession(&ssl, (sslKeys_t *)keys,
			(SvOK(certValidator) ? appCertValidator : NULL));
	if(rc != PS_SUCCESS){
	    del_obj();
	    croak("%d", rc);
	}
	RETVAL = (Crypt_MatrixSSL3_Sess *)ssl;
	// keep real callback in global hash: $certValidatorArg{ssl}=certValidator
	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	if(certValidatorArg==NULL)
		certValidatorArg = newHV();
	if(SvOK(certValidator))
		hv_store_ent(certValidatorArg, key, SvREFCNT_inc(SvRV(certValidator)), 0);
    OUTPUT:
	RETVAL


void
sess_DESTROY(ssl)
	Crypt_MatrixSSL3_Sess *		ssl;
    INIT:
	SV *		key;
    CODE:
	matrixSslDeleteSession((ssl_t *)ssl);
	del_obj();
	// delete callback from global hashes
	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	if(hv_exists_ent(certValidatorArg, key, 0))
		hv_delete_ent(certValidatorArg, key, G_DISCARD, 0);
	if(hv_exists_ent(extensionCbackArg, key, 0))
		hv_delete_ent(extensionCbackArg, key, G_DISCARD, 0);
    OUTPUT:


int
sess_get_outdata(ssl, outBuf)
	Crypt_MatrixSSL3_Sess *		ssl;
	SV *				outBuf;
    INIT:
	unsigned char *			buf;
    CODE:
	RETVAL = matrixSslGetOutdata((ssl_t *)ssl, &buf);
	/* append answer to the output */
	if(RETVAL > 0)
		sv_catpvn_mg(outBuf, buf, RETVAL);
    OUTPUT:
	RETVAL


int
sess_sent_data(ssl, bytes)
	Crypt_MatrixSSL3_Sess *		ssl;
	int				bytes;
    CODE:
	RETVAL = matrixSslSentData((ssl_t *)ssl, bytes);
    OUTPUT:
	RETVAL


int
sess_get_readbuf(ssl, inBuf);
	Crypt_MatrixSSL3_Sess *		ssl;
	SV *				inBuf;
    INIT:
	STRLEN				bufsz = 0;
	unsigned char *			buf;
	unsigned char *			readbuf;
    CODE:
	RETVAL = matrixSslGetReadbuf((ssl_t *)ssl, &readbuf);
	if(RETVAL > 0){
		buf = SvPV(inBuf, bufsz);
		if(RETVAL > bufsz)
			RETVAL = bufsz;
		memcpy(readbuf, buf, RETVAL);
		/* remove from the input whatever got processed */
		sv_setpvn_mg(inBuf, buf+RETVAL,  bufsz-RETVAL);
	}
    OUTPUT:
	RETVAL


int
sess_received_data(ssl, bytes, ptBuf)
	Crypt_MatrixSSL3_Sess *		ssl;
	unsigned int			bytes;
	SV *				ptBuf;
    INIT:
	unsigned char *			buf;
	unsigned int			bufsz;
    CODE:
	RETVAL = matrixSslReceivedData((ssl_t *)ssl, bytes, &buf, &bufsz);
	sv_setpvn_mg(ptBuf, buf, (buf==NULL ? 0 : bufsz));
    OUTPUT:
	RETVAL


int
sess_processed_data(ssl, ptBuf)
	Crypt_MatrixSSL3_Sess *		ssl;
	SV *				ptBuf;
    INIT:
	unsigned char *			buf;
	unsigned int			bufsz;
    CODE:
	RETVAL = matrixSslProcessedData((ssl_t *)ssl, &buf, &bufsz);
	sv_setpvn_mg(ptBuf, buf, (buf==NULL ? 0 : bufsz));
    OUTPUT:
	RETVAL


int
sess_encode_to_outdata(ssl, outBuf)
	Crypt_MatrixSSL3_Sess *		ssl;
	SV *				outBuf;
    INIT:
	unsigned char *			buf;
	STRLEN				bufsz = 0;
    CODE:
	buf = SvPV(outBuf, bufsz);
	RETVAL = matrixSslEncodeToOutdata((ssl_t *)ssl, buf, bufsz);
    OUTPUT:
	RETVAL


void
sess_get_anon_status(ssl, anon)
	Crypt_MatrixSSL3_Sess *		ssl;
	int				anon;
    CODE:
	matrixSslGetAnonStatus((ssl_t *)ssl, &anon);
    OUTPUT:
	anon


int
sess_set_cipher_suite_enabled_status(ssl, cipherId, status);
	Crypt_MatrixSSL3_Sess *		ssl;
	short				cipherId;
	int				status;
    CODE:
	RETVAL = matrixSslSetCipherSuiteEnabledStatus((ssl_t *)ssl, cipherId, status);
    OUTPUT:
	RETVAL


int
sess_encode_closure_alert(ssl)
	Crypt_MatrixSSL3_Sess *		ssl;
    CODE:
	RETVAL = matrixSslEncodeClosureAlert((ssl_t *)ssl);
    OUTPUT:
	RETVAL


int
sess_encode_rehandshake(ssl, keys, certValidator, sessionOption, cipherSpec)
	Crypt_MatrixSSL3_Sess *		ssl;
	Crypt_MatrixSSL3_Keys *		keys;
	SV *				certValidator;
	int				sessionOption;
	int				cipherSpec;
    INIT:
	SV *				key;
    CODE:
	RETVAL = matrixSslEncodeRehandshake((ssl_t *)ssl, (sslKeys_t *)keys,
			(SvOK(certValidator) ? appCertValidator : NULL),
			sessionOption, cipherSpec);
	// keep real callback in global hash: $certValidatorArg{ssl}=certValidator
	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	if(certValidatorArg==NULL)
		certValidatorArg = newHV();
	if(hv_exists_ent(certValidatorArg, key, 0))
		hv_delete_ent(certValidatorArg, key, G_DISCARD, 0); // delete old callback
	if(SvOK(certValidator))
		hv_store_ent(certValidatorArg, key, SvREFCNT_inc(SvRV(certValidator)), 0);
    OUTPUT:
	RETVAL


MODULE = Crypt::MatrixSSL3	PACKAGE = Crypt::MatrixSSL3::HelloExtPtr	PREFIX = helloext_


Crypt_MatrixSSL3_HelloExt *
helloext_new()
    INIT:
	tlsExtension_t *		extension;
	int				rc;
    CODE:
	add_obj();
	rc = matrixSslNewHelloExtension(&extension);
	if(rc != PS_SUCCESS){
	    del_obj();
	    croak("%d", rc);
	}
	RETVAL = (Crypt_MatrixSSL3_HelloExt *)extension;
    OUTPUT:
	RETVAL


void
helloext_DESTROY(extension)
	Crypt_MatrixSSL3_HelloExt *	extension;
    CODE:
	matrixSslDeleteHelloExtension((tlsExtension_t *)extension);
	del_obj();
    OUTPUT:


int
helloext_load(extension, ext, extType)
	Crypt_MatrixSSL3_HelloExt *	extension;
	SV *				ext;
	int				extType;
    INIT:
	unsigned char *			extData;
	STRLEN				extLen = 0;
    CODE:
	extData = SvPV(ext, extLen);
	RETVAL = matrixSslLoadHelloExtension((tlsExtension_t *)extension, extData, extLen, extType);
    OUTPUT:
	RETVAL


