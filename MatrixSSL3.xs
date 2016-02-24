#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "matrixssl-3-7-2b-open/core/coreApi.h"
#include "matrixssl-3-7-2b-open/crypto/cryptoApi.h"
#include "matrixssl-3-7-2b-open/matrixssl/matrixssllib.h"
#include "matrixssl-3-7-2b-open/matrixssl/matrixsslApi.h"
#include "matrixssl-3-7-2b-open/matrixssl/version.h"
#include "MatrixSSL3.h"
#include "regex.h"

#include "const-c.inc"

/******************************************************************************/

typedef sslKeys_t Crypt_MatrixSSL3_Keys;
typedef sslSessionId_t	Crypt_MatrixSSL3_SessID;
typedef ssl_t		Crypt_MatrixSSL3_Sess;
typedef tlsExtension_t	Crypt_MatrixSSL3_HelloExt;

static int objects = 0;

/*****************************************************************************
	SNI entries  a.k.a virtual hosts per server.
	
	We can handle a maximum MAX_SNI_ENTRIES virtual hosts.
	
	For each host we can have:
	    certificate
	    key
	    session tickets keys
	    DH param
	    OCSP staple
	    Certificate Transparency files
*/

#define MAX_SNI_ENTRIES		16

typedef struct s_SNI_entry {
	regex_t regex_hostname;
	sslKeys_t *keys;
	unsigned char *OCSP_staple;
	int32 OCSP_staple_size;
	unsigned char *SCT;
	int32 SCT_size;
} t_SNI_entry;

/*****************************************************************************
	SNI servers
	
	We can handle a maximum MAX_SNI_SERVERS server - each with its own 
	virtual hosts.
	
	For each server we can have:
	    a maximum of MAX_SNI_ENTRIES virtual hosts
*/

#define MAX_SNI_SERVERS		16

typedef struct s_SNI_server {
	t_SNI_entry *SNI_entries[MAX_SNI_ENTRIES];
	int16 SNI_entries_number;
} t_SNI_server;

t_SNI_server *SNI_servers[MAX_SNI_SERVERS];
int16 SNI_server_index = 0;

/*****************************************************************************
	OCSP DER response buffers
	
	These are used when the client doesn't support/send a SNI extension
*/

#define MAX_OCSP_STAPLES 	16

typedef struct s_OCSP_staple {
	unsigned char *OCSP_staple;
	int32 OCSP_staple_size;
} t_OCSP_staple;

t_OCSP_staple *OCSP_staples[MAX_OCSP_STAPLES];
int16 OCSP_staple_index = 0;

/*****************************************************************************
	Certificate Transparency buffers
	
	These are used when the client doesn't support/send a SNI extension
*/

#define MAX_SCT_BUFFERS		16

typedef struct s_SCT_buffer {
	unsigned char *SCT;
	int32 SCT_size;
} t_SCT_buffer;

t_SCT_buffer *SCT_buffers[MAX_SCT_BUFFERS];
int16 SCT_buffer_index = 0;

void
add_obj()
{
    int	rc;

    if(objects == 0){
#ifdef MATRIX_DEBUG
	warn("Calling matrixSslOpen()");
#endif
	rc = matrixSslOpen();
	if(rc != PS_SUCCESS)
	    croak("%d", rc);
    }
#ifdef MATRIX_DEBUG
	warn("add_obj: objects number %d will be %d", objects, objects + 1);
#endif
    objects++;
}

void
del_obj()
{
#ifdef MATRIX_DEBUG
	warn("del_obj: objects number %d will be %d", objects, objects - 1);
#endif
    objects--;
    if(objects == 0){
#ifdef MATRIX_DEBUG
	warn("Calling matrixSslClose()");
#endif
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

int32
appCertValidator(ssl_t *ssl, psX509Cert_t *certInfo, int32 alert)
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

int32
appExtensionCback(ssl_t *ssl, unsigned short type, unsigned short len, void *data)
{
	dSP;
	SV *	key;
	SV *	callback;
	int	res;

	ENTER;
	SAVETMPS;

	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	callback = HeVAL(hv_fetch_ent(extensionCbackArg, key, 0, 0));

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSViv(type)));
	XPUSHs(sv_2mortal(newSVpvn((const char*) data, len)));
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


/*
 * Hash which will contain perl's ALPNCallback CODEREF
 * between matrixSslNew*Session() and matrixSslDeleteSession().
 * 
 * Hash format:
 *  key     integer representation of $ssl (ssl_t *)
 *  value   \&cb_ALPNCallback
 */
static HV *	ALPNCallbackArg = NULL;

void
ALPNCallback(void *ssl, short protoCount, char *proto[MAX_PROTO_EXT], int32 protoLen[MAX_PROTO_EXT], int32 *index)
{
	dSP;
	SV *	key;
	SV *	callback;
	AV *	protos;
	int32	res, i;

	ENTER;
	SAVETMPS;

	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	callback = HeVAL(hv_fetch_ent(ALPNCallbackArg, key, 0, 0));

	protos = (AV *)sv_2mortal((SV *)newAV());
	
	for (i = 0; i < protoCount; i++) {
	    SV *p = newSVpv(proto[i], protoLen[i]);
	    av_push(protos, p);
	}

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newRV((SV *)protos)));
	PUTBACK;

	res = call_sv(callback, G_EVAL|G_SCALAR);
	
	SPAGAIN;
	
	if (res != 1)
		croak("Internal error: perl callback doesn't return 1 scalar!");
	
	if (SvTRUE(ERRSV)) {
		warn("%s", SvPV_nolen(ERRSV));
		warn("die() in ALPNCallback callback not allowed, continue...\n");
		POPs;
		res = -1;
	} else {
		res = POPi;
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	*index = res;
}

// Perl callback that will get called when a hostname is successfully matched.
static SV* VHIndexCallback = NULL;

/*
 * SNI callback that gets called from matrixSSL whenever a client send a SNI
 * extension.
 *
 * This function gets called only in a server socket context.
 *
 * Params:
 * (in) ssl         - pointer to the SSL session
 * (in) hostname    - the hostname specified by the client in the SNI extension
 * (in) hostnameLed - hostname length in bytes
 * (out) newKeys    - pointer that holds a pointer to a sslKeys_t structure. We will search through
 *                    all the SNI entries of the specified SNI server (see below) and if we find a hostname
 *                    that matches we will set this pointer to the address of the keys for the found SNI entry.
 *                    The keys strcuture holds certificate, private key, session ticket keys, DH param) for
 *                    a certain virtual host. This is initialized only once and is shared between all sessions
 *                    accepted by the server socket
 * (in) userPtr     - pointer to a t_SNI_server structure holding information about all defined  virtual
 *                    hosts for a given server socket that was set for a SSL session shortly after its creation
 */

void
SNI_callback(void *ssl, char *hostname, int32 hostnameLen, sslKeys_t **newKeys, void *userPtr, int32 ssl_id)
{
	int32 i = 0, res;
	ssl_t *pssl = (ssl_t *) ssl;
	unsigned char _hostname[255];
	int regex_res = 0;
	char regex_error[255];
	t_SNI_server *ss = (t_SNI_server *) userPtr;
	
	memset(_hostname, 0, hostnameLen + 1);
	memcpy(_hostname, hostname, hostnameLen);
#ifdef MATRIX_DEBUG
	warn("SNI_callback: looking for hostname %s, userPtr %p, ssl_id %d", _hostname, userPtr, ssl_id);
#endif
	*newKeys = NULL;
	
	for (i = 0; i < ss->SNI_entries_number; i++)
			if ((regex_res = regexec(&(ss->SNI_entries[i]->regex_hostname), (const char *) _hostname, 0, NULL, 0)) == 0) {
#ifdef MATRIX_DEBUG
				warn("SNI match for %s on %d, DER = %p, %d, SCT = %p, %d", _hostname, i, ss->SNI_entries[i]->OCSP_staple, ss->SNI_entries[i]->OCSP_staple_size, ss->SNI_entries[i]->SCT, ss->SNI_entries[i]->SCT_size);
#endif
				*newKeys = ss->SNI_entries[i]->keys;
				matrixSslSetOcspDER(pssl, ss->SNI_entries[i]->OCSP_staple, ss->SNI_entries[i]->OCSP_staple_size);
				matrixSslSetSCT(pssl, ss->SNI_entries[i]->SCT, ss->SNI_entries[i]->SCT_size);
				break;
			} else {
			    regerror(regex_res, &(ss->SNI_entries[i]->regex_hostname), regex_error, 255);
			    warn("Error matching %d SNI entry: %s", i, regex_error);
			}
	
	if ((i < ss->SNI_entries_number) && (VHIndexCallback != NULL)) {
		dSP;
	    
		ENTER;
		SAVETMPS;

		PUSHMARK(SP);
		XPUSHs(sv_2mortal(newSViv(ssl_id)));
		XPUSHs(sv_2mortal(newSViv(i)));
		PUTBACK;

		res = call_sv(VHIndexCallback, G_EVAL|G_SCALAR);
	
		SPAGAIN;
	
		if (SvTRUE(ERRSV)) {
			warn("%s", SvPV_nolen(ERRSV));
			warn("die() in ALPNCallback callback not allowed, continue...\n");
			POPs;
			res = -1;
		}

		PUTBACK;
		FREETMPS;
		LEAVE;
	}
}

/*
 * Utility function for building the 'signed_certificate_timestamp' TLS extension data.
 * This extension is sent by client who want to receive  Certificate Transparancy information
 *
 * Params:
 * (in) ar - Perl scalar - holds the file name which contains multiple SCT (Signed Certificate
 *           Timestamp) binary structures received from CT server logs. This file repesents a ready
 *           to use extension data
 *         - Perl array rference - holds as elements file names of individual SCT binary structures
 *           received from CT server logs. The function will concatenate all these files and build
 *           the extension data
 * (out) buffer - a pointer to a pointer that will be allocated and will hold the extension data
 * (out) buffer_size - a pointer to an int32 variable that will hold the extension data size
*/
int
build_SCT_buffer(SV *ar, unsigned char **buffer, int32 *buffer_size)
{
	struct stat fstat;
	AV *sct_array;
	SV **item_sv;
	unsigned char *item, *sct, *c;
	STRLEN item_len = 0;
	int sct_array_size = 0, i = 0, sct_total_size = 0, sct_size = 0, rc = PS_SUCCESS;

	if (SvOK(ar)) {
		if (!SvROK(ar)) {
			// a single file
			item = SvPV(ar, item_len);
			
			if (item == NULL)
				croak("build_SCT_buffer: expecting a scalar or array reference as first parameter");
			
			if ((rc = psGetFileBuf(NULL, item, buffer, buffer_size)) != PS_SUCCESS)
				croak("Error %d trying to read file %s", rc, item);
			
			return 1;
		} else {
			if (SvTYPE(SvRV(ar)) != SVt_PVAV)
				croak("build_SCT_buffer: expecting a scalar or array reference as first parameter");
		}
	} else {
		croak("build_SCT_buffer: expecting a scalar or array reference as first paramete");
	}
	
	// get the SCT files array
	sct_array = (AV *) SvRV(ar);
	
	// get number of SCT files
	sct_array_size = (uint16) av_len(sct_array) + 1;
	
#ifdef MATRIX_DEBUG
	warn("Preparing to read %d SCT files", sct_array_size);
#endif
	for (i = 0; i < sct_array_size; i++) {
		item_sv = (SV *) av_fetch(sct_array, i, 0);
		item = SvPV(*item_sv, item_len);
		
		if (stat(item, &fstat) != 0)
		    croak("Error reading SCT file %s", item);
#ifdef MATRIX_DEBUG
		warn("Reading SCT file %d - %s; size: %d", i, item, fstat.st_size);
#endif
		sct_total_size += (size_t) fstat.st_size;
	}
	
	sct_total_size += sct_array_size * 2;
	*buffer_size = sct_total_size;
	
	c = *buffer = (unsigned char *) malloc(sct_total_size);
	
	for (i = 0; i < sct_array_size; i++) {
		item_sv = (SV *) av_fetch(sct_array, i, 0);
		item = SvPV(*item_sv, item_len);
		
		if ((rc = psGetFileBuf(NULL, item, &sct, &sct_size)) != PS_SUCCESS)
		    croak("Error %d trying to read file %s", rc, item);
		
		*c = (sct_size & 0xFF00) >> 8; c++;
		*c = (sct_size & 0xFF); c++;
		memcpy(c, sct, sct_size);
		c+= sct_size;
		
		psFree(sct, NULL);
	}
	
	return sct_array_size;
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

void open();
	CODE:
	add_obj();

void close();
	int i = 0, j = 0;
	t_SNI_server *ss = NULL;
	CODE:
	del_obj();
	
	// release OCSP staples
#ifdef MATRIX_DEBUG
	warn("----\nReleasing %d OCSP staples", OCSP_staple_index);
#endif
	for (i = 0; i < OCSP_staple_index; i++) {
		if (OCSP_staples[i]->OCSP_staple != NULL) {
#ifdef MATRIX_DEBUG
			warn("Releasing OCSP staple buffer %d, size = %d", i, OCSP_staples[i]->OCSP_staple_size);
#endif
			psFree(OCSP_staples[i]->OCSP_staple, NULL);
		}
#ifdef MATRIX_DEBUG
		warn("Releasing OCSP staple %d", i);
#endif
		free(OCSP_staples[i]);
	}

	// release SCT buffers
#ifdef MATRIX_DEBUG
	warn("----\nReleasing %d SCT buffers", SCT_buffer_index);
#endif
	for (i = 0; i < SCT_buffer_index; i++) {
		if (SCT_buffers[i]->SCT != NULL) {
#ifdef MATRIX_DEBUG
			warn("Releasing SCT extension buffer %d, size = %d", i, SCT_buffers[i]->SCT_size);
#endif
			psFree(SCT_buffers[i]->SCT, NULL);
		}
#ifdef MATRIX_DEBUG
		warn("Releasing SCT buffer %d", i);
#endif
		free(SCT_buffers[i]);
	}

	
	// release SNI servers
#ifdef MATRIX_DEBUG
	warn("----\nReleasing %d SNI servers", SNI_server_index);
#endif
	
	for (j = 0; j < SNI_server_index; j++) {
		ss = SNI_servers[j];
#ifdef MATRIX_DEBUG
		warn("  Releasing %d SNI entries for SNI server %d", ss->SNI_entries_number, j);
#endif
		for (i = 0; i < ss->SNI_entries_number; i++) {
#ifdef MATRIX_DEBUG
			warn("  Releasing regex for SNI entry %d", i);
#endif
			regfree(&(ss->SNI_entries[i]->regex_hostname));
#ifdef MATRIX_DEBUG
			warn("  Releasing keys for SNI entry %d", i);
#endif
			matrixSslDeleteKeys(ss->SNI_entries[i]->keys);
			del_obj();
			
			if (ss->SNI_entries[i]->OCSP_staple != NULL) {
#ifdef MATRIX_DEBUG
				warn("  Releasing OCSP staple buffer for SNI entry %d, size = %d", i, ss->SNI_entries[i]->OCSP_staple_size);
#endif
				psFree(ss->SNI_entries[i]->OCSP_staple, NULL);
			}
			
			if (ss->SNI_entries[i]->SCT != NULL) {
#ifdef MATRIX_DEBUG
				warn("  Releasing SCT extension buffer for SNI entry %d, size = %d", i, ss->SNI_entries[i]->SCT_size);
#endif
				psFree(ss->SNI_entries[i]->SCT, NULL);
			}
#ifdef MATRIX_DEBUG
			warn("  Releasing SNI entry %d", i);
#endif
			free(ss->SNI_entries[i]);
		}
#ifdef MATRIX_DEBUG
		warn("Releasing SNI server %d", j);
#endif
		free(ss);
	}


int
refresh_OCSP_staple(server_index, index, DERfile)
	int server_index = SvOK(ST(0)) ? SvIV(ST(0)) : -1;
	int index = SvOK(ST(1)) ? SvIV(ST(1)): -1;
	unsigned char *DERfile = SvOK(ST(2)) ? SvPV_nolen(ST(2)) : NULL;
	unsigned char **p_buffer = NULL;
	int32 *p_size = NULL, rc = 0;
    CODE:
	if (index < 0)
	    croak("Invalid OCSP staple buffer index %d", index);

	if (server_index < 0) {
#ifdef MATRIX_DEBUG
		warn("Refresh default OCSP stape buffer on index %d", index);
#endif
		if (index >= OCSP_staple_index)
			croak("Out of range default OCSP stape buffer index specified: %d > %d", index, OCSP_staple_index - 1);
		
		p_buffer = &(OCSP_staples[index]->OCSP_staple);
		p_size = &(OCSP_staples[index]->OCSP_staple_size);
	} else {
#ifdef MATRIX_DEBUG
		warn("Refresh OCSP staple buffer for SNI server %d/SNI entry %d", server_index, index);
#endif
		if (server_index >= SNI_server_index)
			croak("Out of range SNI server index spcified: %d > %d", server_index, SNI_server_index - 1);
		
		if (index >= SNI_servers[server_index]->SNI_entries_number)
			croak("Out of range SNI entry index spcified for SNI server %d: %d > %d", server_index, index, SNI_servers[server_index]->SNI_entries_number - 1);
		
		p_buffer = &(SNI_servers[server_index]->SNI_entries[index]->OCSP_staple);
		p_buffer = &(SNI_servers[server_index]->SNI_entries[index]->OCSP_staple_size);
	}
	
	// free previous buffer if necessary
	if (*p_buffer) {
		free(*p_buffer);
		*p_buffer = NULL;
	}
	*p_size = 0;
	
	rc = psGetFileBuf(NULL, DERfile, p_buffer, p_size);
	
	if (rc != PS_SUCCESS)
		croak("Failed to load OCSP staple %s; %d", DERfile, rc);
#ifdef MATRIX_DEBUG
	warn("Refreshed OCSP staple: %p %d", *p_buffer, *p_size);
#endif
	RETVAL = rc;
    OUTPUT:
	RETVAL


int
refresh_SCT_buffer(server_index, index, SCT_params)
	int server_index = SvOK(ST(0)) ? SvIV(ST(0)) : -1;
	int index = SvOK(ST(1)) ? SvIV(ST(1)): -1;
	SV *SCT_params;
	unsigned char **p_buffer = NULL;
	int32 *p_size = NULL, rc = 0;
    CODE:
	if (index < 0)
	    croak("Invalid SCT buffer index %d", index);

	if (server_index < 0) {
#ifdef MATRIX_DEBUG
		warn("Refresh default SCT buffer on index %d", index);
#endif
		if (index >= SCT_buffer_index)
			croak("Out of range default SCT buffer index specified: %d > %d", index, SCT_buffer_index - 1);
		
		p_buffer = &(SCT_buffers[index]->SCT);
		p_size = &(SCT_buffers[index]->SCT_size);
	} else {
#ifdef MATRIX_DEBUG
		warn("Refresh SCT buffer for SNI server %d/SNI entry %d", server_index, index);
#endif
		if (server_index >= SNI_server_index)
			croak("Out of range SNI server index spcified: %d > %d", server_index, SNI_server_index - 1);
		
		if (index >= SNI_servers[server_index]->SNI_entries_number)
			croak("Out of range SNI entry index spcified for SNI server %d: %d > %d", server_index, index, SNI_servers[server_index]->SNI_entries_number - 1);
		
		p_buffer = &(SNI_servers[server_index]->SNI_entries[index]->SCT);
		p_buffer = &(SNI_servers[server_index]->SNI_entries[index]->SCT_size);
	}
	
	// free previous buffer if necessary
	if (*p_buffer) {
		free(*p_buffer);
		*p_buffer = NULL;
	}
	*p_size = 0;
	
	rc = build_SCT_buffer(SCT_params, p_buffer, p_size);
#ifdef MATRIX_DEBUG
	warn("Refreshed SCT buffer: Loaded %d SCT files, %p %d", rc, *p_buffer, *p_size);
#endif
	RETVAL = rc;
    OUTPUT:
	RETVAL


void
set_VHIndex_callback(vh_index_cb)
	SV *vh_index_cb;
    CODE:
	VHIndexCallback = SvREFCNT_inc(SvRV(vh_index_cb));


unsigned int
capabilities();
    CODE:
	RETVAL = 0;
#ifdef USE_SHARED_SESSION_CACHE
	RETVAL |= SHARED_SESSION_CACHE_ENABLED;
#endif
#ifdef USE_STATELESS_SESSION_TICKETS
	RETVAL |= STATELESS_TICKETS_ENABLED;
#endif
#ifdef REQUIRE_DH_PARAMS
	RETVAL |= DH_PARAMS_ENABLED;
#endif
#ifdef USE_ALPN
	RETVAL |= ALPN_ENABLED;
#endif
#ifdef ENABLE_CERTIFICATE_STATUS_REQUEST
	RETVAL |= OCSP_STAPLES_ENABLED;
#endif
#ifdef ENABLE_SIGNED_CERTIFICATE_TIMESTAMP
	RETVAL |= CERTIFICATE_TRANSPARENCY_ENABLED;
#endif
	RETVAL |= SNI_ENABLED;
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
	rc = matrixSslNewKeys(&keys, NULL);
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
	RETVAL = (int) matrixSslLoadRsaKeys((sslKeys_t *)keys, certFile, privFile, privPass, trustedCAcertFiles);
    OUTPUT:
	RETVAL


int
keys_load_rsa_mem(keys, cert, priv, trustedCA)
	Crypt_MatrixSSL3_Keys *		keys;
	SV *				cert;
	SV *				priv;
	SV *				trustedCA;
	unsigned char *			certBuf = NULL;
	unsigned char *			privBuf = NULL;
	unsigned char *			trustedCABuf = NULL;
	STRLEN				certLen		= 0;
	STRLEN				privLen		= 0;
	STRLEN				trustedCALen	= 0;
    INIT:
    CODE:
	/* All bufs can contain \0, so SvPV must be used instead of strlen() */
	certBuf     = SvOK(cert)	? (unsigned char *) SvPV(cert, certLen)		: NULL;
	privBuf     = SvOK(priv)	? (unsigned char *) SvPV(priv, privLen)		: NULL;
	trustedCABuf= SvOK(trustedCA)	? (unsigned char *) SvPV(trustedCA, trustedCALen) : NULL;
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
	unsigned char *			importPassBuf = NULL;
	unsigned char *			macPassBuf = NULL;
	STRLEN				importPassLen	= 0;
	STRLEN				macPassLen	= 0;
    INIT:
    CODE:
	importPassBuf= SvOK(importPass) ? (unsigned char *) SvPV(importPass, importPassLen)	: NULL;
	macPassBuf   = SvOK(macPass)	? (unsigned char *) SvPV(macPass, macPassLen)		: NULL;
	
	RETVAL = matrixSslLoadPkcs12((sslKeys_t *)keys, (unsigned char *) p12File, importPassBuf, importPassLen,
			macPassBuf, macPassLen, flags);
    OUTPUT:
	RETVAL


int
keys_load_session_ticket_keys(keys, name, symkey, hashkey)
  Crypt_MatrixSSL3_Keys *keys;
  SV *name; 
  SV *symkey;
  SV *hashkey;
  char *nameBuf = NULL, *symkeyBuf = NULL, *hashkeyBuf = NULL;
  STRLEN symkeyLen = 0, hashkeyLen = 0;

  CODE:
    nameBuf = SvOK(name) ? SvPV_nolen(name) : NULL;
    symkeyBuf = SvOK(symkey) ? SvPV(symkey, symkeyLen) : NULL;
    hashkeyBuf = SvOK(hashkey) ? SvPV(hashkey, hashkeyLen) : NULL;
    RETVAL = (int) matrixSslLoadSessionTicketKeys(keys, nameBuf, symkeyBuf, symkeyLen, hashkeyBuf, hashkeyLen);
  OUTPUT:
    RETVAL

int
keys_load_DH_params(keys, paramsFile)
	Crypt_MatrixSSL3_Keys *		keys;
	char *				paramsFile = SvOK(ST(1)) ? SvPV_nolen(ST(1)) : NULL;
    CODE:
	RETVAL = (int) matrixSslLoadDhParams((sslKeys_t *)keys, paramsFile);
    OUTPUT:
	RETVAL

MODULE = Crypt::MatrixSSL3	PACKAGE = Crypt::MatrixSSL3::SessIDPtr	PREFIX = sessid_

Crypt_MatrixSSL3_SessID *
sessid_new()
    INIT:
	int rc = PS_SUCCESS;
	sslSessionId_t *		sessionId = NULL;
    CODE:
	add_obj();
	rc = matrixSslNewSessionId(&sessionId, NULL);
	if(rc != PS_SUCCESS){
	    del_obj();
	    croak("%d", rc);
	}

	RETVAL = (Crypt_MatrixSSL3_SessID *)sessionId;
    OUTPUT:
	RETVAL


void
sessid_DESTROY(sessionId)
	Crypt_MatrixSSL3_SessID *	sessionId;
    CODE:
	matrixSslDeleteSessionId((sslSessionId_t *) sessionId);
	del_obj();
    OUTPUT:


void
sessid_clear(sessionId)
	Crypt_MatrixSSL3_SessID *	sessionId;
    CODE:
	matrixSslClearSessionId((sslSessionId_t *) sessionId);
    OUTPUT:


MODULE = Crypt::MatrixSSL3	PACKAGE = Crypt::MatrixSSL3::SessPtr	PREFIX = sess_


Crypt_MatrixSSL3_Sess *
sess_new_client(keys, sessionId, cipherSuites, certValidator, expectedName, extensions, extensionCback)
	Crypt_MatrixSSL3_Keys *		keys;
	Crypt_MatrixSSL3_SessID *	sessionId;
	SV *				cipherSuites;
	SV *				certValidator;
	SV *				expectedName;
	Crypt_MatrixSSL3_HelloExt *	extensions;
	SV *				extensionCback;
	ssl_t *				ssl = NULL;
	SV *				key = NULL;
	int					rc = 0;
	uint32 *			cipherSuitesBuf = NULL;
	uint16				cipherCount = 0, i = 0;
	AV *				cipherSuitesArray = NULL;
	SV **				item = NULL;
	sslSessOpts_t *		sslOpts = NULL;
    
    INIT:
	if (SvROK(cipherSuites) && SvTYPE(SvRV(cipherSuites)) == SVt_PVAV) {
		cipherSuitesArray = (AV *) SvRV(cipherSuites);

		cipherCount = (uint16) av_len(cipherSuitesArray) + 1;
		cipherSuitesBuf = (uint32 *) malloc(cipherCount * sizeof(uint32));
		
		for (i = 0; i < cipherCount; i++) {
			item = av_fetch(cipherSuitesArray, i, 0);
			cipherSuitesBuf[i] = (uint32) SvIV(*item);
		}
	}
	else if (SvOK(cipherSuites)) {
		croak("cipherSuites should be undef or ARRAYREF");
	}
	
    CODE:
	add_obj();
	
	sslOpts = (sslSessOpts_t *) malloc(sizeof(sslSessOpts_t));
	memset((void *) sslOpts, 0, sizeof(sslSessOpts_t));
	
	rc = matrixSslNewClientSession(&ssl,
			(sslKeys_t *)keys, (sslSessionId_t *)sessionId, cipherSuitesBuf, cipherCount,
			(SvOK(certValidator) ? appCertValidator : NULL),
			(SvOK(expectedName) ? (const char *) SvPV_nolen(expectedName) : NULL),
			(tlsExtension_t *) extensions,
			(SvOK(extensionCback) ? appExtensionCback : NULL),
			sslOpts);
	
	free(sslOpts);
	if (cipherSuitesBuf != NULL) free(cipherSuitesBuf);
	
	if(rc != MATRIXSSL_REQUEST_SEND){
	    del_obj();
	    croak("%d", rc);
	}
	RETVAL = (Crypt_MatrixSSL3_Sess *)ssl;
	
	ENTER;
	SAVETMPS;

	key = sv_2mortal(newSViv(PTR2IV(ssl)));

  	// keep real callback in global hash: $certValidatorArg{ssl}=certValidator
  	if(SvOK(certValidator)) {
  		if(certValidatorArg==NULL)
  			certValidatorArg = newHV();
  		hv_store_ent(certValidatorArg, key, SvREFCNT_inc(SvRV(certValidator)), 0);
  	}
  	// keep real callback in global hash: $extensionCbackArg{ssl}=extensionCback
  	if(SvOK(extensionCback)) {
  		if(extensionCbackArg==NULL)
  			extensionCbackArg = newHV();
  		hv_store_ent(extensionCbackArg, key, SvREFCNT_inc(SvRV(extensionCback)), 0);
  	}

	FREETMPS;
	LEAVE;

    OUTPUT:
	RETVAL


Crypt_MatrixSSL3_Sess *
sess_new_server(keys, certValidator)
	Crypt_MatrixSSL3_Keys *		keys;
	SV *				certValidator;
	ssl_t *				ssl = NULL;
	SV *				key = NULL;
	int				rc = 0;
	sslSessOpts_t *		sslOpts = NULL;
    INIT:
    CODE:
	add_obj();

	sslOpts = (sslSessOpts_t *) malloc(sizeof(sslSessOpts_t));
	memset((void *) sslOpts, 0, sizeof(sslSessOpts_t));

	rc = matrixSslNewServerSession(&ssl, (sslKeys_t *)keys,
			(SvOK(certValidator) ? appCertValidator : NULL),
			sslOpts);

	free(sslOpts);
			
	if(rc != PS_SUCCESS){
	    del_obj();
	    croak("%d", rc);
	}
	RETVAL = (Crypt_MatrixSSL3_Sess *)ssl;
	
	ENTER;
	SAVETMPS;

	key = sv_2mortal(newSViv(PTR2IV(ssl)));

	// keep real callback in global hash: $certValidatorArg{ssl}=certValidator
	if(SvOK(certValidator)) {
		if(certValidatorArg==NULL)
			certValidatorArg = newHV();
		hv_store_ent(certValidatorArg, key, SvREFCNT_inc(SvRV(certValidator)), 0);
	}

	FREETMPS;
	LEAVE;

    OUTPUT:
	RETVAL


int
sess_init_SNI(ssl, index, ssl_id, sni_data = NULL)
	Crypt_MatrixSSL3_Sess *ssl;
	int index = SvOK(ST(1)) ? SvIV(ST(1)) : -1;
	int ssl_id = SvOK(ST(2)) ? SvIV(ST(2)) : -1;
	SV *sni_data;
	AV *sni_array = NULL;
	SV **sd_sv = NULL;
	AV *sd = NULL;
	SV **item_sv = NULL;
	unsigned char *item = NULL;
	SV **cert_sv = NULL;
	unsigned char *cert = NULL;
	SV **key_sv = NULL;
	unsigned char *key = NULL;
	STRLEN item_len = 0;
	int32 rc = PS_SUCCESS, i = 0, res = 0;

    CODE:
	unsigned char stk_id[16];
	unsigned char stk_ek[32];
	STRLEN stk_ek_len = 0;
	unsigned char stk_hk[32];
	STRLEN stk_hk_len = 0;
	t_SNI_server *ss = NULL;
	int regex_res = 0;
	char regex_error[255];
#ifdef MATRIX_DEBUG
	warn("initSNI: index %d", index);
#endif
	// check if we have to initialize the SNI server structure or should we just set the callback to an already initialized SNI server structure
	if (index == -1) {
		// new site, check limits
		if (SNI_server_index == MAX_SNI_SERVERS)
			croak("We have already initiazlied the maximum number of %d SNI sites", MAX_SNI_SERVERS);
#ifdef MATRIX_DEBUG
		warn("initSNI: allocating buffer for new SNI server at index %d", SNI_server_index);
#endif
		// create new SNI site buffer
		SNI_servers[SNI_server_index] = (t_SNI_server *) malloc(sizeof(t_SNI_server));
		memset(SNI_servers[SNI_server_index], 0, sizeof(t_SNI_server));
		
		index = SNI_server_index;
		SNI_server_index++;
	} else {
		// already initialized SNI site
		// check if index points to a valid SNI site structure
		if (index >= SNI_server_index)
			croak("Requested SNI site index out of range %d > %d", index, MAX_SNI_SERVERS);
		
		// just set the callback and we're done
#ifdef MATRIX_DEBUG
		warn("Setting up SNI callback using SNI server %d, %p", index, SNI_servers[index]);
#endif
		matrixSslRegisterSNICallback(ssl, SNI_callback, SNI_servers[index], ssl_id);
		
		XSRETURN_IV(index);
	}
	
	// set up pointer to the newly SNI site
	ss = SNI_servers[index];
	
	// initialize SNI server structure
	if (!(SvOK(sni_data) && SvRV(sni_data) && SvTYPE(SvRV(sni_data)) == SVt_PVAV))
		croak("Expected SNI data to be an array reference");
	
	// our array of arrays
	sni_array = (AV *) SvRV(sni_data);

	// get count
	ss->SNI_entries_number = (uint16) av_len(sni_array) + 1;
#ifdef MATRIX_DEBUG
	warn("  Got %d SNI entries", ss->SNI_entries_number);
#endif
	// check limits
	if (ss->SNI_entries_number > MAX_SNI_ENTRIES)
		croak("Not enough room to load all SNI entries %d > %d", ss->SNI_entries_number, MAX_SNI_ENTRIES);

	for (i = 0; i < ss->SNI_entries_number; i++) {
		// alocate memory for each SNI structure
		ss->SNI_entries[i] = (t_SNI_entry *) malloc( sizeof(t_SNI_entry));
		memset(ss->SNI_entries[i], 0, sizeof(t_SNI_entry));
		
		// get one array at the time
		sd_sv = (SV *) av_fetch(sni_array, i, 0);

		// make sure we have an array reference
		if (!(SvOK(*sd_sv) && SvRV(*sd_sv) && SvTYPE(SvRV(*sd_sv)) == SVt_PVAV))
			croak("Expected elements of SNI data to be arrays");
		
		// get per host SNI data
		sd = (AV *) SvRV(*sd_sv);

		// element 0 - hostname - we need to copy this in our structure
		item_sv = (SV *) av_fetch(sd, 0, 0);
		if (!SvOK(*item_sv))
			croak("Hostname not specified in SNI entry %d", i);
		
		item = (unsigned char *) SvPV(*item_sv , item_len);
#ifdef MATRIX_DEBUG
		warn("  SNI entry %d Hostname = %s\n", i, item);
#endif
		//memcpy(ss->SNI_entries[i]->hostname, item, (item_len > 255 ? 255 : item_len));
		//ss->SNI_entries[i]->hostnameLen = item_len;
		regex_res = regcomp(&(ss->SNI_entries[i]->regex_hostname), item, REG_EXTENDED | REG_ICASE | REG_NOSUB);
		
		if (regex_res != 0) {
		    regerror(regex_res, &(ss->SNI_entries[i]->regex_hostname), regex_error, 255);
		    croak("Error compiling hostname regex %s: %s", item, regex_error);
		}
		
		// element 1,2 - key & cert for this host
		cert_sv = (SV *) av_fetch(sd, 1, 0);
		key_sv = (SV *) av_fetch(sd, 2, 0);
		
		if (SvOK(*cert_sv) && SvOK(*key_sv)) {
			cert = (unsigned char *) SvPV_nolen(*cert_sv);
			key = (unsigned char *) SvPV_nolen(*key_sv);
#ifdef MATRIX_DEBUG
			warn("  SNI entry %d cert %s; key %s", i, cert, key);
#endif
			add_obj();
			rc = matrixSslNewKeys(&(ss->SNI_entries[i]->keys), NULL);
			if (rc != PS_SUCCESS) {
				del_obj();
				croak("SNI matrixSslNewKeys failed %d", rc);
			}
			
			rc = matrixSslLoadRsaKeys(ss->SNI_entries[i]->keys, cert, key, NULL, NULL);
			if (rc != PS_SUCCESS)
				croak("SNI matrixSslLoadRsaKeys failed %d; %s; %s", rc, cert, key);
		}
		
		// element 3 - DH param
		item_sv = (SV *) av_fetch(sd, 3, 0);
		
		if (SvOK(*item_sv)) {
			item = (unsigned char *) SvPV_nolen(*item_sv);
#ifdef MATRIX_DEBUG
			warn("  SNI entry %d DH param %s", i, item);
#endif
			rc = matrixSslLoadDhParams(ss->SNI_entries[i]->keys, item);
			if (rc != PS_SUCCESS)
				croak("SNI matrixSslLoadDhParams failed %d; %s", rc, item);
		}
		
		// element 4,5,6 - session tickets id, encryption key, hash key
		item_sv = (SV *) av_fetch(sd, 4, 0);
		
		// if the id is undef that means no session ticket support
		if (SvOK(*item_sv)) {
			item = (unsigned char *) SvPV(*item_sv, item_len);
#ifdef MATRIX_DEBUG
			warn("  SNI entry %d session ticket ID %.16s", i, item);
#endif
			memcpy(stk_id, item, item_len);
			
			// element 5 - encryption key
			item_sv = (SV *) av_fetch(sd, 5, 0);
			if (!SvOK(*item_sv))
				croak("undef encryption key in SNI structure %d", i);
			
			item = (unsigned char *) SvPV(*item_sv, item_len);
			if (!((item_len == 16) || (item_len == 32)))
				croak("size of the encryption key in SNI structure %d must be 16/32. Now it is %d", i, item_len);
#ifdef MATRIX_DEBUG
			warn("  SNI entry %d session ticket encryption key %.32s", i, item);
#endif
			memcpy(stk_ek, item, item_len);
			stk_ek_len = item_len;
			
			// element 6 - hash key
			item_sv = (SV *) av_fetch(sd, 6, 0);
			if (!SvOK(*item_sv))
				croak("undef hash key in SNI structure %d", i);
			
			item = (unsigned char *) SvPV(*item_sv, item_len);
			if (item_len != 32)
				croak("size of the hash key in SNI structure %d must be 16/32. Now it is %d", i, item_len);
#ifdef MATRIX_DEBUG
			warn("  SNI entry %d session ticket hash key %.32s", i, item);
#endif
			memcpy(stk_hk, item, item_len);
			stk_hk_len = item_len;
			
			rc = matrixSslLoadSessionTicketKeys(ss->SNI_entries[i]->keys, stk_id, stk_ek, stk_ek_len, stk_hk, stk_hk_len);
			if (rc != PS_SUCCESS)
				croak("SNI matrixSslLoadSessionTicketKeys failed %d; %s; %s", rc, cert, key);
		}
		
		// element 7 - OCSP DER file
		item_sv = (SV *) av_fetch(sd, 7, 0);
		
		if (SvOK(*item_sv)) {
			item = (unsigned char *) SvPV_nolen(*item_sv);
#ifdef MATRIX_DEBUG
			warn("  SNI entry %d OCSP staple file %s", i, item);
#endif
			rc = psGetFileBuf(NULL, item, &(ss->SNI_entries[i]->OCSP_staple), &(ss->SNI_entries[i]->OCSP_staple_size));
			if (rc != PS_SUCCESS)
				croak("SNI psGetFileBuf failed %d; %s", rc, item);
		};
		
		// element 8 - SCT files
		item_sv = (SV *) av_fetch(sd, 8, 0);
		
		if (SvOK(*item_sv)) {
			res = build_SCT_buffer(*item_sv, &(ss->SNI_entries[i]->SCT), &(ss->SNI_entries[i]->SCT_size));
#ifdef MATRIX_DEBUG
			warn("  Read %d SCT files for SNI entry %d; Total SCT buffer size = %d", res, i, ss->SNI_entries[i]->SCT_size);
#endif
		}
	}

	RETVAL = index;
#ifdef MATRIX_DEBUG
	warn("Setting up SNI callback using SNI server %d, %p", index, ss);
#endif
	matrixSslRegisterSNICallback(ssl, SNI_callback, ss, ssl_id);
    OUTPUT:
	RETVAL


int
sess_load_OCSP_staple(ssl, DERfile)
	Crypt_MatrixSSL3_Sess *		ssl;
	char *				DERfile = SvOK(ST(1)) ? SvPV_nolen(ST(1)) : NULL;
    CODE:
	RETVAL = (int) matrixSslLoadOcspDER(ssl, DERfile);
    OUTPUT:
	RETVAL


int
sess_set_OCSP_staple(ssl, index, DERfile = NULL)
	Crypt_MatrixSSL3_Sess *		ssl;
	int 				index = SvOK(ST(1)) ? SvIV(ST(1)) : -1;
	char *				DERfile;
	int rc = PS_SUCCESS;
    CODE:
#ifdef MATRIX_DEBUG
	warn("set_OCSP_staple: file %s, index %d", DERfile, index);
#endif
	// check if we have to load the DER file or if we should set the pointer/size to an already loaded buffer
	if (index == -1) {
		// check limits
		if (OCSP_staple_index == MAX_OCSP_STAPLES)
			croak("We have already loaded the maximum number of %d OCSP staples", MAX_OCSP_STAPLES);
		
		OCSP_staples[OCSP_staple_index] = (t_OCSP_staple *) malloc(sizeof(t_OCSP_staple));
		memset(OCSP_staples[OCSP_staple_index], 0, sizeof(t_OCSP_staple));
		
		rc = psGetFileBuf(NULL, DERfile, &(OCSP_staples[OCSP_staple_index]->OCSP_staple), &(OCSP_staples[OCSP_staple_index]->OCSP_staple_size));
		
		if (rc != PS_SUCCESS)
			croak("Failed to load DER response %s; %d", DERfile, rc);

		index = OCSP_staple_index;
		OCSP_staple_index++;
	}
	
	// check if index points to a valid OCSP response buffer
	if (index >= OCSP_staple_index)
		croak("Requested index out of range %d > %d", index, OCSP_staple_index);
	
	matrixSslSetOcspDER(ssl, OCSP_staples[index]->OCSP_staple, OCSP_staples[index]->OCSP_staple_size);
	RETVAL = index;
    OUTPUT:
	RETVAL

int
sess_set_SCT_buffer(ssl, index, SCT_params = NULL)
	Crypt_MatrixSSL3_Sess *		ssl;
	int 				index = SvOK(ST(1)) ? SvIV(ST(1)) : -1;
	SV*				SCT_params;
	int ars = 0, rc = PS_SUCCESS;
    CODE:
#ifdef MATRIX_DEBUG
	warn("set_SCT_buffer: index %d", index);
#endif
	// check if we have to prepare the buffer or should we just set the pointer/size to an already loaded buffer
	if (index == -1) {
		// check limits
		if (SCT_buffer_index == MAX_SCT_BUFFERS)
			croak("We have already loaded the maximum number of %d SCT buffers", MAX_SCT_BUFFERS);
		
		index = SCT_buffer_index;
		SCT_buffers[index] = (t_SCT_buffer *) malloc(sizeof(t_SCT_buffer));
		memset(SCT_buffers[index], 0, sizeof(t_SCT_buffer));
		
		ars = build_SCT_buffer(SCT_params, &(SCT_buffers[index]->SCT), &(SCT_buffers[index]->SCT_size));
#ifdef MATRIX_DEBUG
		warn("Read %d SCT files for SCT buffer %d; Total SCT buffer size = %d", ars, index, SCT_buffers[index]->SCT_size);
#endif
		
		SCT_buffer_index++;
	}
	
	// check if index points to a valid SCT buffer
	if (index >= SCT_buffer_index)
		croak("Requested SCT buffer index out of range %d > %d", index, SCT_buffer_index);
	
	matrixSslSetSCT(ssl, SCT_buffers[index]->SCT, SCT_buffers[index]->SCT_size);
	RETVAL = index;
    OUTPUT:
	RETVAL

void
sess_set_ALPN_callback(ssl, cb_ALPN)
	Crypt_MatrixSSL3_Sess *		ssl;
	SV *				cb_ALPN;
	SV *				key = NULL;
	int rc = 0;
	CODE:
	
	if (!SvOK(cb_ALPN)) {
	    croak("You must specify the ALPN callback");
	}
	
	matrixSslRegisterALPNCallback(ssl, ALPNCallback);
	
	ENTER;
	SAVETMPS;

	key = sv_2mortal(newSViv(PTR2IV(ssl)));

	// keep real callback in global hash: $certValidatorArg{ssl}=certValidator
	if(ALPNCallbackArg==NULL)
		ALPNCallbackArg = newHV();
	hv_store_ent(ALPNCallbackArg, key, SvREFCNT_inc(SvRV(cb_ALPN)), 0);

	FREETMPS;
	LEAVE;
    OUTPUT:

void
sess_DESTROY(ssl)
	Crypt_MatrixSSL3_Sess *		ssl;
	SV *		key = NULL;
    INIT:
    CODE:
	ENTER;
	SAVETMPS;

	// delete callback from global hashes
	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	if(hv_exists_ent(certValidatorArg, key, 0))
		hv_delete_ent(certValidatorArg, key, G_DISCARD, 0);
	if(hv_exists_ent(extensionCbackArg, key, 0))
		hv_delete_ent(extensionCbackArg, key, G_DISCARD, 0);
	if(hv_exists_ent(ALPNCallbackArg, key, 0))
		hv_delete_ent(ALPNCallbackArg, key, G_DISCARD, 0);

	FREETMPS;
	LEAVE;

	matrixSslDeleteSession((ssl_t *)ssl);
	del_obj();

    OUTPUT:


int
sess_get_outdata(ssl, outBuf)
	Crypt_MatrixSSL3_Sess *		ssl;
	SV *				outBuf;
	unsigned char *			buf = NULL;
    INIT:
    CODE:
	RETVAL = matrixSslGetOutdata((ssl_t *)ssl, &buf);
	/* append answer to the output */
	if(RETVAL > 0)
		sv_catpvn_mg(outBuf, (const char *) buf, RETVAL);
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
	STRLEN				bufsz = 0;
	unsigned char *			buf = NULL;
	unsigned char *			readbuf = NULL;
    INIT:
    CODE:
	RETVAL = matrixSslGetReadbuf((ssl_t *)ssl, &readbuf);
	if(RETVAL > 0){
		buf = (unsigned char *) SvPV(inBuf, bufsz);
		if((unsigned int) RETVAL > bufsz)
			RETVAL = bufsz;
		memcpy(readbuf, buf, RETVAL);
		/* remove from the input whatever got processed */
		sv_setpvn_mg(inBuf, (const char *) buf+RETVAL,  bufsz-RETVAL);
	}
    OUTPUT:
	RETVAL


int
sess_received_data(ssl, bytes, ptBuf)
	Crypt_MatrixSSL3_Sess *		ssl;
	unsigned int			bytes;
	SV *				ptBuf;
	unsigned char *			buf = NULL;
	unsigned int			bufsz = 0;
    INIT:
    CODE:
	RETVAL = matrixSslReceivedData((ssl_t *)ssl, bytes, &buf, (uint32 *) &bufsz);
	sv_setpvn_mg(ptBuf, (const char *) buf, (buf==NULL ? 0 : bufsz));
    OUTPUT:
	RETVAL


int
sess_processed_data(ssl, ptBuf)
	Crypt_MatrixSSL3_Sess *		ssl;
	SV *				ptBuf;
	unsigned char *			buf = NULL;
	unsigned int			bufsz = 0;
    INIT:
    CODE:
	RETVAL = matrixSslProcessedData((ssl_t *)ssl, &buf, (uint32 *) &bufsz);
	sv_setpvn_mg(ptBuf, (const char *) buf, (buf==NULL ? 0 : bufsz));
    OUTPUT:
	RETVAL


int
sess_encode_to_outdata(ssl, outBuf)
	Crypt_MatrixSSL3_Sess *		ssl;
	SV *				outBuf;
	unsigned char *			buf = NULL;
	STRLEN				bufsz = 0;
    INIT:
    CODE:
	buf = (unsigned char *) SvPV(outBuf, bufsz);
	RETVAL = matrixSslEncodeToOutdata((ssl_t *)ssl, buf, bufsz);
    OUTPUT:
	RETVAL


int
sess_get_anon_status(ssl)
	Crypt_MatrixSSL3_Sess *		ssl;
	int32				anon = 0;
    CODE:
	matrixSslGetAnonStatus((ssl_t *)ssl, &anon);
	RETVAL = (int) anon;
    OUTPUT:
	RETVAL


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
sess_encode_rehandshake(ssl, keys, certValidator, sessionOption, cipherSpecs)
	Crypt_MatrixSSL3_Sess *		ssl;
	Crypt_MatrixSSL3_Keys *		keys;
	SV *				certValidator;
	int				sessionOption;
	SV *				cipherSpecs;
	SV *				key = NULL;
	uint32 *			cipherSpecsBuf = NULL;
	uint16				cipherCount = 0, i = 0;
	AV *				cipherSpecsArray = NULL;
	SV **				item = NULL;
	
    INIT:
	if (SvROK(cipherSpecs) && SvTYPE(SvRV(cipherSpecs)) == SVt_PVAV) {
		cipherSpecsArray = (AV *) SvRV(cipherSpecs);

		cipherCount = (uint16) av_len(cipherSpecsArray) + 1;
		cipherSpecsBuf = (uint32 *) malloc(cipherCount * sizeof(uint32));
		
		for (i = 0; i < cipherCount; i++) {
			item = av_fetch(cipherSpecsArray, i, 0);
			cipherSpecsBuf[i] = (uint32) SvIV(*item);
		}
	}
	else if (SvOK(cipherSpecs)) {
		croak("cipherSpecs should be undef or ARRAYREF");
	}

    CODE:
	RETVAL = matrixSslEncodeRehandshake((ssl_t *)ssl, (sslKeys_t *)keys,
			(SvOK(certValidator) ? appCertValidator : NULL),
			sessionOption, cipherSpecsBuf, cipherCount);
	
	if (cipherSpecsBuf != NULL) free(cipherSpecsBuf);
	
	ENTER;
	SAVETMPS;

	// keep real callback in global hash: $certValidatorArg{ssl}=certValidator
	key = sv_2mortal(newSViv(PTR2IV(ssl)));
	if(certValidatorArg==NULL)
		certValidatorArg = newHV();
	if(hv_exists_ent(certValidatorArg, key, 0))
		hv_delete_ent(certValidatorArg, key, G_DISCARD, 0); // delete old callback
	if(SvOK(certValidator))
		hv_store_ent(certValidatorArg, key, SvREFCNT_inc(SvRV(certValidator)), 0);

	FREETMPS;
	LEAVE;
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
	rc = matrixSslNewHelloExtension(&extension, NULL);
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
	unsigned char *			extData = NULL;
	STRLEN				extLen = 0;
    CODE:
	extData = (unsigned char *) SvPV(ext, extLen);
	RETVAL = matrixSslLoadHelloExtension((tlsExtension_t *)extension, extData, extLen, extType);
    OUTPUT:
	RETVAL


