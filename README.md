[![Build Status](https://travis-ci.org/powerman/perl-Crypt-MatrixSSL3.svg?branch=master)](https://travis-ci.org/powerman/perl-Crypt-MatrixSSL3)
[![Coverage Status](https://coveralls.io/repos/powerman/perl-Crypt-MatrixSSL3/badge.svg?branch=master)](https://coveralls.io/r/powerman/perl-Crypt-MatrixSSL3?branch=master)

# NAME

Crypt::MatrixSSL3 - Perl extension for SSL and TLS using MatrixSSL.org v3.7.2b

# VERSION

This document describes Crypt::MatrixSSL3 version v3.7.7

# SYNOPSIS

    use Crypt::MatrixSSL3;

    # 1. See the MatrixSSL documentation.
    # 2. See example scripts included in this package:
    #       ssl_client.pl
    #       ssl_server.pl
    #       functions.pl

# DESCRIPTION

Crypt::MatrixSSL3 lets you use the MatrixSSL crypto library (see
http://matrixssl.org/) from Perl. With this module, you will be
able to easily write SSL and TLS client and server programs.

MatrixSSL includes everything you need, all in under 50KB.

You will need a "C" compiler to build this, unless you're getting
the ".ppm" prebuilt Win32 version. Crypt::MatrixSSL3 builds cleanly
on (at least) Windows, Linux, and Macintosh machines.

MatrixSSL is an Open Source (GNU General Public License) product, and is
also available commercially if you need freedom from GNU rules.

Everything you need is included here, but check the MatrixSSL.org
web site to make sure you've got the latest version of the
MatrixSSL "C" code if you like (it's in the directory "./inc"
of this package if you want to replace the included version from
the MatrixSSL.org download site).

# API BACKWARD COMPATIBILITY AND STATUS

MatrixSSL tends to make incompatible API changes in minor releases, so
**every next version of Crypt::MatrixSSL3 may have incompatible API changes**!

This version adds several new features which isn't well-tested yet and
thus considered unstable:

- Support for shared session cache using shared memory
- Stateless ticket session resuming support
- Loading the DH param for DH cipher suites
- Application Layer Protocol Negotiation callback support
- SNI (virtual hosts)
- OCSP staple
- Certificate Transparency
- Support for TLS\_FALLBACK\_SCSV
- Partial support for "status\_request" TLS extension
- Browser preferred ciphers

    Selecting our strongest ciphers from the client supported list.

# TERMINOLOGY

When a client establishes an SSL connection without sending a SNI
extension in its CLIENT\_HELLO message we say that the client connects to
the **default server**.

If a SNI extension is present then the client connects to a **virtual host**.

# EXPORTS

Constants and functions can be exported using different tags.
Use tag ':all' to export everything.

By default (tag ':DEFAULT') only SSL\_MAX\_PLAINTEXT\_LEN and return code
constants (tag ':RC') will be exported.

- :Version

        SSL2_MAJ_VER
        SSL3_MAJ_VER
        SSL3_MIN_VER
        TLS_1_1_MIN_VER
        TLS_1_2_MIN_VER
        TLS_MAJ_VER
        TLS_MIN_VER
        MATRIXSSL_VERSION
        MATRIXSSL_VERSION_MAJOR
        MATRIXSSL_VERSION_MINOR
        MATRIXSSL_VERSION_PATCH
        MATRIXSSL_VERSION_CODE

- :Cipher

    Used in matrixSslSetCipherSuiteEnabledStatus().

        #******************************************************************************
        #
        #   Recommended cipher suites:
        #
        #   Define the following to enable various cipher suites
        #   At least one of these must be defined.  If multiple are defined,
        #   the handshake will determine which is best for the connection.
        #

        TLS_RSA_WITH_AES_128_CBC_SHA
        TLS_RSA_WITH_AES_256_CBC_SHA
        TLS_RSA_WITH_AES_128_CBC_SHA256
        TLS_RSA_WITH_AES_256_CBC_SHA256
        TLS_RSA_WITH_AES_128_GCM_SHA256

        # Pre-Shared Key Ciphers
        TLS_RSA_WITH_AES_256_GCM_SHA384
        TLS_PSK_WITH_AES_256_CBC_SHA
        TLS_PSK_WITH_AES_128_CBC_SHA
        TLS_PSK_WITH_AES_256_CBC_SHA384
        TLS_PSK_WITH_AES_128_CBC_SHA256

        # Ephemeral ECC DH keys, ECC DSA certificates
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

        # Ephemeral ECC DH keys, RSA certificates
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

        # Non-Ephemeral ECC DH keys, ECC DSA certificates
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384

        # Non-Ephemeral ECC DH keys, RSA certificates
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256


        #******************************************************************************
        #
        #   These cipher suites are secure, but not in general use. Enable only if
        #   specifically required by application.
        #
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256


        #******************************************************************************
        #
        #   These cipher suites are generally considered weak, not recommended for use.
        #
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        SSL_RSA_WITH_3DES_EDE_CBC_SHA
        TLS_RSA_WITH_SEED_CBC_SHA
        SSL_RSA_WITH_RC4_128_SHA
        SSL_RSA_WITH_RC4_128_MD5


        #******************************************************************************
        #
        #   These cipher suites do not combine authentication and encryption and
        #   are not recommended for use-cases that require strong security or
        #   Man-in-the-Middle protection.
        #
        TLS_DH_anon_WITH_AES_256_CBC_SHA
        TLS_DH_anon_WITH_AES_128_CBC_SHA
        SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
        SSL_DH_anon_WITH_RC4_128_MD5
        SSL_RSA_WITH_NULL_SHA
        SSL_RSA_WITH_NULL_MD5


        # Other
        SSL_NULL_WITH_NULL_NULL
        TLS_RSA_WITH_IDEA_CBC_SHA

    Flag for matrixSslEncodeRehandshake():

        SSL_OPTION_FULL_HANDSHAKE

- :Alert

    Alert level codes:

        SSL_ALERT_LEVEL_FATAL
        SSL_ALERT_LEVEL_WARNING

    Alert description codes:

        SSL_ALERT_ACCESS_DENIED
        SSL_ALERT_BAD_CERTIFICATE
        SSL_ALERT_BAD_RECORD_MAC
        SSL_ALERT_CERTIFICATE_EXPIRED
        SSL_ALERT_CERTIFICATE_REVOKED
        SSL_ALERT_CERTIFICATE_UNKNOWN
        SSL_ALERT_CLOSE_NOTIFY
        SSL_ALERT_DECODE_ERROR
        SSL_ALERT_DECOMPRESSION_FAILURE
        SSL_ALERT_DECRYPTION_FAILED
        SSL_ALERT_DECRYPT_ERROR
        SSL_ALERT_HANDSHAKE_FAILURE
        SSL_ALERT_ILLEGAL_PARAMETER
        SSL_ALERT_INAPPROPRIATE_FALLBACK
        SSL_ALERT_INSUFFICIENT_SECURITY
        SSL_ALERT_INTERNAL_ERROR
        SSL_ALERT_NONE
        SSL_ALERT_NO_APP_PROTOCOL
        SSL_ALERT_NO_CERTIFICATE
        SSL_ALERT_NO_RENEGOTIATION
        SSL_ALERT_PROTOCOL_VERSION
        SSL_ALERT_RECORD_OVERFLOW
        SSL_ALERT_UNEXPECTED_MESSAGE
        SSL_ALERT_UNKNOWN_CA
        SSL_ALERT_UNRECOGNIZED_NAME
        SSL_ALERT_UNSUPPORTED_CERTIFICATE
        SSL_ALERT_UNSUPPORTED_EXTENSION

- :Error

    Error codes from different functions:

        PS_FAILURE
        MATRIXSSL_ERROR
        PS_ARG_FAIL
        PS_CERT_AUTH_FAIL
        PS_CERT_AUTH_FAIL_AUTHKEY
        PS_CERT_AUTH_FAIL_BC
        PS_CERT_AUTH_FAIL_DN
        PS_CERT_AUTH_FAIL_EXTENSION
        PS_CERT_AUTH_FAIL_PATH_LEN
        PS_CERT_AUTH_FAIL_REVOKED
        PS_CERT_AUTH_FAIL_SIG
        PS_DISABLED_FEATURE_FAIL
        PS_EAGAIN
        PS_INTERRUPT_FAIL
        PS_LIMIT_FAIL
        PS_MEM_FAIL
        PS_PARSE_FAIL
        PS_PENDING
        PS_PLATFORM_FAIL
        PS_PROTOCOL_FAIL
        PS_TIMEOUT_FAIL
        PS_UNSUPPORTED_FAIL

- :RC

    Return codes from different functions:

        PS_SUCCESS
        MATRIXSSL_SUCCESS
        MATRIXSSL_APP_DATA
        MATRIXSSL_APP_DATA_COMPRESSED
        MATRIXSSL_HANDSHAKE_COMPLETE
        MATRIXSSL_RECEIVED_ALERT
        MATRIXSSL_REQUEST_CLOSE
        MATRIXSSL_REQUEST_RECV
        MATRIXSSL_REQUEST_SEND

- :Limit

    Max amount of disabled ciphers in matrixSslSetCipherSuiteEnabledStatus():

        SSL_MAX_DISABLED_CIPHERS

    Max size for message in matrixSslEncodeToOutdata():

        SSL_MAX_PLAINTEXT_LEN

- :Validate

    Return code in user validation callback:

        SSL_ALLOW_ANON_CONNECTION

- :Bool

    Boolean used in matrixSslSetCipherSuiteEnabledStatus() and {authStatus}:

        PS_TRUE
        PS_FALSE

- :Func

        set_cipher_suite_enabled_status
        get_ssl_alert
        get_ssl_error

# VARIABLES

## CA\_CERTIFICATES

    $keys->load_rsa( undef, undef, undef, $Crypt::MatrixSSL3::CA_CERTIFICATES )

Scalar. Contains path to ca-certificates.crt file distributed with this module.
This file is generated by \`mk-matrixssl-ca-certificates.pl\` and contains
all certificates from current Firefox CA bundle supported by MatrixSSL.

# FUNCTIONS

Some MatrixSSL functions are not accessible from Perl.

These functions implement optimization which is useless in Perl:

    matrixSslGetWritebuf
    matrixSslEncodeWritebuf

## Open

## Close

    Crypt::MatrixSSL3::Open();
    Crypt::MatrixSSL3::Close();

If you write server intensive applications it is still better to control
how often the MatrixSSL library gets initialized/deinitialized. For this
you can call Open() to initialize the library at the start of you
application and (optionally) Close() to deinitialize the library when your
application ends.

If you won't call Open() manually then these functions will be called
automatically before creating first object of any class (::Keys, ::SessID,
::Client, ::Server or ::HelloExt) and after last object will be destroyed:

    matrixSslOpen
    matrixSslClose

## capabilities

    $caps = Crypt::MatrixSSL3::capabilities();

Returns a bitwise OR combination of the following constants:

    SHARED_SESSION_CACHE_ENABLED     - shared session cache between multiple processes is enabled
    STATELESS_TICKETS_ENABLED        - stateless ticket session resuming support is enabled
    DH_PARAMS_ENABLED                - loading the DH param for DH cipher suites is enabled
    ALPN_ENABLED                     - Application Layer Protocol Negotiation callback support is enabled
    SNI_ENABLED                      - Server Name Identification (virtual hosts) support is enabled
    OCSP_STAPLES_ENABLED             - handling of the "status_request" TLS extension by responding with an OCSP staple is enabled
    CERTIFICATE_TRANSPARENCY_ENABLED - handling of the "signed_certificate_timestamp" TLS extension is enabled

Before using any of these features it's a good idea to test if MatrixSSL is supporting them.

## set\_cipher\_suite\_enabled\_status

    $rc = set_cipher_suite_enabled_status( $cipherId, $status );

    matrixSslSetCipherSuiteEnabledStatus( NULL, $cipherId, $status )

If this function will be used, matrixSslClose() will be never called.

## get\_ssl\_alert

    ($level, $descr) = get_ssl_alert( $ptBuf );
    $descr           = get_ssl_alert( $ptBuf );

Unpack alert level and description from $ptBuf returned by
$ssl->received\_data() or $ssl->processed\_data().

Return ($level, $descr) in list context, and $descr in scalar context.
Both $level and $descr are dualvars (code in numeric context and text
in string context).

## get\_ssl\_error

    $rc = get_ssl_error( $rc );

Return dualvar for this error code (same as $rc in numeric context and
text error name in string context).

## refresh\_OCSP\_staple

    $rc = refresh_OCSP_staple( $server_index, $index, $DERfile );

Used to refresh an already loaded OCSP staple either for a default server
or for a virtual host.

Parameters:

- $server\_index

    If you want to update the OCSP staple for a virtual host this parameter
    must have the returned value of the first $sll->init\_SNI(...) call.

    If you want to update the OCSP staple for a default server this parameter
    must have the returned value of the first $ssl->set\_server\_params(...) call

- $index

    When updating a virtual host ($server\_index > -1) this value specifies the
    0-based index of the virtual host for which the OCSP staple should be
    refreshed.

    When updating a default server this value must be -1 or undef

- $DERfile

    File containing the new OCSP staple in DER format as it was received from
    the CA's OCSP responder.

Returns PS\_SUCCESS if the update was successful.

## refresh\_SCT\_buffer

    $sct_array_size = refresh_SCT_buffer( $server_index, $index, $SCT_params );

Used to refresh an already loaded CT extension data buffer either for a
default server or for a virtual host.

Parameters:

- $server\_index and $index

    Are the same as refresh\_OCSP\_staple above.

- $SCT\_params
    - Perl scalar contains a file name with prepared extension data.
    - Perl array reference with file names of SCT binary structures that the
    function will use to create the extension data.

Returns the number of files loaded (if this is 0 there was an error loading one of the files).

## refresh\_ALPN\_data

    $num_protocols = refresh_ALPN_data( $server_index, $index, $protocols );

Used to refresh the application protocols for a default server or for a virtual host.

Parameters:

- $server\_index and $index

    Are the same as refresh\_OCSP\_staple above.

- $protocols

    - Perl array reference containing the new protocols.

    Returns the number of protocols you supplied (if this is 0 there was an error loading one of the files).

Returns the number of files loaded in order to build extension data.

## set\_VHIndex\_callback

    set_VHIndex_callback( \&VHIndexCallback );

More information about ["VHIndexCallback"](#vhindexcallback) in the ["CALLBACKS"](#callbacks) section.

## set\_ALPN\_callback

    set_VHIndex_callback( \&ALPNCallback );

More information about ["ALPNCallback"](#alpncallback) in the ["CALLBACKS"](#callbacks) section.

# CLASSES

Constructors for all classes will throw exception on error instead of
returning error as matrixSslNew\*() functions do. Exception will be
thrown using ` croak($return_code) `, so to get $return\_code from $@
you should convert it back to number:

    eval { $client = Crypt::MatrixSSL3::Client->new(...) };
    $rc = 0+$@ if $@;

## Crypt::MatrixSSL3::Keys

### new

    $keys = Crypt::MatrixSSL3::Keys->new();

    matrixSslNewKeys( $keys )

Return new object $keys.
Throw exception if matrixSslNewKeys() doesn't return PS\_SUCCESS.
When this object will be destroyed will call:

    matrixSslDeleteKeys( $keys )

### load\_rsa

    $rc = $keys->load_rsa( $certFile,
        $privFile, $privPass, $trustedCAcertFiles );

    matrixSslLoadRsaKeys( $keys, $certFile,
        $privFile, $privPass, $trustedCAcertFiles )

### load\_rsa\_mem

    $rc = $keys->load_rsa_mem( $cert, $priv, $trustedCA );

    matrixSslLoadRsaKeysMem( $keys, $cert, length $cert,
        $priv, length $priv, $trustedCA, length $trustedCA )

### load\_ecc

    $rc = $keys->load_ecc( $certFile,
        $privFile, $privPass, $trustedCAcertFiles );

    matrixSslLoadEcKeys( $keys, $certFile,
        $privFile, $privPass, $trustedCAcertFiles )

### load\_rsa\_mem

    $rc = $keys->load_ecc_mem( $cert, $priv, $trustedCA );

    matrixSslLoadEcKeysMem( $keys, $cert, length $cert,
        $priv, length $priv, $trustedCA, length $trustedCA )

### load\_pkcs12

    $rc = $keys->load_pkcs12( $p12File, $importPass, $macPass, $flags );

    matrixSslLoadPkcs12( $keys, $p12File, $importPass, length $importPass,
        $macPass, length $macPass, $flags )

### load\_DH\_params

    $rc = $keys->load_DH_params( $DH_params_file );

    matrixSslLoadDhParams ( $keys, $DH_params_file )

### load\_session\_ticket\_keys

    $rc = $keys->load_session_ticket_keys( $name, $symkey, $hashkey );

    matrixSslLoadSessionTicketKeys ($keys, $name, $symkey, length $symkey,
        $haskkey, length $hashkey )

**Server side.**

## Crypt::MatrixSSL3::SessID

### new

    $sessID = Crypt::MatrixSSL3::SessID->new();

Return new object $sessID representing (sslSessionId\_t\*) type.
Throw exception if failed to allocate memory.
When this object will be destroyed will free memory, so you should
keep this object while there are still Client/Server session
which use this $sessID.

### clear

    $sessID->clear();

    matrixSslClearSessionId($sessID)

## Crypt::MatrixSSL3::Client

### new

    $ssl = Crypt::MatrixSSL3::Client->new(
        $keys, $sessID, \@cipherSuites,
        \&certValidator, $expectedName,
        $extensions, \&extensionCback,
    );

    matrixSslNewClientSession( $ssl,
        $keys, $sessID, \@cipherSuites,
        \&certValidator, $expectedName,
        $extensions, \&extensionCback,
    )

Return new object $ssl.
Throw exception if matrixSslNewClientSession() doesn't return
MATRIXSSL\_REQUEST\_SEND.
When this object will be destroyed will call:

    matrixSslDeleteSession( $ssl )

More information about callbacks ["certValidator"](#certvalidator) and ["extensionCback"](#extensioncback)
in the ["CALLBACKS"](#callbacks) section.

## Crypt::MatrixSSL3::Server

### new

    $ssl = Crypt::MatrixSSL3::Server->new( $keys, \&certValidator );

    matrixSslNewServerSession( $ssl, $keys, \&certValidator )

Return new object $ssl.
Throw exception if matrixSslNewServerSession() doesn't return PS\_SUCCESS.
When this object will be destroyed will call:

    matrixSslDeleteSession( $ssl )

More information about callback ["certValidator"](#certvalidator) in the ["CALLBACKS"](#callbacks) section.

### init\_SNI

    $sni_index = $ssl->init_SNI( $sni_index, $ssl_id, $sni_params );

Used to initialize the virtual host configuration for a server (socket).
This function can be called in two ways:

    # 1) one time, after the first client was accepted and the server SSL
    #    session created
    $sni_index = $ssl->init_SNI( -1, $ssl_id, $sni_params );

When $sni\_index is -1 or undef the XS module will allocate and initialize
a SNI server structure using the parameters present in $sni\_params. After
that, it will register the MatrixSSL SNI callback to an internal XS
function using the newly created SNI server structure as parameter.
This MUST be called only once per server socket and the result $sni\_index
value must be cached for subsequent calls.

    # 2) many times, after clients are accepted and server SSL sessions
    #    created
    $ssl->init_SNI( $sni_index, $ssl_id );

This will skip the SNI server initialization part and just register the
MatrixSSL SNI callback to an internal XS function using the SNI server
structure specified by $sni\_index as parameter.

Parameters:

- $sni\_index int >= 0 or -1|undef

    For the first call this parameter MUST be -1. Subsequent calls MUST use
    the returned value of the first call.

- $ssl\_id

    A 32 bit integer that uniquely identifies this session. This parameter
    will be sent back when MatrixSSL calls the SNI callback defined in the XS
    module when a client sends a SNI extension.
    If the XS module is able to match the requested client hostname it will
    call the Perl callback set with set\_VHIndex\_callback.

- $sni\_params \[{...},...\] or undef

    This is a reference to an array that contains one or more array references:

        $sni_params = [                                                     # virtual hosts support - when a client sends a TLS SNI extension, the settings below will apply
                                                                            #                         based on the requested hostname
            # virtual host 0 (also referred in the code as SNI entry 0)
            {
                'hostname' => 'hostname',                                   # regular expression for matching the hostname
                'cert' => '/path/to/certificate;/path/to/CA-chain',         # KEY - certificate (the CA-chain is optional)
                'key' => '/path/to/private_key',                            # KEY - private key
                'DH_param' => /path/to/DH_params',                          # KEY - file containing the DH parameter used with DH ciphers
                'session_ticket_keys' => {                                  # session tickets setup
                    'id' => '1234567890123456',                             # KEY - TLS session tickets - 16 bytes unique identifier
                    'encrypt_key' => '12345678901234567890123456789012',    # KEY - TLS session tickets - 128/256 bit encryption key
                    'hash_key' => '12345678901234567890123456789012',       # KEY - TLS session tickets - 256 bit hash key
                },
                'OCSP_staple' => '/path/to/OCSP_staple.der',                # SESSION - file containing a OCSP staple that gets sent when a client
                                                                            #           send a TLS status request extension
                'SCT_params' => [                                           # SESSION - Certificate Transparency SCT files used to build the
                                                                            #           'signed_certificate_timestamp' TLS extension data buffer
                    '/path/to/SCT1.sct',
                    '/path/to/SCT2.sct',
                    ...
                ],
                # instead of the Certificate Transparency SCT files you can specify a scalar with a single file that contains multiple SCT files
                # note that this file is not just a concatenation of the SCT files, but a ready-to-use 'signed_certificate_timestamp' TLS extension data buffer
                # see ct-submit.pl for more info
                #'SCT_params' => '/path/to/CT_extension_data_buffer',
                'ALPN' => ['protocol1', 'protocol2']                        # SESSION - server supported protocols
            },
            # virtual host 1
            ...
        ]

Returns the index of the internal SNI server structure used for
registering the MatrixSSL SNI callback. This MUST be saved after the first
call.

### set\_server\_params

    $sv_index = $ssl->set_server_params( $sv_index, $ssl_id, $sv_params );

Used to set the OCSP staple to be returned if the client sends the
"status\_request" TLS extension, the extension data to be returned if the
client sends the "signed\_certificate\_timestamp" TLS extension and the
server supported protocols used when a client send a TLS ALPN extension.

Note that this function call only affects the **default server**. Virtual
hosts are managed by using the $ssl->init\_SNI(...).

See $ssl->init\_SNI(...) for usage.

Parameters:

- $sv\_index and $ssl\_id

    The same as $sni\_index and $ssl\_id for $ssl->init\_SNI(...)

- $sv\_params {...} or undef

    This is a reference to a hash with the following structure (all keys are optional):

        $sv_params = {
            'OCSP_staple' => '/path/to/OCSP_staple.der',
            'SCT_params' => ['/path/to/SCT1.sct', '/path/to/SCT2.sct'] or '/path/to/CT_extension_data_buffer'
            'ALPN' => ['protocol1', 'protocol2']
        }

    If you specify the 'ALPN' parameter, you should also provide
    an ALPN callback. More information about callback ["ALPNCallback"](#alpncallback)
    in the ["CALLBACKS"](#callbacks) section.

    Returns the index of the internal default server structure used for
    registering the parameters. This MUST be saved after the first
    call.

### load\_OCSP\_staple

    $rc = $ssl->load_OCSP_staple( $DERfile );

Loads an OCSP staple to be returned if the client sends the
"status\_request" TLS extension.

Note that this function is very inefficient because the loaded data is
bound to the specified session and it will be freed when the session is
destroyed.
It has the advantage that the session will contain the latest OCSP data if
the OCSP DER file is refreshed in the meantime.

Don't be lazy and use $ssl->set\_server\_params({'OCSP\_staple' => '...'}) and
$ssl->refresh\_OCSP\_staple(...) instead.

## Crypt::MatrixSSL3::Client and Crypt::MatrixSSL3::Server

### get\_outdata

    $rc = $ssl->get_outdata( $outBuf );

Unlike C API, it doesn't set $outBuf to memory location inside MatrixSSL,
but instead it append buffer returned by C API to the end of $outBuf.

    matrixSslGetOutdata( $ssl, $tmpBuf )
    $outBuf .= $tmpBuf

Throw exception if matrixSslGetOutdata() returns < 0.

### sent\_data

    $rc = $ssl->sent_data( $bytes );

    matrixSslSentData( $ssl, $bytes )

### received\_data

    $rc = $ssl->received_data( $inBuf, $ptBuf );

    $n = matrixSslGetReadbuf( $ssl, $buf )
    $n = min($n, length $inBuf)
    $buf = substr($inBuf, 0, $n, q{})
    matrixSslReceivedData( $ssl, $n, $ptBuf, $ptLen )

Combines two calls: matrixSslGetReadbuf() and matrixSslReceivedData().
It copy data from beginning of $inBuf into buffer returned by
matrixSslGetReadbuf() and cut copied data from beginning of $inBuf (it may
copy less bytes than $inBuf contain if size of buffer provided by
MatrixSSL will be smaller).
Then it calls matrixSslReceivedData() to get $rc and may fill $ptBuf with
received alert or application data.

It is safe to call it with empty $inBuf, but this isn't a good idea
performance-wise.

Throw exception if matrixSslGetReadbuf() returns <= 0.

### processed\_data

    $rc = $ssl->processed_data( $ptBuf );

    matrixSslProcessedData( $ssl, $ptBuf, $ptLen )

In case matrixSslReceivedData() or matrixSslProcessedData() will return
MATRIXSSL\_RECEIVED\_ALERT, you can get alert level and description from
$ptBuf:

    my ($level, $descr) = get_ssl_alert($ptBuf);

### encode\_to\_outdata

    $rc = $ssl->encode_to_outdata( $outBuf );

    matrixSslEncodeToOutdata( $ssl, $outBuf, length $outBuf )

### encode\_closure\_alert

    $rc = $ssl->encode_closure_alert();

    matrixSslEncodeClosureAlert( $ssl )

### encode\_rehandshake

    $rc = $ssl->encode_rehandshake(
        $keys, \&certValidator, $sessionOption, \@cipherSuites,
    );

    matrixSslEncodeRehandshake( $ssl, $keys, \&certValidator,
        $sessionOption, \@cipherSuites )

More information about callback ["certValidator"](#certvalidator) in the ["CALLBACKS"](#callbacks) section.

### set\_cipher\_suite\_enabled\_status

    $rc = $ssl->set_cipher_suite_enabled_status( $cipherId, $status );

    matrixSslSetCipherSuiteEnabledStatus( $ssl, $cipherId, $status )

### get\_anon\_status

    $anon = $ssl->get_anon_status();

    matrixSslGetAnonStatus( $ssl, $anon )

## Crypt::MatrixSSL3::HelloExt

### new

    $extension = Crypt::MatrixSSL3::HelloExt->new();

    matrixSslNewHelloExtension>( $extension )

Return new object $extension.
Throw exception if matrixSslNewHelloExtension() doesn't return PS\_SUCCESS.
When this object will be destroyed will call:

    matrixSslDeleteHelloExtension( $extension )

### load

    $rc = $extension->load( $ext, $extType );

    matrixSslLoadHelloExtension( $extension, $ext, length $ext, $extType )

# CALLBACKS

## certValidator

Will be called with two scalar params: $certInfo and $alert
(unlike C callback which also have $ssl param).

Param $certInfo instead of (psX509Cert\_t \*) will contain reference to
array with certificates. Each certificate will be hash in this format:

    notBefore       => $notBefore,
    notAfter        => $notAfter,
    subjectAltName  => {
        dns             => $dns,
        uri             => $uri,
        email           => $email,
    },
    subject        => {
        country         => $country,
        state           => $state,
        locality        => $locality,
        organization    => $organization,
        orgUnit         => $orgUnit,
        commonName      => $commonName,
    },
    issuer         => {
        country         => $country,
        state           => $state,
        locality        => $locality,
        organization    => $organization,
        orgUnit         => $orgUnit,
        commonName      => $commonName,
    },
    authStatus     => $authStatus,

This callback must return single scalar with integer value (as described in
MatrixSSL documentation). If callback die(), then warning will be printed,
and execution will continue assuming callback returned -1.

## extensionCback

Will be called with two scalar params: $type and $data
(unlike C callback which also have $ssl and length($data) params).

This callback must return single scalar with integer value (as described in
MatrixSSL documentation). If callback die(), then warning will be printed,
and execution will continue assuming callback returned -1.

## ALPNCallback

Will be called when a client sends an ALPN extension and a successful
application protocol has been negotiated. If the server doesn't implement
any of the client's protocols the XS module will send an appropriate
response and the client will receive a SSL\_ALERT\_NO\_APP\_PROTOCOL alert.

Will be called with 2 parameters:

    $ssl_id - this is the $ssl_id used in the $ssl->init_SNI(...) or
              $ssl->set_server_params(...) function call
    $app_proto - scalar with the negociated protocol name

## VHIndexCallback

Will be called whenever we have a successful match against the hostname
specified by the client in its SNI extension. This will inform the Perl
code which virtual host the current SSL session belongs to.

Will be called with 2 parameters:

    $ssl_id - this is the $ssl_id used in the $ssl->init_SNI(...) function call
    $index - a 0-based int specifying which virtual host matchd the client requested hostname

Doesn't return anything.

# HOWTO: Certificate Transparency

## PREREQUISITES

For generating Certificate Transparency files you will need the following:

### Certificates

- Server certificate (server.crt)
- Issuer certificate (issuer.crt)
- Certificate Authority chain (server-CA.crt) - this includes any number of
intermediate certificate and optionally ends with the root certificate.

## USING THE ct-submit.pl TOOL

### Generate one file containing SCTs from all CT log servers

    ct-submit.pl --pem server.crt --pem issuer.crt --pem server-CA.pem \
        --extbuf /path/to/CT.sct

The resulted file can be used in your script like:

    # set CT response for a SSL session (default server)
    $sv_index = $ssl->set_server_params( $sv_index, $ssl_id, {
        'SCT_params' => '/path/to/CT.sct'
    });

    # refresh the CT response
    Crypt::MatrixSSL3::refresh_SCT_buffer( $sv_index, undef, '/path/to/CT.sct' );

### Generate multiple SCT files containing binary representation of the responses received from the log servers

    ct-submit.pl --pem server.crt --pem issuer.crt --pem server-CA.pem \
        --individual /path/to/sct/

This will create in the /path/to/stc/ folder the following files
(considering that the requests to the log servers were successful):

    aviator.sct          # https://ct.googleapis.com/aviator
    certly.sct           # https://log.certly.io
    pilot.sct            # https://ct.googleapis.com/pilot
    rocketeer.sct        # https://ct.googleapis.com/rocketeer
    digicert.sct         # https://ct1.digicert-ct.com/log - disabled by default -
                         # accepts certificates only from select CAs
    izenpe.sct           # https://ct.izenpe.com - disabled by default -
                         # accepts certificates only from select CAs

One or more files can be used in your script like:

    # set CT response for a SSL session (default server)
    # note that even if you're using a single file (which will be wrong
    # according to the RFC because at least 2 SCTs from different server logs
    # must be sent), you still need to provide an array reference with one element
    $sv_index = $ssl->set_server_params( $sct_index, $ssl_id, {
        'SCT_params' => [
            '/path/to/sct/aviator.sct',
            '/path/to/sct/certly.sct'
        ]
    });

    # refresh CT response
    Crypt::MatrixSSL3::refresh_SCT_buffer( $sv_index, undef, [
        '/path/to/sct/aviator.sct',
        '/path/to/sct/certly.sct',
    ]);

# HOWTO: OCSP staple

## PREREQUISITES

For generating an OCSP staple you will need to following:

### OpenSSL

OpenSSL with OCSP application installed.

### Certificates

- Server certificate (server.crt)
- Issuer certificate (issuer.crt)
- Full Certificate Authority chain (full-CA.crt) - this includes the issuer
certificate, any number of intermediate certificate and ends with the root
certificate.

## GETTING AN OCSP STAPLE

### Get the OCSP responder URI

    openssl x509 -noout -ocsp_uri -in server.crt

### Query the OCSP responder

    openssl ocsp -no_nonce -issuer issuer.crt -cert server.crt \
        -CAfile full-CA.crt -url OCSP_responder_URI \
        -header "HOST" OCSP_response_host -respout /path/to/OCSP_staple.der

### Inspecting an OCSP staple

    openssl ocsp -respin /path/to/OCSP_staple.der -text -CAfile full-CA.crt

## USAGE

### Set an OCSP staple to be used within a SSL session (default server)

    $sv_index = $ssl->set_server_params( $sv_index, $ssl_id, {
        'OCSP_staple' => '/path/to/OCSP_staple.der'
    });

### Refreshing an already allocated OCSP staple buffer

    Crypt::MatrixSSL3::refresh_OCSP_staple( $sv_index, undef, '/path/to/OCSP_staple.der' );

# HOWTO: Virtual hosts

## TERMINOLOGY

### Default server

Describes a set of properties (certificate, private key, OCSP staple, etc.)
to be used when the client connects but doesn't send a SNI TLS extension
in its CLIENT\_HELLO message.

### Virtual host (SNI entry)

Describes also a set of properties (like above) but these will be used
when the client sends a SNI extension and we have a successful match on
the virtual host's hostname and the client specified hostname.

### SNI server

All the virtual hosts (SNI entries) declared for one server.

## IMPLEMENTATION

Here is some Perl pseudo code on how these are used:

    Crypt::MatrixSSL3::set_VHIndex_callback(sub {
        my ($id, $index) = @_;
        print("Virtual host $index was selected for SSL session $ssl_id");
    });

    Crypt::MatrixSSL3::set_ALPN_callback(sub {
        my ($id, $app_proto) = @_;
        print("Application protocol $app_proto was negociated for SSL session $ssl_id");
    });

    my $sni_index = -1;
    my $sv_index = -1;

    # define a listening socket
    $server_sock = ...

    # initialize default server keys - these will be shared by all server sessions
    my $sv_keys = Crypt::MatrixSSL3::Keys->new();

    # load key material (certificate, private key, etc)
    $sv_keys->load_rsa(...)

    ...

    # we assume when a client connects an accept_client sub will be called
    sub accept_client {
        # accept client socket
        my $client_sock = accept($server_sock, ...);

        # create server session reusing the keys
        my $cssl =  Crypt::MatrixSSL3::Server->new($sv_keys, undef);

        # create a unique SSL session ID
        # for example this can be the fileno of the client socket
        my $ssl_id = fileno($client_sock);

        # set OCSP staple, Certificate Transparecy data (SCT) and supported protocols
        # for the default server. These will be initialized only once and then reused
        # when $sv_index != -1
        $sv_index = $ssl->set_server_params($sv_index, $ssl_id, {
            'OCSP_staple' => '...',
            'SCT_params' => '...',
            'ALPN' => [...]
        });

        # initialize virtual hosts
        # when first called init_SNI will take as first parameter $sni_index which is -1
        # behind the scene the XS module does this (pretty much like what we're doing above)
        #   - allocates a SNI_server structure that will hold one or more SNI_entries (virtual hosts)
        #   - allocates a SNI_entry structure for each virtual host and:
        #     - creates new server keys
        #     - sets up OCSP staple buffer (if needed)
        #     - sets up SCT buffer (if needed)
        #     - stores server implemented protocols if provided
        #   - sets up the matrixSSL SNI callback that will get called if the client sends a SNI TLS extension
        #     in its CLIENT_HELLO message. When the CS SNI callback is called if any of the hostnames define
        #     for each virtual host matches againt the client requested hostname, the &VHIndexCallback setup
        #     above will be called with the $ssl_id of the session and the 0-based index of the virtual host
        #     the client sent its request to
        # returns the index of the newly created SNI_server structure for future use
        # this will be initialized only once and then reused when $sni_index != -1
        $sni_index = $ssl->init_SNI($sni_index, [
            # see MatrixSSL.pm - init_SNI function
        ], $ssl_id);

        # further initialization stuff after accepting the client
        ...
    }

    # secure communication with the client
    ...

# SEE ALSO

http://www.MatrixSSL.org - the download from this site includes
simple yet comprehensive documentation in PDF format.

# SUPPORT

## Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at [https://github.com/powerman/perl-Crypt-MatrixSSL3/issues](https://github.com/powerman/perl-Crypt-MatrixSSL3/issues).
You will be notified automatically of any progress on your issue.

## Source Code

This is open source software. The code repository is available for
public review and contribution under the terms of the license.
Feel free to fork the repository and submit pull requests.

[https://github.com/powerman/perl-Crypt-MatrixSSL3](https://github.com/powerman/perl-Crypt-MatrixSSL3)

    git clone https://github.com/powerman/perl-Crypt-MatrixSSL3.git

## Resources

- MetaCPAN Search

    [https://metacpan.org/search?q=Crypt-MatrixSSL3](https://metacpan.org/search?q=Crypt-MatrixSSL3)

- CPAN Ratings

    [http://cpanratings.perl.org/dist/Crypt-MatrixSSL3](http://cpanratings.perl.org/dist/Crypt-MatrixSSL3)

- AnnoCPAN: Annotated CPAN documentation

    [http://annocpan.org/dist/Crypt-MatrixSSL3](http://annocpan.org/dist/Crypt-MatrixSSL3)

- CPAN Testers Matrix

    [http://matrix.cpantesters.org/?dist=Crypt-MatrixSSL3](http://matrix.cpantesters.org/?dist=Crypt-MatrixSSL3)

- CPANTS: A CPAN Testing Service (Kwalitee)

    [http://cpants.cpanauthors.org/dist/Crypt-MatrixSSL3](http://cpants.cpanauthors.org/dist/Crypt-MatrixSSL3)

# AUTHORS

C. N. Drake <christopher@pobox.com>

Alex Efros <powerman@cpan.org>

# COPYRIGHT AND LICENSE

This software is Copyright (c) 2005- by C. N. Drake <christopher@pobox.com>.

This software is Copyright (c) 2012- by Alex Efros <powerman@cpan.org>.

This is free software, licensed under:

    The GNU General Public License version 2

MatrixSSL is distributed under the GNU General Public License,
Crypt::MatrixSSL3 uses MatrixSSL, and so inherits the same license.
