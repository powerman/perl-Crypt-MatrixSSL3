package Crypt::MatrixSSL3;

use 5.006;
use strict;
use warnings;

use Scalar::Util qw( dualvar );
use XSLoader;

BEGIN {
    use version 0.77 (); our $VERSION = 'v3.7.3';
    XSLoader::load(__PACKAGE__,$VERSION);
}

use File::ShareDir;
our $CA_CERTIFICATES = File::ShareDir::dist_file('Crypt-MatrixSSL3', 'ca-certificates.crt');

# WARNING The CONST_* constants automatically parsed from this file by
# Makefile.PL to generate const-*.inc, so if these constants will be
# reformatted there may be needs in updating regexp in Makefile.PL.
use constant CONST_VERSION_INT => qw(
    SSL2_MAJ_VER
    SSL3_MAJ_VER
    SSL3_MIN_VER
    TLS_1_1_MIN_VER
    TLS_1_2_MIN_VER
    TLS_MAJ_VER
    TLS_MIN_VER
    MATRIXSSL_VERSION_MAJOR
    MATRIXSSL_VERSION_MINOR
    MATRIXSSL_VERSION_PATCH
);
use constant CONST_VERSION => (
    CONST_VERSION_INT,
    'MATRIXSSL_VERSION_CODE',
    'MATRIXSSL_VERSION',
);
use constant CONST_CIPHER => qw(
    SSL_NULL_WITH_NULL_NULL
    SSL_RSA_WITH_NULL_MD5
    SSL_RSA_WITH_NULL_SHA
    SSL_RSA_WITH_RC4_128_MD5
    SSL_RSA_WITH_RC4_128_SHA
    SSL_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_RSA_WITH_IDEA_CBC_SHA
    SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    SSL_DH_anon_WITH_RC4_128_MD5
    SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    TLS_DH_anon_WITH_AES_128_CBC_SHA
    TLS_DH_anon_WITH_AES_256_CBC_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA256
    TLS_RSA_WITH_AES_256_CBC_SHA256
    TLS_RSA_WITH_SEED_CBC_SHA
    TLS_PSK_WITH_AES_128_CBC_SHA
    TLS_PSK_WITH_AES_128_CBC_SHA256
    TLS_PSK_WITH_AES_256_CBC_SHA384
    TLS_PSK_WITH_AES_256_CBC_SHA
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    TLS_RSA_WITH_AES_128_GCM_SHA256
    TLS_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
);

use constant CONST_SESSION_OPTION => qw(
    SSL_OPTION_FULL_HANDSHAKE
);

use constant CONST_ALERT_LEVEL => qw(
    SSL_ALERT_LEVEL_WARNING
    SSL_ALERT_LEVEL_FATAL
);

use constant CONST_ALERT_DESCR => qw(
    SSL_ALERT_CLOSE_NOTIFY
    SSL_ALERT_UNEXPECTED_MESSAGE
    SSL_ALERT_BAD_RECORD_MAC
    SSL_ALERT_DECRYPTION_FAILED
    SSL_ALERT_RECORD_OVERFLOW
    SSL_ALERT_DECOMPRESSION_FAILURE
    SSL_ALERT_HANDSHAKE_FAILURE
    SSL_ALERT_NO_CERTIFICATE
    SSL_ALERT_BAD_CERTIFICATE
    SSL_ALERT_UNSUPPORTED_CERTIFICATE
    SSL_ALERT_CERTIFICATE_REVOKED
    SSL_ALERT_CERTIFICATE_EXPIRED
    SSL_ALERT_CERTIFICATE_UNKNOWN
    SSL_ALERT_ILLEGAL_PARAMETER
    SSL_ALERT_UNKNOWN_CA
    SSL_ALERT_ACCESS_DENIED
    SSL_ALERT_DECODE_ERROR
    SSL_ALERT_DECRYPT_ERROR
    SSL_ALERT_PROTOCOL_VERSION
    SSL_ALERT_INSUFFICIENT_SECURITY
    SSL_ALERT_INTERNAL_ERROR
    SSL_ALERT_INAPPROPRIATE_FALLBACK
    SSL_ALERT_NO_RENEGOTIATION
    SSL_ALERT_UNSUPPORTED_EXTENSION
    SSL_ALERT_UNRECOGNIZED_NAME
    SSL_ALERT_NO_APP_PROTOCOL
    SSL_ALERT_NONE
);

# Order is important in CONST_ERROR and CONST_RC! Some constants have same
# value, but their names ordered to get better output in %RETURN_CODE.
use constant CONST_ERROR => qw(
    PS_FAILURE
    MATRIXSSL_ERROR
    PS_ARG_FAIL
    PS_PLATFORM_FAIL
    PS_MEM_FAIL
    PS_LIMIT_FAIL
    PS_UNSUPPORTED_FAIL
    PS_DISABLED_FEATURE_FAIL
    PS_PROTOCOL_FAIL
    PS_TIMEOUT_FAIL
    PS_INTERRUPT_FAIL
    PS_PENDING
    PS_EAGAIN
    PS_PARSE_FAIL
    PS_CERT_AUTH_FAIL_BC
    PS_CERT_AUTH_FAIL_DN
    PS_CERT_AUTH_FAIL_SIG
    PS_CERT_AUTH_FAIL_REVOKED
    PS_CERT_AUTH_FAIL
    PS_CERT_AUTH_FAIL_EXTENSION
    PS_CERT_AUTH_FAIL_PATH_LEN
    PS_CERT_AUTH_FAIL_AUTHKEY
);

use constant CONST_RC => qw(
    PS_SUCCESS
    MATRIXSSL_SUCCESS
    MATRIXSSL_REQUEST_SEND
    MATRIXSSL_REQUEST_RECV
    MATRIXSSL_REQUEST_CLOSE
    MATRIXSSL_APP_DATA
    MATRIXSSL_HANDSHAKE_COMPLETE
    MATRIXSSL_RECEIVED_ALERT
    MATRIXSSL_APP_DATA_COMPRESSED
);

use constant CONST_LIMIT => qw(
    SSL_MAX_DISABLED_CIPHERS
    SSL_MAX_PLAINTEXT_LEN
);

use constant CONST_VALIDATE => qw(
    SSL_ALLOW_ANON_CONNECTION
);

use constant CONST_BOOL => qw(
    PS_TRUE
    PS_FALSE
);

use constant CONST_CAPABILITIES => qw(
    SHARED_SESSION_CACHE_ENABLED
    STATELESS_TICKETS_ENABLED
    DH_PARAMS_ENABLED
    ALPN_ENABLED
    SNI_ENABLED
    OCSP_STAPLES_ENABLED
    CERTIFICATE_TRANSPARENCY_ENABLED
);

BEGIN {
    eval 'use constant '.$_.' => '.(0+constant($_)) for
        CONST_VERSION_INT,
        CONST_CIPHER,
        CONST_SESSION_OPTION,
        CONST_ALERT_LEVEL,
        CONST_ALERT_DESCR,
        CONST_ERROR,
        CONST_RC,
        CONST_LIMIT,
        CONST_VALIDATE,
        CONST_BOOL,
        CONST_CAPABILITIES,
        ;
}
# TODO  ExtUtils::Constant fail to generate correct const-*.inc when both
#       string and integer constants used. So, hardcode these constants
#       here until this issue will be fixed.
use constant MATRIXSSL_VERSION_CODE => 'OPEN';
use constant MATRIXSSL_VERSION      => sprintf '%d.%d.%d-%s',
    MATRIXSSL_VERSION_MAJOR,
    MATRIXSSL_VERSION_MINOR,
    MATRIXSSL_VERSION_PATCH,
    MATRIXSSL_VERSION_CODE;

my %ALERT_LEVEL = map { 0+constant($_) => $_ } CONST_ALERT_LEVEL;
my %ALERT_DESCR = map { 0+constant($_) => $_ } CONST_ALERT_DESCR;
my %RETURN_CODE = map { 0+constant($_) => $_ } CONST_ERROR, CONST_RC;


#
# Usage: use Crypt::MatrixSSL3 qw( :all :DEFAULT :RC :Cipher SSL_MAX_PLAINTEXT_LEN ... )
#
my %tags = (
    Version      => [ CONST_VERSION  ],
    Cipher       => [ CONST_CIPHER   ],
    SessOpts     => [ CONST_SESSION_OPTION ],
    Alert        => [ CONST_ALERT_LEVEL, CONST_ALERT_DESCR ],
    Error        => [ CONST_ERROR    ],
    RC           => [ CONST_RC       ],
    Limit        => [ CONST_LIMIT    ],
    Validate     => [ CONST_VALIDATE ],
    Bool         => [ CONST_BOOL     ],
    Capabilities => [ CONST_CAPABILITIES ],
    Func         => [qw(
        set_cipher_suite_enabled_status
        get_ssl_alert
        get_ssl_error
    )],
);
$tags{all}      = [ map { @{$_} } values %tags ];
$tags{DEFAULT}  = [ 'SSL_MAX_PLAINTEXT_LEN', @{$tags{RC}} ];
my %known = map { $_ => 1 } @{ $tags{all} };

sub import {
    my (undef, @p) = @_;
    if (!@p) {
        @p = (':DEFAULT');
    }
    @p = map { /\A:(\w+)\z/xms ? @{ $tags{$1} || [] } : $_ } @p;

    my $pkg = caller;
    no strict 'refs';

    for my $func (@p) {
        next if !$known{$func};
        *{"${pkg}::$func"} = \&{$func};
    }

    return;
}


sub get_ssl_alert {
    my ($ptBuf) = @_;
    my ($level_code, $descr_code) = map {ord} split //, $ptBuf;
    my $level = dualvar $level_code, $ALERT_LEVEL{$level_code};
    my $descr = dualvar $descr_code, $ALERT_DESCR{$descr_code};
    return wantarray ? ($level, $descr) : $descr;
}

sub get_ssl_error {
    my ($rc) = @_;
    my $error = dualvar $rc, $RETURN_CODE{$rc};
    return $error;
}


# shift/goto trick used to force correct source line in XS's croak()
package Crypt::MatrixSSL3::Keys;
sub new { shift; goto &Crypt::MatrixSSL3::KeysPtr::new }

package Crypt::MatrixSSL3::SessID;
sub new { shift; goto &Crypt::MatrixSSL3::SessIDPtr::new }

package Crypt::MatrixSSL3::Client;
sub new { shift; goto &Crypt::MatrixSSL3::SessPtr::new_client }

package Crypt::MatrixSSL3::Server;
sub new { shift; goto &Crypt::MatrixSSL3::SessPtr::new_server }

package Crypt::MatrixSSL3::HelloExt;
sub new { shift; goto &Crypt::MatrixSSL3::HelloExtPtr::new }


1;
__END__

=head1 NAME

Crypt::MatrixSSL3 - Perl extension for SSL and TLS using MatrixSSL.org v3.7.2b


=head1 VERSION

This document describes Crypt::MatrixSSL3 version v3.7.3


=head1 SYNOPSIS

    use Crypt::MatrixSSL3;

    # 1. See the MatrixSSL documentation.
    # 2. See example scripts included in this package:
    #       ssl_client.pl
    #       ssl_server.pl
    #       functions.pl


=head1 DESCRIPTION

Crypt::MatrixSSL3 lets you use the MatrixSSL crypto library (see
http://matrixssl.org/) from Perl.  With this module, you will be
able to easily write SSL and TLS client and server programs.

MatrixSSL includes everything you need, all in under 50KB.

You will need a "C" compiler to build this, unless you're getting
the ".ppm" prebuilt Win32 version.  Crypt::MatrixSSL3 builds cleanly
on (at least) Windows, Linux, and Macintosh machines.

MatrixSSL is an Open Source (GNU General Public License) product, and is
also available commercially if you need freedom from GNU rules.

Everything you need is included here, but check the MatrixSSL.org
web site to make sure you've got the latest version of the
MatrixSSL "C" code if you like (it's in the directory "./matrixssl"
of this package if you want to replace the included version from
the MatrixSSL.org download site.)


=head1 TERMINOLOGY

When a client establishes an SSL connection without sending a SNI extension in its CLIENT_HELLO message we say that the client connects to the B<default server>.

If a SNI extension is present then the client connects to a B<virtual host>.


=head1 EXPORTS

Constants and functions can be exported using different tags.
Use tag ':all' to export everything.

By default (tag ':DEFAULT') only SSL_MAX_PLAINTEXT_LEN and return code
constants (tag ':RC') will be exported.

=over

=item :Version

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

=item :Cipher

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

=item :Alert

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

=item :Error

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

=item :RC

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

=item :Limit

Max amount of disabled ciphers in matrixSslSetCipherSuiteEnabledStatus():

    SSL_MAX_DISABLED_CIPHERS

Max size for message in matrixSslEncodeToOutdata():

    SSL_MAX_PLAINTEXT_LEN

=item :Validate

Return code in user validation callback:

    SSL_ALLOW_ANON_CONNECTION

=item :Bool

Booleans used in matrixSslSetCipherSuiteEnabledStatus() and {authStatus}:

    PS_TRUE
    PS_FALSE

=item :Func

    set_cipher_suite_enabled_status
    get_ssl_alert
    get_ssl_error

=back


=head1 VARIABLES

=head2 CA_CERTIFICATES

    $keys->load_rsa( undef, undef, undef, $Crypt::MatrixSSL3::CA_CERTIFICATES )

Scalar. Contains path to ca-certificates.crt file distributed with this module.
This file is generated by `mk-matrixssl-ca-certificates.pl` and contains
all certificates from current Firefox CA bundle supported by MatrixSSL.


=head1 FUNCTIONS

Some MatrixSSL functions are not accessible from Perl.

These functions will be called automatically before creating first
object of any class (::Keys, ::SessID, ::Client, ::Server or ::HelloExt)
and after last object will be destroyed.

    matrixSslOpen
    matrixSslClose

These functions implement optimization which is useless in Perl:

    matrixSslGetWritebuf
    matrixSslEncodeWritebuf

=over

=item B<Open>()

=item B<Close>()

If you write server intensive applications it is still better to control
how often the MatrixSSL library gets initialized/deinitialized. For this
you can call

    Crypt::MatrixSSL3::Open()

to initialize the library at the start of you application and

    Crypt::MatrixSSL3::Close()

to deinitialize the library when your application ends.

=item B<capabilities>()

Returns a bitwise OR combination of the following constants:

    SHARED_SESSION_CACHE_ENABLED     - shared session cache between multiple processes is enabled
    STATELESS_TICKETS_ENABLED        - stateless ticket session resuming support is enabled
    DH_PARAMS_ENABLED                - loading the DH param for DH cipher suites is enabled
    ALPN_ENABLED                     - Application Layer Protocol Negotiation callback support is enabled
    SNI_ENABLED                      - Server Name Identification (virtual hosts) support is enabled
    OCSP_STAPLES_ENABLED             - handling of the "status_request" TLS extension by responding with an OCSP staple is enabled
    CERTIFICATE_TRANSPARENCY_ENABLED - handling of the "signed_certificate_timestamp" TLS extension is enabled

Before using any of these features it's a good idea to test if MatrixSSL is supporting them.

=item B<set_cipher_suite_enabled_status>( $cipherId, $status )

    matrixSslSetCipherSuiteEnabledStatus( NULL, $cipherId, $status )

If this function will be used, matrixSslClose() will be never called.

=item B<get_ssl_alert>( $ptBuf )

Unpack alert level and description from $ptBuf returned by
$ssl->received_data() or $ssl->processed_data().

Return ($level, $descr) in list context, and $descr in scalar context.
Both $level and $descr are dualvars (code in numeric context and text
in string context).

=item B<get_ssl_error>( $rc )

Return dualvar for this error code (same as $rc in numeric context and
text error name in string context).

=item B<refresh_OCSP_staple>( $server_index, $index, $DERfile )

Used to refresh an already loaded OCSP staple either for a default server or for a virtual host.

Parameters:

=over

=item $server_index

If you want to update the OCSP staple for a virtual host this parameter must have the returned value of the first $sll->init_SNI(...) call.

If you want to update the OCSP staple for a default server this parameter must be -1 or undef.

=item $index

When updating a virtual host ($server_index > -1) this value specifies the 0-based index of the virtual host for which the OCSP staple should be refreshed.

When updating a default server this value specifies the index returned by the $ssl->set_OCSP_staple(...) first call.

=item $DERfile

File containing the new OCSP staple in DER format as it was received from the CA's OCSP responder.

=back

Returns PS_SUCCESS if the update was successful.

=item B<refresh_SCT_buffer> ( $server_index, $index, $SCT_params )

Used to refresh an already loaded CT extension data buffer either for a default server or for a virtual host.

Parameters:

=over

=item $server_index and $index the same as refresh_OCSP_staple above, but $indexs take the return value of the first $ssl->set_SCT_buffer(...) call

=item $SCT_params

Perl scalar contains a file name with prepared extension data.
Perl array reference with file names of SCT binary structures that the function will use to create the extension data.

=back

Returns the number of files loaded in order to build extension data.

=item B<set_VHIndex_callback> ( \&VHIndexCallback )

More information about &VHIndexCallback in the CALLBACKS section.

=back

=head1 CLASSES

Constructors for all classes will throw exception on error instead of
returning error as matrixSslNew*() functions do. Exception will be
thrown using C< croak($return_code) >, so to get $return_code from $@
you should convert it back to number:

    eval { $client = Crypt::MatrixSSL3::Client->new(...) };
    $return_code = 0+$@ if $@;

=head2 Crypt::MatrixSSL3::Keys

=over

=item B<new>()

    matrixSslNewKeys( $keys )

Return new object $keys.
Throw exception if matrixSslNewKeys() doesn't return PS_SUCCESS.
When this object will be destroyed will call:

    matrixSslDeleteKeys( $keys )

=item $keys->B<load_rsa>( $certFile, $privFile, $privPass, $trustedCAcertFiles )

    matrixSslLoadRsaKeys( $keys, $certFile,
        $privFile, $privPass, $trustedCAcertFiles )

=item $keys->B<load_rsa_mem>( $cert, $priv, $trustedCA )

    matrixSslLoadRsaKeysMem( $keys, $cert, length $cert,
        $priv, length $priv, $trustedCA, length $trustedCA )

=item $keys->B<load_pkcs12>( $p12File, $importPass, $macPass, $flags )

    matrixSslLoadPkcs12( $keys, $p12File, $importPass, length $importPass,
        $macPass, length $macPass, $flags )

=item $keys->B<load_DH_params>( $DH_params_file )

    matrixSslLoadDhParams ( $keys, $DH_params_file )

=item $keys->B<load_session_ticket_keys>( $name, $symkey, $hashkey ) C<server side>

    matrixSslLoadSessionTicketKeys ($keys, $name, $symkey, length $symkey, $haskkey, length $hashkey )

=back

=head2 Crypt::MatrixSSL3::SessID

=over

=item B<new>()

Return new object $sessID representing (sslSessionId_t*) type.
Throw exception if failed to allocate memory.
When this object will be destroyed will free memory, so you should
keep this object while there are exist Client/Server session
which uses this $sessID.

=item $sessID->B<clear>()

    matrixSslClearSessionId($sessID);

=back

=head2 Crypt::MatrixSSL3::Client

=over

=item B<new>( $keys, $sessID, \@cipherSuites, \&certValidator, $expectedName, $extensions, \&extensionCback )

    matrixSslNewClientSession( $ssl, $keys, $sessID, \@cipherSuites,
        \&certValidator, $expectedName, $extensions, \&extensionCback )

Return new object $ssl.
Throw exception if matrixSslNewClientSession() doesn't return
MATRIXSSL_REQUEST_SEND.
When this object will be destroyed will call:

    matrixSslDeleteSession( $ssl )

More information about callbacks &certValidator and &extensionCback
in next section.

=back

=head2 Crypt::MatrixSSL3::Server

=over

=item B<new>( $keys, \&certValidator )

    matrixSslNewServerSession( $ssl, $keys, \&certValidator )

Return new object $ssl.
Throw exception if matrixSslNewServerSession() doesn't return PS_SUCCESS.
When this object will be destroyed will call:

    matrixSslDeleteSession( $ssl )

More information about callback &certValidator in next section.

=back

=head2 Crypt::MatrixSSL3::Client and Crypt::MatrixSSL3::Server

=over

=item $ssl->B<get_outdata>( $outBuf )

Unlike C API, it doesn't set $outBuf to memory location inside MatrixSSL,
but instead it append buffer returned by C API to the end of $outBuf.

    matrixSslGetOutdata( $ssl, $tmpBuf )
    $outBuf .= $tmpBuf

=item $ssl->B<sent_data>( $bytes )

    matrixSslSentData( $ssl, $bytes )

=item $ssl->B<get_readbuf>( $inBuf )

Unlike C API, it doesn't set $inBuf to memory location inside MatrixSSL,
but instead it copy data from beginning of $inBuf into buffer returned by
C API and cut copied data from beginning of $inBuf (it may copy less bytes
than $inBuf contain if size of buffer provided by MatrixSSL will be smaller).

    $n = matrixSslGetReadbuf( $ssl, $buf )
    $n = min($n, length $inBuf)
    $buf = substr($inBuf, 0, $n, q{})

It is safe to call it with empty $inBuf, but this isn't a good idea
performance-wise.

=item $ssl->B<received_data>( $bytes, $ptBuf )

    matrixSslReceivedData( $ssl, $bytes, $ptBuf, $ptLen )

=item $ssl->B<processed_data>( $ptBuf )

    matrixSslProcessedData( $ssl, $ptBuf, $ptLen )

In case matrixSslReceivedData() or matrixSslProcessedData() will return
MATRIXSSL_RECEIVED_ALERT, you can get alert level and description from
$ptBuf:

    my ($level, $descr) = get_ssl_alert($ptBuf);

=item $ssl->B<encode_to_outdata>( $outBuf )

    matrixSslEncodeToOutdata( $ssl, $outBuf, length $outBuf )

=item $ssl->B<encode_closure_alert>( )

    matrixSslEncodeClosureAlert( $ssl )

=item $ssl->B<encode_rehandshake>( $keys, \&certValidator, $sessionOption, \@cipherSuites )

    matrixSslEncodeRehandshake( $ssl, $keys, \&certValidator,
        $sessionOption, \@cipherSuites )

More information about callback &certValidator in next section.

=item $ssl->B<set_cipher_suite_enabled_status>( $cipherId, $status )

    matrixSslSetCipherSuiteEnabledStatus( $ssl, $cipherId, $status )

=item $anon = $ssl->B<get_anon_status>()

    matrixSslGetAnonStatus( $ssl, $anon )

=item $ssl->B<init_SNI>( $sni_index, $ssl_id, $sni_params ) C<server side>

Used to initialize the virtual host configuration for a server (socket). This function can be called in two ways:

    1) $sni_index = $ssl->init_SNI( -1, $ssl_id, $sni_params ) - one time, after the first client was accepted and the server SSL session created

When $sni_index is -1 or undef the XS module will allocate and initialize a SNI server structure using the
parameters present in $sni_params. After that, it will register the MatrixSSL SNI callback to an internal XS
function using the newly created SNI server structure as parameter.
This MUST be called only once per server socket and the result $sni_index value must be cached for subsequent calls.

    2) $ssl->init_SNI( $sni_index, $ssl_id ) - many times, after clients are accepted and server SSL sessions created

This will skip the SNI server initialization part and just register the MatrixSSL SNI callback to an internal XS
function using the SNI server structure specified by $sni_index as parameter.

Parameters:

=over

=item $sni_index int >= 0 or -1|undef

For the first call this parameter MUST be -1. Subsequent calls MUST use the returned value of the first call.

=item $sni_params [[...],...] or undef

This is a reference to an array that contains one or more array references:

    $sni_params = [                                      # virtual hosts support - when a client sends a TLS SNI extension, the settings below will apply
                                                         #                         based on the requested hostname
        # virtual host 0 (also referred in the code as SNI entry 0)
        [
            'hostname',                                  # regular expression for matching the hostname
            '/path/to/certificate;/path/to/CA-chain',    # KEY - certificate (the CA-chain is optional)
            '/path/to/private_key',                      # KEY - private key
            '/path/to/DH_params',                        # KEY - file containing the DH parameter used with DH ciphers
            '1234567890123456',                          # KEY - TLS session tickets - 16 bytes unique identifier
            '12345678901234567890123456789012',          # KEY - TLS session tickets - 128/256 bit encryption key
            '12345678901234567890123456789012',          # KEY - TLS session tickets - 256 bit hash key
            '/path/to/OCSP_staple.der',                  # SESSION - file containing a OCSP staple that gets sent when a client
                                                         #           send a TLS status request extension
            [                                            # SESSION - Certificate Transparency SCT files used to build the 'signed_certificate_timestamp' TLS extension data buffer
                '/path/to/SCT1.sct',
                '/path/to/SCT2.sct',
                ...
            ]
            # instead of the Certificate Transparency SCT files you can specify a scalar with a single file that contains multiple SCT files
            # note that this file is not just a concatenation of the SCT files, but a ready-to-use 'signed_certificate_timestamp' TLS extension data buffer
            # see ct-submit.pl for more info
            #'/path/to/CT_extension_data_buffer
        ],
        # virtual host 1
        ...
    ]

=item $ssl_id

A 32 bit integer that uniquely identifies this session. This parameter will be sent back when MatrixSSL calls the SNI callback defined in the XS module when a client sends a SNI extension.
If the XS module is able to match the requested client hostname it will call the Perl callback set with set_VHIndex_callback.

=back

Returns the index of the internal SNI server structure used for registering the MatrixSSL SNI callback. This MUST be saved after the first call.

=item $ssl->B<set_OCSP_staple>( $ocsp_index, $DERfile ) C<server side>

Used to set the OCSP staple to be returned if the client sends the "status_request" TLS extension. Note that this function call
only affects the B<default server>. Virtual hosts are managed by using the $ssl->init_SNI(...)

See $ssl->init_SNI(...) for usage.

The $DERfile parameter specifies the file containing the OCSP staple in DER format.

=item $ssl->B<load_OCSP_staple>( $DERfile ) C<server side>

Loads an OCSP staple to be returned if the client sends the "status_request" TLS extension.

Note that this function is very inefficient because the loaded data is bound to the specified session and it will be freed when the session is destroyed.
It has the advantage that the session will contain the latest OCSP data if the OCSP DER file is refreshed in the meantime.

Don't be lazy and use $ssl->set_OCSP_staple and refresh_OCSP_staple instead.

=item $ssl->B<set_SCT_buffer>( $sct_index, $SCT_params ) C<server side>

Used to set the extension data to be returned if the client sends the "signed_certificate_timestamp" TLS extension. Note that this function call
only affects the B<default server>. Virtual hosts are managed by using the $ssl->init_SNI(...)

See $ssl->init_SNI(...) for usage.

The $SCT_params has the same structure as the one used in the $ssl->init_SNI(...) function.

=item $ssl->B<set_ALPN_callback>( \&ALPNcb ) C<server side>

Sets a callback that will receive as parameter data sent by the client in the ALPN TLS extension.

More information about callback &ALPNcb in next section.

=back

=head2 Crypt::MatrixSSL3::HelloExt

=over

=item B<new>( )

    matrixSslNewHelloExtension>( $extension )

Return new object $extension.
Throw exception if matrixSslNewHelloExtension() doesn't return PS_SUCCESS.
When this object will be destroyed will call:

    matrixSslDeleteHelloExtension( $extension )

=item $extension->B<load>( $ext, $extType )

    matrixSslLoadHelloExtension( $extension, $ext, length $ext, $extType )

=back


=head1 CALLBACKS

=over

=item &certValidator

Will be called with two scalar params: $certInfo and $alert
(unlike C callback which also have $ssl param).

Param $certInfo instead of (psX509Cert_t *) will contain reference to
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

=item &extensionCback

Will be called with two scalar params: $type and $data
(unlike C callback which also have $ssl and length($data) params).

This callback must return single scalar with integer value (as described in
MatrixSSL documentation). If callback die(), then warning will be printed,
and execution will continue assuming callback returned -1.

=item &ALPNcb

Will be called with an array reference containing strings with the protocols
the client supports.

The callback must return the 0-based index of a supported protocol or
-1 if none of the client supplied protocols is supported.

=item &VHIndexCallback

Will be called whenever we have a successful match against the hostname specified by the client in its SNI extension.
This will inform the Perl code which virtual host the current SSL session belongs to.

Will be called with 2 parameters:

    $ssl_id - this is the $ssl_id used in the $ssl->init_SNI(...) function call
    $index - a 0-based int specifying which virtual host matchd the client requested hostname

Doesn't return anything.

=back


=head1 SEE ALSO

http://www.MatrixSSL.org - the download from this site includes
simple yet comprehensive documentation in PDF format.


=head1 SUPPORT

=head2 Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at L<https://github.com/powerman/perl-Crypt-MatrixSSL3/issues>.
You will be notified automatically of any progress on your issue.

=head2 Source Code

This is open source software. The code repository is available for
public review and contribution under the terms of the license.
Feel free to fork the repository and submit pull requests.

L<https://github.com/powerman/perl-Crypt-MatrixSSL3>

    git clone https://github.com/powerman/perl-Crypt-MatrixSSL3.git

=head2 Resources

=over

=item * MetaCPAN Search

L<https://metacpan.org/search?q=Crypt-MatrixSSL3>

=item * CPAN Ratings

L<http://cpanratings.perl.org/dist/Crypt-MatrixSSL3>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Crypt-MatrixSSL3>

=item * CPAN Testers Matrix

L<http://matrix.cpantesters.org/?dist=Crypt-MatrixSSL3>

=item * CPANTS: A CPAN Testing Service (Kwalitee)

L<http://cpants.cpanauthors.org/dist/Crypt-MatrixSSL3>

=back


=head1 AUTHORS

C. N. Drake E<lt>christopher@pobox.comE<gt>

Alex Efros E<lt>powerman@cpan.orgE<gt>


=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2005- by C. N. Drake E<lt>christopher@pobox.comE<gt>.

This software is Copyright (c) 2012- by Alex Efros E<lt>powerman@cpan.orgE<gt>.

This is free software, licensed under:

  The GNU General Public License version 2

MatrixSSL is distributed under the GNU General Public License,
Crypt::MatrixSSL3 uses MatrixSSL, and so inherits the same license.


=cut
