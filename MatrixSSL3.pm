package Crypt::MatrixSSL3;

use 5.006;
use strict;
use warnings;

use Scalar::Util qw( dualvar );
use XSLoader;

BEGIN {
    our $VERSION = '3.3';
    XSLoader::load(__PACKAGE__,$VERSION);
}

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
    SSL_RSA_WITH_3DES_EDE_CBC_SHA
    SSL_RSA_WITH_NULL_MD5
    SSL_RSA_WITH_NULL_SHA
    SSL_RSA_WITH_RC4_128_MD5
    SSL_RSA_WITH_RC4_128_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    SSL_OPTION_FULL_HANDSHAKE
);
use constant CONST_ALERT_LEVEL => qw(
    SSL_ALERT_LEVEL_FATAL
    SSL_ALERT_LEVEL_WARNING
);
use constant CONST_ALERT_DESCR => qw(
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
    SSL_ALERT_INTERNAL_ERROR
    SSL_ALERT_NONE
    SSL_ALERT_NO_CERTIFICATE
    SSL_ALERT_NO_RENEGOTIATION
    SSL_ALERT_PROTOCOL_VERSION
    SSL_ALERT_RECORD_OVERFLOW
    SSL_ALERT_UNEXPECTED_MESSAGE
    SSL_ALERT_UNKNOWN_CA
    SSL_ALERT_UNSUPPORTED_CERTIFICATE
    SSL_ALERT_UNSUPPORTED_EXTENSION
);
# Order is important in CONST_ERROR and CONST_RC! Some constants have same
# value, but their names ordered to get better output in %RETURN_CODE.
use constant CONST_ERROR => qw(
    PS_FAILURE
    MATRIXSSL_ERROR
    PS_ARG_FAIL
    PS_CERT_AUTH_FAIL
    PS_LIMIT_FAIL
    PS_MEM_FAIL
    PS_PARSE_FAIL
    PS_PLATFORM_FAIL
    PS_PROTOCOL_FAIL
    PS_UNSUPPORTED_FAIL
);
use constant CONST_RC => qw(
    PS_SUCCESS
    MATRIXSSL_SUCCESS
    MATRIXSSL_APP_DATA
    MATRIXSSL_HANDSHAKE_COMPLETE
    MATRIXSSL_RECEIVED_ALERT
    MATRIXSSL_REQUEST_CLOSE
    MATRIXSSL_REQUEST_RECV
    MATRIXSSL_REQUEST_SEND
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

BEGIN {
    eval 'use constant '.$_.' => '.(0+constant($_)) for
        CONST_VERSION_INT,
        CONST_CIPHER,
        CONST_ALERT_LEVEL,
        CONST_ALERT_DESCR,
        CONST_ERROR,
        CONST_RC,
        CONST_LIMIT,
        CONST_VALIDATE,
        CONST_BOOL,
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
    Version     => [ CONST_VERSION  ],
    Cipher      => [ CONST_CIPHER   ],
    Alert       => [ CONST_ALERT_LEVEL, CONST_ALERT_DESCR ],
    Error       => [ CONST_ERROR    ],
    RC          => [ CONST_RC       ],
    Limit       => [ CONST_LIMIT    ],
    Validate    => [ CONST_VALIDATE ],
    Bool        => [ CONST_BOOL     ],
    Func        => [qw(
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

Crypt::MatrixSSL3 - Perl extension for SSL and TLS using MatrixSSL.org v3.3


=head1 SYNOPSIS

  use Crypt::MatrixSSL3;

  # 1. See the MatrixSSL documentation.
  # 2. See scripts included in this package:
  #     sample_ssl_client.pl
  #     sample_ssl_server.pl
  #     sample_functions.pl


=head1 DESCRIPTION

Crypt::MatrixSSL3 lets you use the MatrixSSL crypto library (see
http://matrixssl.org/) from Perl.  With this module, you will be
able to easily write SSL and TLS client and server programs.

MatrixSSL includes everything you need, all in under 50KB.

You will need a "C" compiler to build this, unless you're getting
the ".ppm" prebuilt Win32 version.  Crypt::MatrixSSL3 builds cleanly
on (at least) Windows, Linux, and Macintosh machines.

MatrixSSL is an Open Source (GNU Public License) product, and is
also available commercially if you need freedom from GNU rules.

Everything you need is included here, but check the MatrixSSL.org
web site to make sure you've got the latest version of the
MatrixSSL "C" code if you like (it's in the directory "./matrixssl"
of this package if you want to replace the included version from
the MatrixSSL.org download site.)


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

    SSL_NULL_WITH_NULL_NULL
    SSL_RSA_WITH_3DES_EDE_CBC_SHA
    SSL_RSA_WITH_NULL_MD5
    SSL_RSA_WITH_NULL_SHA
    SSL_RSA_WITH_RC4_128_MD5
    SSL_RSA_WITH_RC4_128_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV

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
    SSL_ALERT_INTERNAL_ERROR
    SSL_ALERT_NONE
    SSL_ALERT_NO_CERTIFICATE
    SSL_ALERT_NO_RENEGOTIATION
    SSL_ALERT_PROTOCOL_VERSION
    SSL_ALERT_RECORD_OVERFLOW
    SSL_ALERT_UNEXPECTED_MESSAGE
    SSL_ALERT_UNKNOWN_CA
    SSL_ALERT_UNSUPPORTED_CERTIFICATE
    SSL_ALERT_UNSUPPORTED_EXTENSION

=item :Error

Error codes from different functions:

    PS_FAILURE
    MATRIXSSL_ERROR
    PS_ARG_FAIL
    PS_CERT_AUTH_FAIL
    PS_LIMIT_FAIL
    PS_MEM_FAIL
    PS_PARSE_FAIL
    PS_PLATFORM_FAIL
    PS_PROTOCOL_FAIL
    PS_UNSUPPORTED_FAIL

=item :RC

Return codes from different functions:

    PS_SUCCESS
    MATRIXSSL_SUCCESS
    MATRIXSSL_APP_DATA
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

=back

=head2 Crypt::MatrixSSL3::SessID

=over

=item B<new>()

Return new object $sessid representing (sslSessionId_t*) type.
Throw exception if failed to allocate memory.
When this object will be destroyed will free memory, so you should
keep this object while there are exist Client/Server session
which uses this $sessid.

=item $sessid->B<init>()

 matrixSslInitSessionId($sessid);

=back

=head2 Crypt::MatrixSSL3::Client

=over

=item B<new>( $keys, $sessionId, $cipherSuite, \&certValidator, $extensions, \&extensionCback )

 matrixSslNewClientSession( $ssl, $keys, $sessionId, $cipherSuite,
    \&certValidator, $extensions, \&extensionCback )

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

=item $ssl->B<get_readbuf>( $ssl, $inBuf )

Unlike C API, it doesn't set $inBuf to memory location inside MatrixSSL,
but instead it copy data from beginning of $inBuf into buffer returned by
C API and cut copied data from beginning of $inBuf (it may copy less bytes
than $inBuf contain if size of buffer provided by MatrixSSL will be smaller).

 $n = matrixSslGetReadbuf( $ssl, $buf )
 $n = min($n, length $inBuf)
 $buf = substr($inBuf, 0, $n, q{})

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

=item $ssl->B<encode_rehandshake>( $keys, \&certValidator, $sessionOption, $cipherSpec )

 matrixSslEncodeRehandshake( $ssl, $keys, \&certValidator,
    $sessionOption, $cipherSpec )

More information about callback &certValidator in next section.

=item $ssl->B<set_cipher_suite_enabled_status>( $cipherId, $status )

 matrixSslSetCipherSuiteEnabledStatus( $ssl, $cipherId, $status )

=item $ssl->B<get_anon_status>( $anon )

 matrixSslGetAnonStatus( $ssl, $anon )

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

 notBefore      => $notBefore,
 notAfter       => $notAfter,
 subjectAltName => {
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

=back


=head1 SEE ALSO

http://www.MatrixSSL.org - the download from this site includes
simple yet comprehensive documentation in PDF format.


=head1 AUTHORS

 C. N. Drake, <christopher@pobox.com>
 Alex Efros  <powerman-asdf@ya.ru>


=head1 COPYRIGHT AND LICENSE

MatrixSSL is distrubed under the GNU Public License:-
http://www.gnu.org/copyleft/gpl.html

Crypt::MatrixSSL3 uses MatrixSSL, and so inherits the same License.

 Copyright (C) 2005,2012 by C. N. Drake.
 Copyright (C) 2012 by Alex Efros.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.3 or,
at your option, any later version of Perl 5 you may have available.


=cut
