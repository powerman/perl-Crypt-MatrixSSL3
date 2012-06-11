use warnings;
use strict;
use Test::More tests => 13;
use Test::Exception;

use Crypt::MatrixSSL3 qw( :DEFAULT :Error );

my $p12File             = 't/cert/testserver.p12';
my $p12File_nopass      = 't/cert/testserver_nopass.p12';
my $p12File_badca       = 't/cert/testserver_badca.p12';
my $importPass          = 'thepass';


is PS_PARSE_FAIL, _load_pkcs12('no such', undef, undef, 0),
    'bad file';
is PS_CERT_AUTH_FAIL, _load_pkcs12($p12File_badca, undef, undef, 0),
    'bad cert chain';

is PS_SUCCESS, _load_pkcs12($p12File_nopass, undef, undef, 0),
    'not encrypted: NO PASSWORD';
is PS_SUCCESS, _load_pkcs12($p12File_nopass, '', undef, 0),
    'not encrypted: EMPTY PASSWORD';
is PS_PARSE_FAIL, _load_pkcs12($p12File_nopass, 'a_n_y', undef, 0),
    'not encrypted: ANY PASSWORD';
is PS_SUCCESS, _load_pkcs12($p12File_nopass, undef, '', 0),
    'not encrypted: EMPTY MAC PASSWORD';
is PS_SUCCESS, _load_pkcs12($p12File_nopass, undef, 'a_n_y', 0),
    'not encrypted: ANY MAC PASSWORD';
 
is PS_PARSE_FAIL, _load_pkcs12($p12File, undef, undef, 0),
    'encrypted: NO PASSWORD';
is PS_PARSE_FAIL, _load_pkcs12($p12File, '', undef, 0),
    'encrypted: EMPTY PASSWORD';
is PS_PARSE_FAIL, _load_pkcs12($p12File, 'wrong', undef, 0),
    'encrypted: WRONG PASSWORD';
is PS_SUCCESS, _load_pkcs12($p12File, $importPass, undef, 0),
    'encrypted: RIGHT PASSWORD';
is PS_SUCCESS, _load_pkcs12($p12File, $importPass, '', 0),
    'encrypted: RIGHT PASSWORD, EMPTY MAC PASSWORD';
is PS_SUCCESS, _load_pkcs12($p12File, $importPass, 'a_n_y', 0),
    'encrypted: RIGHT PASSWORD, ANY MAC PASSWORD';


sub _load_pkcs12 {
    my $keys = Crypt::MatrixSSL3::Keys->new();
    return $keys->load_pkcs12($_[0], $_[1], $_[2], $_[3]);
}

