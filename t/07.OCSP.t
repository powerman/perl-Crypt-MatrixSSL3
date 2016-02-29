use warnings;
use strict;
use Test::More;
use Test::Exception;

use Crypt::MatrixSSL3 qw(:all);

Crypt::MatrixSSL3::Open();

unless (Crypt::MatrixSSL3::capabilities() & OCSP_STAPLES_ENABLED) {
    plan skip_all => "OCSP staples not enabled - OCSP_STAPLES_ENABLED not defined";
} else {
    plan tests => 6;
}

my $certFile            = 't/cert/server.crt';
my $privFile            = 't/cert/server.key';
my $privPass            = undef;
my $OCSPtest            = 't/cert/OCSPtest.der';

my ($Server_Keys, $Server_SSL);

########
# Init #
########

lives_ok { $Server_Keys = Crypt::MatrixSSL3::Keys->new() }
    'Keys->new (server)';
is PS_SUCCESS, $Server_Keys->load_rsa($certFile, $privFile, $privPass, undef),
    '$Server_Keys->load_rsa';
lives_ok { $Server_SSL = Crypt::MatrixSSL3::Server->new($Server_Keys, undef) }
    'Server->new';

my $index = $Server_SSL->set_OCSP_staple(-1, $OCSPtest);

cmp_ok $index, '>=', '0', '$Server_SSL->set_OCSP_staple(-1, file) first call';
cmp_ok $Server_SSL->set_OCSP_staple($index, undef), '==', $index, '$Server_SSL->set_OCSP_staple(index, undef) second call';
cmp_ok Crypt::MatrixSSL3::refresh_OCSP_staple(undef, $index, $OCSPtest), '==', PS_SUCCESS, 'Crypt::MatrixSSL3::refresh_OCSP_staple(undef, index, file)';

undef $Server_SSL;
undef $Server_Keys;

Crypt::MatrixSSL3::Close();
