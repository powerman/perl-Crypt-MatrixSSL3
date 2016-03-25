use warnings;
use strict;
use Test::More;
use Test::Exception;

use Crypt::MatrixSSL3 qw(:all);

Crypt::MatrixSSL3::Open();

unless (Crypt::MatrixSSL3::capabilities() & OCSP_STAPLES_ENABLED) {
    plan skip_all => "OCSP staples not enabled - OCSP_STAPLES_ENABLED not defined";
} else {
    plan tests => 8;
}

my $certFile            = 't/cert/server.crt';
my $privFile            = 't/cert/server.key';
my $privPass            = undef;
my $OCSPtest            = 't/cert/OCSPtest.der';
my $CTbuffer            = 't/cert/CTbuffer.sct';
my $CTfiles             = ['t/cert/CTfile1.sct', 't/cert/CTfile2.sct'];

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

my $server_index = $Server_SSL->set_server_params(-1, 420, {
    'OCSP_staple' => $OCSPtest,
    'SCT_params' => $CTbuffer,
    'ALPN' => ['proto1', 'proto2']
});

cmp_ok $server_index, '>=', '0', '$Server_SSL->set_server_params(-1, 420, params) first call';
cmp_ok $Server_SSL->set_server_params($server_index, 420), '==', $server_index, '$Server_SSL->set_server_params(index, 420) second call';
cmp_ok Crypt::MatrixSSL3::refresh_OCSP_staple($server_index, undef, $OCSPtest), '==', PS_SUCCESS, 'Crypt::MatrixSSL3::refresh_OCSP_staple(server_index, undef, file)';
cmp_ok Crypt::MatrixSSL3::refresh_SCT_buffer($server_index, undef, $CTbuffer), '==', 1, 'Crypt::MatrixSSL3::refresh_SCT_buffer(server_index, undef, file)';
cmp_ok Crypt::MatrixSSL3::refresh_SCT_buffer($server_index, undef, $CTfiles), '==', 2, 'Crypt::MatrixSSL3::refresh_SCT_buffer(server_index, undef, [files])';

undef $Server_SSL;
undef $Server_Keys;

Crypt::MatrixSSL3::Close();
