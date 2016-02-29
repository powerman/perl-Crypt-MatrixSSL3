use warnings;
use strict;
use Test::More;
use Test::Exception;

use Crypt::MatrixSSL3 qw(:all);

Crypt::MatrixSSL3::Open();

unless (Crypt::MatrixSSL3::capabilities() & CERTIFICATE_TRANSPARENCY_ENABLED) {
    plan skip_all => "Certificate Transparency not enabled - CERTIFICATE_TRANSPARENCY_ENABLED not defined";
} else {
    plan tests => 9;
}

my $certFile            = 't/cert/server.crt';
my $privFile            = 't/cert/server.key';
my $privPass            = undef;
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

my $index = $Server_SSL->set_SCT_buffer(-1, $CTbuffer);

cmp_ok $index, '>=', '0', '$Server_SSL->set_SCT_buffer(-1, scalar) first call';
cmp_ok $Server_SSL->set_SCT_buffer($index, undef), '==', $index, '$Server_SSL->set_SCT_buffer(index, undef) second call';
cmp_ok Crypt::MatrixSSL3::refresh_SCT_buffer(undef, $index, $CTbuffer), '==', 1, 'Crypt::MatrixSSL3::refresh_SCT_buffer(undef, index, scalar)';

$index = $Server_SSL->set_SCT_buffer(-1, $CTfiles);

cmp_ok $index, '>=', '0', '$Server_SSL->set_SCT_buffer(-1, arrayref) first call';
cmp_ok $Server_SSL->set_SCT_buffer($index, undef), '==', $index, '$Server_SSL->set_SCT_buffer(index, undef) second call';
cmp_ok Crypt::MatrixSSL3::refresh_SCT_buffer(undef, $index, $CTfiles), '==', 2, 'Crypt::MatrixSSL3::refresh_SCT_buffer(undef, index, arrayref)';

undef $Server_SSL;
undef $Server_Keys;

Crypt::MatrixSSL3::Close();
