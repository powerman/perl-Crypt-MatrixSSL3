use warnings;
use strict;
use Test::More tests => 3;
use Test::Exception;

use Crypt::MatrixSSL3;

my $certFile            = 't/cert/testserver.crt';
my $privFile            = 't/cert/testserver.key';
my $privPass            = undef;
my $trustedCAcertFiles  = 't/cert/testca.crt';
my $Server_Keys         = 0;


lives_ok { $Server_Keys = Crypt::MatrixSSL3::Keys->new() }
    'Keys->new';

my $rc = $Server_Keys->load_rsa($certFile, $privFile, $privPass, undef);
is $rc, PS_SUCCESS, '$Server_Keys->load_rsa';

undef $Server_Keys;
ok 1, 'matrixSslClose';

