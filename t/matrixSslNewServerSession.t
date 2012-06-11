use warnings;
use strict;
use Test::More tests => 8;
use Test::Exception;

use Crypt::MatrixSSL3 qw( :DEFAULT :Error );

my ($ssl, $keys);


is undef, $ssl,
    'ssl not defined';
throws_ok { $ssl = Crypt::MatrixSSL3::Server->new($keys=undef, undef) }
    qr/^${\PS_FAILURE}\b/,
    'no keys';

lives_ok { $keys = Crypt::MatrixSSL3::Keys->new() }
    'Keys->new';

lives_ok { $ssl = Crypt::MatrixSSL3::Server->new($keys, undef) }
    'empty keys';

is PS_SUCCESS, $keys->load_rsa(undef, undef, undef, 'ca-certificates.crt'),
    '$keys->load_rsa';

lives_ok { $ssl = Crypt::MatrixSSL3::Server->new($keys, undef) }
    'wrong keys';

ok $ssl && $$ssl > 0,
    'ssl is not NULL';
undef $ssl;

undef $keys;
ok(1, 'matrixSslClose');

