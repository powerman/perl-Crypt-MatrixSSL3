use warnings;
use strict;
use Carp;
use Test::More tests => 28;
use Test::Exception;

use Scalar::Util qw( weaken );

use Crypt::MatrixSSL3 qw( :DEFAULT :Validate :Alert get_ssl_alert get_ssl_error );

my $trustedCAbundle     = 'ca-certificates.crt';
my $trustedCAcertFiles  = 't/cert/testca.crt';

my $certFile            = 't/cert/testserver.crt';
my $privFile            = 't/cert/testserver.key';
my $privPass            = undef;

my $trustedCAcert; if(open(IN,'<',"$trustedCAcertFiles.der")) {local $/; $trustedCAcert=<IN>; close(IN); }
my $cert; if(open(IN,'<',"$certFile.der")) {local $/; $cert=<IN>; close(IN); }
my $priv; if(open(IN,'<',"$privFile.der")) {local $/; $priv=<IN>; close(IN); }

our ($Server_Keys, $Client_Keys, $SessionID);

our @VALIDATE = (
    0, SSL_ALLOW_ANON_CONNECTION, undef, -1, 
    SSL_ALERT_BAD_CERTIFICATE, SSL_ALERT_UNKNOWN_CA,
    SSL_ALERT_UNSUPPORTED_CERTIFICATE, SSL_ALERT_CERTIFICATE_REVOKED,
    SSL_ALERT_CERTIFICATE_EXPIRED, SSL_ALERT_CERTIFICATE_UNKNOWN,
    SSL_ALERT_ACCESS_DENIED,
);

sub assert { croak 'assertion failed' if $_[0] }

my ($ref, $keys, $sessionId, $ssl);

{ my $x = 'x'; weaken($ref = \$x); $keys = \$x }
ok $ref;
$keys = Crypt::MatrixSSL3::Keys->new();
ok !$ref, 'Keys->new: old $keys freed';
undef $keys;
ok(1, 'matrixSslClose'); # make sure matrixSslClose() doesn't crash

{ my $x = 'x'; weaken($ref = \$x); $sessionId = \$x; }
ok $ref;
$sessionId = Crypt::MatrixSSL3::SessID->new();
ok !$ref, 'SessID->new: old $sessionId freed';

{ my $x = 'x'; weaken($ref = \$x); $ssl = \$x; }
ok $ref;
$keys = Crypt::MatrixSSL3::Keys->new();
assert $keys->load_rsa(undef, undef, undef, $trustedCAbundle);
$ssl = Crypt::MatrixSSL3::Client->new($keys, $sessionId, 0, undef, undef, undef);
ok !$ref, 'Client->new: old $ssl freed';
undef $ssl;

{ my $x = 'x'; weaken($ref = \$x); $ssl = \$x; }
ok $ref;
$keys = Crypt::MatrixSSL3::Keys->new();
assert $keys->load_rsa($certFile, $privFile, $privPass, undef);
$ssl = Crypt::MatrixSSL3::Server->new($keys, undef);
ok !$ref, 'Server->new: old $ssl freed';
undef $ssl;

leaktest('newkeys_deletekeys', test=>100000);
leaktest('loadrsakeys_client', test=>500);
leaktest('loadrsakeys_server');
leaktest('loadrsakeysmem_server');
leaktest('newsessionid_deletesessionid', test=>100000);

$Server_Keys = Crypt::MatrixSSL3::Keys->new();
$Client_Keys = Crypt::MatrixSSL3::Keys->new();
assert $Server_Keys->load_rsa($certFile, $privFile, $privPass, undef);
assert $Client_Keys->load_rsa(undef, undef, undef, $trustedCAbundle);

leaktest('newsession', test=>10000);
leaktest('handshake');
leaktest('client_server', test=>500);
$SessionID = Crypt::MatrixSSL3::SessID->new();
leaktest('client_server', test=>500); # now with same sessionId

undef $Server_Keys;
undef $Client_Keys;
ok(1, 'matrixSslClose'); # make sure matrixSslClose() doesn't crash


sub newkeys_deletekeys {
    $keys = Crypt::MatrixSSL3::Keys->new();
    undef $keys;
}

sub loadrsakeys_client {
    my $keys = Crypt::MatrixSSL3::Keys->new();
    assert $keys->load_rsa(undef, undef, undef, $trustedCAbundle);
}

sub loadrsakeys_server {
    my $keys = Crypt::MatrixSSL3::Keys->new();
    assert $keys->load_rsa($certFile, $privFile, $privPass, $trustedCAcertFiles);
}

sub loadrsakeysmem_server {
    my $keys = Crypt::MatrixSSL3::Keys->new();
    assert $keys->load_rsa_mem($cert, $priv, $trustedCAcert);
}

sub newsessionid_deletesessionid {
    my $sessionId = Crypt::MatrixSSL3::SessID->new();
}

sub newsession {
    my ($Server_SSL, $Client_SSL, $Client_sessionId);
    my $cb = do { my $a = [1 .. 1000]; sub { return $a } };
    $Server_SSL = Crypt::MatrixSSL3::Server->new($Server_Keys, undef);
    $Client_sessionId = Crypt::MatrixSSL3::SessID->new();
    $Client_SSL = Crypt::MatrixSSL3::Client->new($Client_Keys, $Client_sessionId, 0, $cb, undef, undef);
}

sub handshake {
    my ($Server_SSL, $Client_SSL);
    $Server_SSL = Crypt::MatrixSSL3::Server->new($Server_Keys, undef);
    $Client_SSL = Crypt::MatrixSSL3::Client->new($Client_Keys, undef, 0, \&_cb_validate, undef, undef);

    my ($client2server, $server2client) = (q{}, q{});
    my ($client_rc, $server_rc);
    while (1) {
        # quiet warnings about dying in certValidate callback
        open my $oldstderr, '>&', \*STDERR  or die "can't dup STDERR: $!";
        close STDERR                        or die "can't close STDERR: $!";
        open STDERR, '>', \(my $stderr)     or die "can't open STDERR: $!";

        $server_rc = _decode($Server_SSL, $client2server, $server2client);
        $client_rc = _decode($Client_SSL, $server2client, $client2server);

        open STDERR, '>&', $oldstderr       or die "can't reopen STDERR: $!";
        close $oldstderr                    or die "can't close oldstderr: $!";

        last if $client_rc || $server_rc;
    }
    if ($client_rc == -1 && !$server_rc) {
        $server_rc = _decode($Server_SSL, $client2server, $server2client);
    }
    my $rc = (defined $VALIDATE[-1] && ($VALIDATE[-1] == 0 || $VALIDATE[-1] == SSL_ALLOW_ANON_CONNECTION)) ? 1 : -1;
    if ($client_rc != $rc || $server_rc != $rc) {
        die "handshake: expect: $rc, got: $client_rc, $server_rc\n";
    }
}

sub client_server {
    my ($Server_SSL, $Client_SSL);
    $Server_SSL = Crypt::MatrixSSL3::Server->new($Server_Keys, undef);
    $Client_SSL = Crypt::MatrixSSL3::Client->new($Client_Keys, $SessionID, 0, sub{0}, undef, undef);

    my ($client2server, $server2client) = (q{}, q{});
    my ($client_rc, $server_rc);
    while (1) {
        $server_rc = _decode($Server_SSL, $client2server, $server2client);
        $client_rc = _decode($Client_SSL, $server2client, $client2server);
        last if $client_rc || $server_rc;
    }
    $server_rc ||= _decode($Server_SSL, $client2server, $server2client);
    $client_rc == 1
        or die 'client: handshake failed';
    $server_rc == 1
        or die 'server: handshake failed';
    length($client2server) == 0
        or die 'client2server non-empty after handshake';
    length($server2client) == 0
        or die 'server2client non-empty after handshake';

    my $s   = "Hello MatrixSSL!\n";
    my $s16k= $s.("\0" x 16000);
    my $buf;

    $Client_SSL->encode_to_outdata($s) > 0
        or die 'encode_to_outdata';
    $Client_SSL->encode_to_outdata($s) > 0
        or die 'encode_to_outdata';
    assert _decode($Client_SSL, $server2client, $client2server);
    assert _decode($Server_SSL, $client2server, $server2client, $buf);
    $buf eq $s.$s
        or die 'packets 1+2 decoded incorrectly';

    $Client_SSL->encode_to_outdata($s16k) > 0
        or die 'encode_to_outdata';
    $Client_SSL->encode_to_outdata($s16k) > 0
        or die 'encode_to_outdata';
    assert _decode($Client_SSL, $server2client, $client2server);
    assert _decode($Server_SSL, $client2server, $server2client, $buf);
    $buf eq $s.$s.$s16k
        or die 'packet 3 decoded incorrectly';
    assert _decode($Client_SSL, $server2client, $client2server);
    assert _decode($Server_SSL, $client2server, $server2client, $buf);
    $buf eq $s.$s.$s16k.$s16k
        or die 'packet 4 decoded incorrectly';
}

sub _cb_validate {
    my ($crt, $alert) = @_;
    push @VALIDATE, shift @VALIDATE;
    die "I'm tired of validating!\n" if !defined $VALIDATE[-1];
    return $VALIDATE[-1];
}

sub _decode {
    my ($ssl) = @_; # other 3 params must be modified in place
    while (my $n = $ssl->get_readbuf($_[1])) {
        die error($n) if $n < 0;
        my $buf;
        my $rc = $ssl->received_data($n, $buf);
RC:
        if    ($rc == MATRIXSSL_REQUEST_SEND)       { last          }
        elsif ($rc == MATRIXSSL_REQUEST_RECV)       { next          }
        elsif ($rc == MATRIXSSL_HANDSHAKE_COMPLETE) { return 1      }
        elsif ($rc == MATRIXSSL_RECEIVED_ALERT)     { alert($buf); return -1 }
        elsif ($rc == MATRIXSSL_APP_DATA)           { $_[3].=$buf   }
        elsif ($rc == MATRIXSSL_SUCCESS)            { last          }
        else                                        { die error($rc)}
        $rc = $ssl->processed_data($buf);
        goto RC;
    }
    while (my $n = $ssl->get_outdata($_[2])) {
        die error($n) if $n < 0;
        my $rc = $ssl->sent_data($n);
        if    ($rc == MATRIXSSL_REQUEST_SEND)       { next          }
        elsif ($rc == MATRIXSSL_SUCCESS)            { last          }
        elsif ($rc == MATRIXSSL_REQUEST_CLOSE)      { return -1     }
        elsif ($rc == MATRIXSSL_HANDSHAKE_COMPLETE) { return 1      }
        else                                        { die error($rc)}
    }
    return;
}

sub error {
    my $rc = get_ssl_error($_[0]);
    return sprintf "MatrixSSL error %d: %s\n", $rc, $rc;
}
sub alert {
    my ($level, $descr) = get_ssl_alert($_[0]);
#     diag sprintf "MatrixSSL alert: level %d: %s, desc %d: %s\n", $level, $level, $descr, $descr;
    return;
}


##############################################################################

sub leaktest {
    my $test = shift;
    my %arg  = (init=>10, test=>1000, max_mem_diff=>100, diag=>0, @_);
    my $tmp = 'x' x 1000000; undef $tmp;
    my $code = do { no strict 'refs'; \&$test };
    $code->() for 1 .. $arg{init};
    my $mem = MEM_used();
    my $fd  = FD_used();
    $code->() for 1 .. $arg{test};
    diag sprintf "---- MEM $test\nWAS: %d\nNOW: %d\n", $mem, MEM_used() if $arg{diag};
    ok( MEM_used() - $mem < $arg{max_mem_diff},  "MEM: $test" );
    is( FD_used() - $fd, 0,                      " FD: $test" );
}

#########################
# General-purpose utils #
#########################
sub Cat {
    croak 'usage: Cat( FILENAME )' if @_ != 1;
    my ($filename) = @_;
    open my $f, '<', $filename or croak "open: $!";
    local $/ if !wantarray;
    return <$f>;
}
sub MEM_used {
    return(`ps -o'rss' -p $$` =~ /(\d+)/) if($^O=~/(^darwin$)/);	# Mac OS/X
    if($^O=~/Win32/i) { my($m)=`tasklist /nh /fi "PID eq $$"` =~/.*\s([\d,]+)/; $m=~tr/,//d; return $m;}	# MSWin32
    return (Cat('/proc/self/status') =~ /VmRSS:\s*(\d*)/)[0];		# Linux
};
sub FD_used {
    if($^O=~/^(darwin|MSWin32)$/) {
	#diag "If anyone knows how to find the process file-descriptor usage under Mac OS/X or $^O please let me know!";
	return 0;
    }
    opendir my $fd, '/proc/self/fd' or croak "opendir: $!";
    return @{[ readdir $fd ]} - 2;
};

