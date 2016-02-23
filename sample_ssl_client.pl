#!/usr/bin/perl
use warnings;
use strict;
use blib;
use IO::Socket;
use Crypt::MatrixSSL3 qw(:all);
require 'sample_functions.pl';

# Process arguments:

my ($HOST, $PORT) = @ARGV==2 ? @ARGV
                  : @ARGV==1 ? ($ARGV[0], 'https')
                  :            ('google.com', 'https')
                  ;

warn <<"EOUSAGE";
Crypt::MatrixSSL3 sample SSL client.
Usage: $0 [hostname [port]]
Now downloading: https://${HOST}:${PORT}/

EOUSAGE

# Initialize vars:

my ($sock, $eof);                               # for socket i/o
my ($in, $out, $appIn, $appOut) = (q{}) x 4;    # ssl and app buffers
my ($handshakeIsComplete, $err);                # ssl state
my ($ssl, $keys);                               # for MatrixSSL

$appOut = "GET / HTTP/1.0\r\nHost: ${HOST}\r\n\r\n";

# Initialize MatrixSSL (as client):

Crypt::MatrixSSL3::open();

my $r = PS_SUCCESS;

$keys = Crypt::MatrixSSL3::Keys->new();
#die "load_rsa: $r" unless ($r = $keys->load_rsa(undef, undef, undef, 'ca-certificates.crt') == PS_SUCCESS);
die "load_rsa: $r" unless ($r = $keys->load_rsa(undef, undef, undef, 't/cert/testCA.crt') == PS_SUCCESS);
warn "1";
$ssl = Crypt::MatrixSSL3::Client->new($keys, undef, undef, sub {0}, undef, undef, undef);
warn "2";

# Socket I/O:

$sock = IO::Socket::INET->new("${HOST}:${PORT}")
    or die 'unable to connect to remote server';
$sock->blocking(0);

while (!$eof && !$err) {
    # I/O
    $eof = nb_io($sock, $in, $out);
    $err = ssl_io($ssl, $in, $out, $appIn, $appOut, $handshakeIsComplete);
}

close($sock);

# Process result:

print $appIn;
die $err if $err;

