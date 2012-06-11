#!/usr/bin/perl
use warnings;
use strict;
use blib;
use IO::Socket;
use Crypt::MatrixSSL3;
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

$keys = Crypt::MatrixSSL3::Keys->new();
$keys->load_rsa(undef, undef, undef, 'ca-certificates.crt;t/cert/testca.crt')
    == PS_SUCCESS or die 'load_rsa';
$ssl = Crypt::MatrixSSL3::Client->new($keys, undef, 0, sub{0}, undef, undef);

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

