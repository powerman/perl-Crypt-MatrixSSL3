#!/usr/bin/perl
use warnings;
use strict;
use blib;
use IO::Socket;
use Crypt::MatrixSSL3;
require 'sample_functions.pl';

# Process arguments:

my ($PORT) = @ARGV==1 ? ($ARGV[0])
           :            (4433)
           ;

warn <<"EOUSAGE";
Crypt::MatrixSSL3 sample SSL server.
Usage: $0 [port]
Starting https server on port ${PORT}
EOUSAGE

# Initialize vars:

my ($srvsock, $sock, $eof);                     # for socket i/o
my ($in, $out, $appIn, $appOut) = (q{}) x 4;    # ssl and app buffers
my ($handshakeIsComplete, $err);                # ssl state
my ($ssl, $keys);                               # for MatrixSSL

# Initialize MatrixSSL (as server):

$keys = Crypt::MatrixSSL3::Keys->new();
$keys->load_rsa('t/cert/testserver.crt', 't/cert/testserver.key', undef, undef)
    == PS_SUCCESS or die 'load_rsa';
$ssl = Crypt::MatrixSSL3::Server->new($keys, undef);

# Socket I/O:

$srvsock = IO::Socket::INET->new(Listen=>5, LocalPort=>$PORT, ReuseAddr=>1)
    or die 'unable to start server';
$sock = $srvsock->accept();
$sock->blocking(0);

my $processed;  # flag: true if client request was processed
while (!$eof && !$err && !($processed && !length $out)) {
    # Processing client request and sending reply.
    if (!$processed && $appIn =~ /\r\n\r\n/) {
        $appOut = "HTTP/1.0 200 OK\r\nServer: Crypt::MatrixSSL3\r\n\r\n"
                . "Below is copy of your request:\r\n$appIn";
        $processed = 1;
    }
    # I/O
    $eof = nb_io($sock, $in, $out);
    $err = ssl_io($ssl, $in, $out, $appIn, $appOut, $handshakeIsComplete);
}

close($sock);
close($srvsock);

# Process result:

die $err if $err;

