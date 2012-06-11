#!/usr/bin/perl
# Update ./ca-certificates.crt using current Firefox CA bundle.
use warnings;
use strict;
use blib;
use Crypt::MatrixSSL3;

system('perl mk-ca-bundle.pl -u');
open my $f, '<', 'ca-bundle.crt' or die "open: $!";
my $bundle = join q{}, <$f>;
close $f;
unlink 'ca-bundle.crt';

matrixSslOpen();

open $f, '>', 'ca-certificates.crt' or die "open: $!";
while ($bundle =~ /^(\S[^\n]*)\n=+\n(-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----\n)/msg) {
    my ($name, $cert) = ($1, $2);
    open my $tmp, '>', '/tmp/temp.crt' or die "open: $!";
    print {$tmp} $cert;
    close $tmp;
    matrixSslNewKeys(my $keys);
    my $rc = matrixSslLoadRsaKeys($keys, undef, undef, undef, '/tmp/temp.crt');
    matrixSslDeleteKeys($keys);
    unlink '/tmp/temp.crt';
    print "$Crypt::MatrixSSL3::mxSSL_RETURN_CODES{$rc}\t$name\n";
    print {$f} $cert if $rc == $PS_SUCCESS;
}
close $f or die "close: $!";

matrixSslClose();

