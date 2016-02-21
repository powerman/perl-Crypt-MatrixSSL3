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

Crypt::MatrixSSL3::open();

open $f, '>', 'ca-certificates.crt' or die "open: $!";
while ($bundle =~ /^(\S[^\n]*)\n=+\n(-----BEGIN CERTIFICATE-----\n.*?\n-----END CERTIFICATE-----\n)/msg) {
    my ($name, $cert) = ($1, $2);
    open my $tmp, '>', 'temp.crt' or die "open: $!";
    print {$tmp} $cert;
    close $tmp;
    my $keys = Crypt::MatrixSSL3::Keys->new();
    my $rc = $keys->load_rsa(undef, undef, undef, 'temp.crt');
    undef $keys;
    unlink 'temp.crt';
    print "" . ($rc == PS_SUCCESS ? "Adding" : "Ignoring") . " $name\n";
    print {$f} $cert if $rc == PS_SUCCESS;
}
close $f or die "close: $!";

Crypt::MatrixSSL3::close();
