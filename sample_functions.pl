use blib;
use Crypt::MatrixSSL3 qw( get_ssl_alert get_ssl_error );

# $eof = nb_io($sock, $in, $out);
# Doing I/O on non-blocking $sock.
# Readed data appended to $in.
# Written data deleted from $out.
# Return true on EOF.
# Throw exception on I/O error.
sub nb_io {
    my ($sock, $in, $out) = @_;
    my $n;
    if (length $out) {
        $n = syswrite($sock, $out);
        die "syswrite: $!" if !defined $n && !$!{EAGAIN};
        substr($out, 0, $n, q{});
    }
    do {
        $n = sysread($sock, my $buf=q{}, 1024);
        die "sysread: $!" if !defined $n && !$!{EAGAIN};
        $in .= $buf;
    } while $n;
    my $eof = defined $n && !$n;
    @_[1 .. $#_] = ($in, $out);
    return $eof; 
}

# $err = ssl_io($ssl, $in, $out, $appIn, $appOut, $handshakeIsComplete);
# $in and $out is socket buffers.
# Decoded SSL packets deleted from $in.
# Encoded SSL packets (internal or encoded $appOut) appended to $out.
# Decoded (from $in) application data appended to $appIn.
# Encoded application data deleted from $appOut.
# Flag $handshakeIsComplete is internal and shouldn't be changed by user!
# Return empty string if no error happens;
#   error message text if matrixSsl*() return error.
sub ssl_io {
    my ($ssl, $in, $out, $appIn, $appOut, $handshakeIsComplete) = @_;
    my $err = q{};
RECV:
    while (my $n = $ssl->get_readbuf($in)) {
        if ($n < 0)                                 { $err=error($n); last }
        my $rc = $ssl->received_data($n, my $buf);
RC:
        if    ($rc==MATRIXSSL_REQUEST_SEND)         { last          }
        elsif ($rc==MATRIXSSL_REQUEST_RECV)         { next          }
        elsif ($rc==MATRIXSSL_HANDSHAKE_COMPLETE)   { $handshakeIsComplete=1; last }
        elsif ($rc==MATRIXSSL_RECEIVED_ALERT)       { $err=alert($buf); last }
        elsif ($rc==MATRIXSSL_APP_DATA)             { $appIn.=$buf; $handshakeIsComplete=1 }
        elsif ($rc==MATRIXSSL_SUCCESS)              { last          }
        else                                        { $err=error($rc); last }
        $rc = $ssl->processed_data($buf);
        goto RC;
    }
    goto RET if $err;
SEND:
    while (my $n = $ssl->get_outdata($out)) {
        if ($n < 0)                                 { $err=error($n); last }
        my $rc = $ssl->sent_data($n);
        if    ($rc==MATRIXSSL_REQUEST_SEND)         { next          }
        elsif ($rc==MATRIXSSL_SUCCESS)              { last          }
        elsif ($rc==MATRIXSSL_REQUEST_CLOSE)        { last          }
        elsif ($rc==MATRIXSSL_HANDSHAKE_COMPLETE)   { $handshakeIsComplete=1; last }
        else                                        { $err=error($rc); last }
    }
    goto RET if $err;
    if ($handshakeIsComplete && length $appOut) {
        while (length $appOut) {
            my $s = substr($appOut, 0, SSL_MAX_PLAINTEXT_LEN, q{});
            $ssl->encode_to_outdata($s)
                > 0 or die 'encode_to_outdata';
        }
        goto SEND;
    }
RET:
    @_[1 .. $#_] = ($in, $out, $appIn, $appOut, $handshakeIsComplete);
    return $err;
}

sub error {
    my $rc = get_ssl_error($_[0]);
    return sprintf "MatrixSSL error %d: %s\n", $rc, $rc;
}
sub alert {
    my ($level, $descr) = get_ssl_alert($_[0]);
    return sprintf "MatrixSSL alert %s: %s\n", $level, $descr;
}



1;
