use 5.00001;
use ExtUtils::MakeMaker;
#
#  WARNING: Do not try to "make dist" under Windows; it destroys the Upper/lower CaSe of some files.
#
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
#
# Many thanks to Randy Kobes for helping me figure out how to make this work on Win32, which
# also laid the foundation for me getting it to work nicely on Linux and Macintosh
#
use Config;
my $os_src = ($^O =~ /Win32/) ? 'core/WIN32' : 'core/POSIX';
my $o = $Config{obj_ext};
my $c='.c';
my $mxbase='matrixssl-3-3-open';

if(!-d $mxbase) {	# Extract the MatrixSSL original source if it's not already extracted.
  use Archive::Tar;
  my $tar = Archive::Tar->new;
  $tar->read("$mxbase.tgz");
  $tar->extract();
}

my $mxfiles="$mxbase.files";
my $mxmodfiles="modfiles";


# Apply cumulative patch, if any
if (-r "$mxbase.patch") {
    system("cd $mxbase && patch -p1 -N -i ../$mxbase.patch");
}


# NOTE: For future versions of MatrixSSL (this is v1.8.6) - if the below routine failes - you might need to do this;
#       1. cd matrixssl-x-y-z/src
#       2. make all; cd ..
#       3. find . -name '*.o' -print >/tmp/objs
#       4. vi ../Makefile.PL
#       5. include the file /tmp/objs - eg:   ":r /tmp/objs"
#       6. change all the ".o" endings to "$mxext"
#       7. change all the leading "./" to $mxbase/
#       8. join them all on to one line and assign them all to "$mxfiles"; be careful NOT to expand the "$mxext" or "$mxbase" (eg: use single quotes)
#       9. replace the os/linux/linux$mxext one with os/$os_src$mxext


# Autogenerate list with object files produced by MatrixSSL because it's
# different between MatrixSSL versions.
if (! -r $mxfiles) {
    if ($^O =~ /Win32/) {
        # TODO  I don't have windoze with installed perl and C compiler,
        #       so I can't realize this feature for Win32.
        die "$mxfiles autogeneration not supported under Win32 yet.\n";
    }
    else {
        system("
            cd \Q$mxbase\E/ &&
            make all &&
            cd ../ &&
            find \Q$mxbase\E -name '*.o' | sed 's/\.o\$//' > \Q$mxfiles\E
            ") and die "system: $? $!";
    }
}
# Prepare list of object & C MatrixSSL files for usage in Makefile later.
open my $files, '<', $mxfiles or die "open: $!";
chomp(my @files = <$files>);
close $files;
s{core/POSIX|core/WIN32}{$os_src} for @files;
# These are all the object files we need for our release
my $mxobjs  = join ' ', map { $_.$o } @files;
# These are the .c files that built the above objects.
# Note that the peersec "Makefile" did this for us, via "make all" in the
# "./matrixssl" subdirectory.
my $mxc     = join ' ', map { $_.$c } @files;

# Here, we fudge the replacement of the original MatrixSSL source code for the clean
sub MY::clean_subdirs {
#Was:  return "clean_subdirs :\t$(NOECHO) $(NOOP)\n";
  return qq ~clean_subdirs :\n\t\$(MV) "$mxbase" "/tmp/delme-$$-$mxbase"\n~;
  # return qq ~clean_subdirs :\n\t\$(CP) "$mxbase/src/pki/matrixPki.h.ori" "$mxbase/src/pki/matrixPki.h"\n~;
}

# FIXME If this code not needed anymore, then it should be deleted
#       together with $mxc var above.
sub MY::postamble {

return '';

        return "

libmatrixssl.lib: $mxbase/src/Makefile $mxc
	cd $mxbase/src && \$(MAKE) all
	ar -rc libmatrixssl.lib $mxobjs

";
#     'OBJECT'		=> 'matrixssl/src/libmatrixssl.so matrixssl/src/cipherSuite.c matrixssl/src/matrixSsl.c matrixssl/src/sslEncode.c matrixssl/src/sslDecode.c matrixssl/src/sslv3.c matrixssl/src/crypto/peersec/base64.c matrixssl/src/crypto/peersec/arc4.c matrixssl/src/crypto/peersec/asn1.c matrixssl/src/crypto/peersec/des3.c matrixssl/src/crypto/peersec/md2.c matrixssl/src/crypto/peersec/md5.c matrixssl/src/crypto/peersec/mpi.c matrixssl/src/crypto/peersec/rsa.c matrixssl/src/crypto/peersec/sha1.c matrixssl/src/os/psMalloc.c matrixssl/src/os/linux/linux.c', # link all the C files too

}


# Some Linicies seem to require '-lpthread' - if you're having problems, try removing this:-
my $libs = ($^O =~ /Win32/) ? '' : '-lpthread';

my $defines = q{};
$defines.='-DLINUX '            if $^O =~ /linux/;
$defines.='-DPOSIX '            if $^O !~ /Win32/;
$defines.='-DPSTM_64BIT '       if $^O !~ /Win32/ && $Config{archname} =~ /64/;
$defines.='-Os -fomit-frame-pointer -fPIC -I./ -I../ ';

# From: ./matrixssl-3-3-open/matrixssl/matrixsslConfig.h
$defines.='-D_h_MATRIXSSLCONFIG ';              # prevent 'redefined' warnings
$defines.='-DUSE_TLS_RSA_WITH_AES_128_CBC_SHA ';
$defines.='-DUSE_TLS_RSA_WITH_AES_256_CBC_SHA ';
$defines.='-DUSE_SSL_RSA_WITH_3DES_EDE_CBC_SHA ';
# $defines.='-DUSE_SSL_RSA_WITH_RC4_128_SHA ';
# $defines.='-DUSE_SSL_RSA_WITH_RC4_128_MD5 ';
$defines.='-DUSE_SSL_RSA_WITH_NULL_SHA ';
$defines.='-DUSE_SSL_RSA_WITH_NULL_MD5 ';
$defines.='-DUSE_TLS ';				# TLS 1.0 aka SSL 3.1
$defines.='-DUSE_TLS_1_1 ';
# $defines.='-DDISABLE_SSLV3 ';
$defines.='-DUSE_CLIENT_SIDE_SSL ';
$defines.='-DUSE_SERVER_SIDE_SSL ';
$defines.='-DSSL_DEFAULT_IN_BUF_SIZE=1500 ';	# Baseline recv buf size
$defines.='-DSSL_DEFAULT_OUT_BUF_SIZE=1500 ';	# Baseline send buf size
$defines.='-DSSL_SESSION_TABLE_SIZE=32 ';
$defines.='-DSSL_SESSION_ENTRY_LIFE=86400000 ';	# one day
$defines.='-DENABLE_SECURE_REHANDSHAKES ';
# $defines.='-DREQUIRE_SECURE_REHANDSHAKES ';
# $defines.='-DENABLE_INSECURE_REHANDSHAKES ';
$defines.='-DENABLE_FALSE_START ';
$defines.='-DUSE_BEAST_WORKAROUND ';
# $defines.='-DUSE_CERT_CHAIN_PARSING ';
# $defines.='-DUSE_SSL_HANDSHAKE_MSG_TRACE ';
# $defines.='-DUSE_SSL_INFORMATIONAL_TRACE ';

# From: ./matrixssl-3-3-open/crypto/cryptoConfig.h
$defines.='-D_h_PS_CRYPTOCONFIG ';
# $defines.='-DUSE_CRYPTO_TRACE ';
$defines.='-DUSE_RSA ';
# $defines.='-DPS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM ';
$defines.='-DPS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED ';
$defines.='-DUSE_AES ';
$defines.='-DUSE_3DES ';
$defines.='-DUSE_DES ';
$defines.='-DPS_AES_IMPROVE_PERF_INCREASE_CODESIZE ';
$defines.='-DPS_3DES_IMPROVE_PERF_INCREASE_CODESIZE ';
$defines.='-DUSE_ARC4 ';
$defines.='-DUSE_RC2 ';
$defines.='-DUSE_SHA1 ';
$defines.='-DUSE_MD5 ';
$defines.='-DUSE_HMAC ';
$defines.='-DPS_MD5_IMPROVE_PERF_INCREASE_CODESIZE ';
$defines.='-DPS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE ';
$defines.='-DUSE_X509 ';
$defines.='-DUSE_CERT_PARSE ';
$defines.='-DUSE_FULL_CERT_PARSE ';
$defines.='-DUSE_BASE64_DECODE ';
$defines.='-DUSE_PRIVATE_KEY_PARSING ';
$defines.='-DUSE_PKCS5 ';
$defines.='-DUSE_PKCS8 ';
$defines.='-DUSE_PKCS12 ';
$defines.='-DUSE_YARROW ';
# $defines.='-DUSE_BURN_STACK ';

$defines.='-DUSE_INT64 ';			# possibly only for 64bit hosts, altough on Intel, "A 32-bit application that can do 64-bit integer arithmetic"...

$defines.='-DMATRIX_USE_FILE_SYSTEM ';		# enable reading key files


if ($^O =~ /Win32/) {
    open my $f, '<', $mxbase.'/core/osdep.h' or die "open: $!";
    my $h = join q{}, <$f>;
    close $f or die "close: $!";
    $h =~ s{__declspec\(dll\w+\)}{}g;
    open $f, '>', $mxbase.'/core/osdep.h' or die "open: $!";
    print {$f} $h;
    close $f or die "close: $!";
}


WriteMakefile(
    NAME		=> 'Crypt::MatrixSSL3',
    VERSION_FROM	=> 'MatrixSSL3.pm', # finds $VERSION
    BUILD_REQUIRES      => {
        'Config'            => 0,
        'Archive::Tar'      => 0,
    },
    PREREQ_PM		=> {
        'Test::More'        => 0,
        'Test::Exception'   => 0,
        'IO::Socket'        => 0,
        'Scalar::Util'      => 0,
        'Carp'              => 0,
    },
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM    => 'MatrixSSL3.pm', # retrieve abstract from module
       AUTHOR           => 'C. N. Drake <christopher@pobox.com>')
    : ()),
    LIBS		=> [$libs], # e.g., '-lm'
    DEFINE		=> $defines, # e.g., '-DHAVE_SOMETHING'
    INC		        => "-I. -I$mxbase", # e.g., '-I. -I/usr/include/other'
    OBJECT		=> "$mxobjs MatrixSSL3$o", # link all the C files too
    clean               => {FILES => "$mxobjs Matrixssl$o"},
);


if (eval {require ExtUtils::Constant; 1}) {
    open my $f, '<', 'MatrixSSL3.pm' or die "open: $!";
    my %names = map {s/^\s*//;s/\s*$//;$_=>1} grep /^\s+[A-Z0-9_]+\s*$/, <$f>;
    close $f;
    ExtUtils::Constant::WriteConstants(
        NAME         => 'Crypt::MatrixSSL3',
        DEFAULT_TYPE => 'IV',
        NAMES        => [
            (grep {!/^MATRIXSSL_VERSION(?:_CODE)?$/} keys %names),
#             (map {{name=>$_,type=>'PV'}} qw( MATRIXSSL_VERSION MATRIXSSL_VERSION_CODE )),
        ],
        C_FILE       => 'const-c.inc',
        XS_FILE      => 'const-xs.inc',
    );
}


{
    my $online = prompt 'Run tests which require internet connection', 'n';
    $online = lc $online eq 'y' ? 'y' : 'n';
    open my $f, '>', 't/config.pm' or die "open: $!";
    printf {$f} "use constant CFG_ONLINE => '%s';\n", $online;
    printf {$f} '1;';
    close $f or die "close: $!";
}


package MY;

sub c_o {
    my $inherited = shift->SUPER::c_o(@_);
    $inherited =~ s{\$\*.c\n}{\$\*.c -o \$\*.o\n}mg;
    return $inherited;
}


