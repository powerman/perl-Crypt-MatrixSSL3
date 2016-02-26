requires 'Getopt::Long';
requires 'JSON';
requires 'LWP::UserAgent';
requires 'MIME::Base64';
requires 'Pod::Usage';
requires 'Scalar::Util';
requires 'perl', '5.006';
requires 'version', '0.77';

on configure => sub {
    requires 'Archive::Tar';
    requires 'ExtUtils::Constant';
    requires 'ExtUtils::MakeMaker', '6.63_03';
};

on test => sub {
    requires 'Socket';
    requires 'Test::Exception';
    requires 'Test::More';
};

on develop => sub {
    requires 'Test::Distribution';
    requires 'Test::Perl::Critic';
};
