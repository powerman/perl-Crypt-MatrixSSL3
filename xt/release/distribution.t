use Test::More;

eval { require Test::Distribution };
plan( skip_all => 'Test::Distribution not installed' ) if $@;
Test::Distribution->import(
    not => 'prereq', # our Makefile.PL is too complex to be parsed
    podcoveropts => {
        also_private    => [
            qr/^(?:constant)$/,
        ],
        # pod_from        => 'MAIN PM FILE HERE',
    }
);
