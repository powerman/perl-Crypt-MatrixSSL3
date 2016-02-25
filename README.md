[![Build Status](https://travis-ci.org/powerman/perl-Crypt-MatrixSSL3.svg?branch=master)](https://travis-ci.org/powerman/perl-Crypt-MatrixSSL3)
[![Coverage Status](https://coveralls.io/repos/powerman/perl-Crypt-MatrixSSL3/badge.svg?branch=master)](https://coveralls.io/r/powerman/perl-Crypt-MatrixSSL3?branch=master)

# DESCRIPTION

Crypt::MatrixSSL3 lets you use the MatrixSSL crypto library (see
http://matrixssl.org/) from Perl.  With this module, you will be
able to easily write SSL and TLS client and server programs.

MatrixSSL includes everything you need, all in under 50KB.

You will need a "C" compiler to build this.
This version works in linux.  Older versions worked in (at least)
Windows and Mac too - let me know if you need a build for these,
and I'll do the work to get it going for you.

MatrixSSL is an Open Source (GNU General Public License) product, and is
also available commercially if you need freedom from GNU rules.

Everything you need should be included here, but check the 
MatrixSSL.org web site to make sure you've got the latest version
of the MatrixSSL "C" code.

# INSTALLATION

To install this module type the following:

       perl Makefile.PL
       make
       make test
       make install

# DEPENDENCIES

This module requires no other modules or libraries.

# COPYRIGHT AND LICENCE

MatrixSSL is distributed under the GNU General Public License:-
http://www.gnu.org/copyleft/gpl.html

Crypt::MatrixSSL3 uses MatrixSSL, and so inherits the same License.

Copyright (C) 2005,2006,2012,2016 by C. N. Drake <christopher@pobox.com>.

Copyright (C) 2012,2016 by Alex Efros <powerman@cpan.org>.
