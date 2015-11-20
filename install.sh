#!/bin/bash
APT_DEPS="openssl exim4 libcrypt-ssleay-perl"
PERL_DEPS="Data::Validate::IP YAML:XS Email::MIME Email::Sender::Simple LWP::UserAgent JSON"

apt-get install -y $APT_DEPS
cpan install $PERL_DEPS
