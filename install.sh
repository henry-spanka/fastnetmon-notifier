#!/bin/bash
APT_DEPS="openssl exim4 libcrypt-ssleay-perl libssl-dev ca-certificates"
PERL_DEPS="Data::Validate::IP YAML:XS Email::MIME Email::Sender::Simple LWP::UserAgent IO::Socket::SSL Net::SSLeay LWP::Protocol::https JSON"

apt-get install -y $APT_DEPS
cpan install $PERL_DEPS
