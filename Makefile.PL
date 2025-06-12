#!/usr/bin/env perl
# IMPORTANT: if you delete this file your app will not work as
# expected.  You have been warned.
use lib '.';
use inc::Module::Install 1.02;

name 'Umi';
all_from 'lib/Umi.pm';

#--- umi related stuff ------------------------------------------------

requires 'Mojolicious';
requires 'Mojolicious::Plugin::Authentication';
# probably you may need 'cpan -f -i Mojolicious::Plugin::Authorization'
requires 'Mojolicious::Plugin::Authorization';
requires 'Mojolicious::Plugin::StaticCache';
requires 'Mojolicious::Plugin::CHI';
requires 'Crypt::HSXKPasswd';
requires 'Crypt::X509';
requires 'Crypt::X509::CRL';
requires 'Data::Printer';
requires 'Digest::SHA';
requires 'File::Path';
requires 'File::Temp';
requires 'File::Which';
requires 'GD';
requires 'GD::Barcode::QRcode';
requires 'IPC::Run';
requires 'Net::CIDR::Set';
requires 'Net::DNS';
requires 'Net::LDAP';
requires 'Text::vCard';
requires 'Try::Tiny';

test_requires 'Test::More';
test_requires 'Test::Mojo';

install_script glob('script/*.pl');
auto_install;
WriteAll;
