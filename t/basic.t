# -*- mode: cperl; eval: (follow-mode 1); -*-

use Mojo::Base -strict;
use Test::More;
use Test::Mojo;

my $t = Test::Mojo->new('Umi');

$t->get_ok('/public')->status_is(200)->content_like(qr/Login/i);

done_testing;
