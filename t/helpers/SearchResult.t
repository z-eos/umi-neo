# -*- mode: cperl; eval: (follow-mode 1); -*-
#

use Mojo::Base -strict;

use Test::More;
use Test::Mojo;

my $t = Test::Mojo->new('Umi');

my $d = $t->app->h_dns_resolver({ fqdn => 'a.root-servers.net', name => '198.41.0.4', type => 'PTR', legend => 'test1' });
is exists $d->{success} && $d->{success} eq 'a.root-servers.net' ? 1 : 0, 1, '[h_dns_resolver]: PTR: 198.41.0.4 resolves to a.root-servers.net';
$d = $t->app->h_dns_resolver({ name => 'a.root-servers.net', type => 'A', legend => 'test2' });
is exists $d->{success} && $d->{success} eq '198.41.0.4' ? 1 : 0, 1, '[h_dns_resolver]: A: a.root-servers.net resolves to 198.41.0.4';

# $t->app->h_log($d);

done_testing;

