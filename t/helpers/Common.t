# -*- mode: cperl; eval: (follow-mode 1); -*-
#

use Mojo::Base -strict;

use Test::More;
use Test::Mojo;

my $t = Test::Mojo->new('Umi');

my $h = $t->app->h_compact({ empty => '', nonempty => '123'});
is exists $h->{empty} ? 1 : 0,                      0, '[h_compact]: empty element removed from hash';
my @a = $t->app->h_compact( qw('' '123') );
is scalar @a == 1 ? 1 : 0,                          1, '[h_compact]: empty element removed from array';

is $t->app->h_is_ip_pair('1.2.3.4 5.6.7.8'),        1, '[h_is_ip_pair]: string is     a pair of IP addresses';
is $t->app->h_is_ip_pair('1.2222.3.4 555.6.777.8'), 0, '[h_is_ip_pair]: string is not a pair of IP addresses';

is $t->app->h_is_ip('1.2.3.4'),                     1, '[h_is_ip]: string is     an IP address';
is $t->app->h_is_ip('1.2222.3.4'),                  0, '[h_is_ip]: string is not an IP address';

is $t->app->h_macnorm({ mac => '01:23:45:67:89:AB' }), '0123456789ab', '[h_macnorm]: colon-delimited normalized';
is $t->app->h_macnorm({ mac => '01-23-45-67-89-ab' }), '0123456789ab', '[h_macnorm]: dash-delimited normalized';
is $t->app->h_macnorm({ mac => '0123.4567.89AB' }),    '0123456789ab', '[h_macnorm]: Cisco-dotted normalized';
is $t->app->h_macnorm({ mac => 'not-a-mac' }),         0,              '[h_macnorm]: invalid format';
is $t->app->h_macnorm({ mac => '01:23:45:67:89' }),    0,              '[h_macnorm]: too few octets';


my $r1 = $t->app->h_qrcode({ toqr => 'HelloWorld' });
is defined $r1->{qr},                                  1,              '[h_qrcode]: qr key defined for simple text';
is substr($r1->{qr}, 0, 5),                            'iVBOR',        '[h_qrcode]: qr payload starts "iVBOR"';
my $r2 = $t->app->h_qrcode({ toqr => 'Привіт' });
is defined $r2->{qr},                                  1,              '[h_qrcode]: qr key defined for UTF-8 text';
is substr($r2->{qr}, 0, 5),                            'iVBOR',        '[h_qrcode]: qr payload starts "iVBOR" for UTF-8';

is $t->app->h_get_rdn('uid=abc,ou=Defg,dc=ij'), 'uid', '[h_get_rdn]: RDN for uid=abc,ou=Defg,dc=ij is uid';
is $t->app->h_get_rdn_val('uid=abc,ou=Defg,dc=ij'), 'abc', '[h_get_rdn_val]: value of RDN for uid=abc,ou=Defg,dc=ij is abc';

my $k = $t->app->h_keygen_ssh;
like $k->{public}, qr/^ssh-ed25519 /, '[h_keygen_ssh]: ' . $k->{public};

$k = $t->app->h_keygen_gpg;
like $k->{public}, qr/^-----BEGIN PGP PUBLIC KEY BLOCK-----/, '[h_keygen_gpg]: ' . $k->{public};

my $p = $t->app->h_pwdgen;
like $p->{ssha}, qr/^\{SSHA\}/, '[h_pwdgen]: ' . $p->{ssha};

my $hd = $t->app->h_hash_diff( { a => 'a', b => 'b', d => 'd'}, { b => 'B', c =>'c', d => 'd'});
is $hd->{added}->{c} eq 'c' && $hd->{changed}->{b}->{new} eq 'B' && $hd->{removed}->{a} eq 'a' && $hd->{unchanged}->{d} eq 'd' ? 1 : 0, 1, '[h_hash_diff]: added `c`, changed `b`, removed `a` and uchanged `d`';

my $ad = $t->app->h_array_diff( [ 'a', 'b', 'c' ], [ 'b', 'c', 'd' ] );
is $ad->{added}->[0] eq 'd' && $ad->{removed}->[0] eq 'a' && $ad->{unchanged}->[0] eq 'b' && $ad->{unchanged}->[1] eq 'c' ? 1 : 0, 1, '[h_array_diff]: added `d`, removed `a` and unchanged `b`, `c`';

is $t->app->h_ts_to_generalizedTime('1991-01-10'), '19910110000000Z', '[h_ts_to_generalizedTime]: `1991-01-10` -> `19910110000000Z`';

#$t->app->h_log($ad);

done_testing;
