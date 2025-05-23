# -*- mode: cperl; eval: (follow-mode 1); -*-
#

use Mojo::Base -strict;

use Test::More;
use Test::Mojo;

my $t = Test::Mojo->new('Umi');

#my $p = $t->app->h_pwdgen({pwd_alg => 'XKCD', xk_separator_character => 'CHAR', xk_separator_character_char => '-' });
my $p = $t->app->h_pwdgen({ pwd_alg => 'XKCD',
			    xk_num_words => 3,
			    xk_separator_character => 'RANDOM',
			    xk_separator_alphabet => '%^&' });
like $p->{ssha}, qr/^\{SSHA\}/, '[h_pwdgen]: XKCD: ' . $p->{clear};

$p = $t->app->h_pwdgen({pwd_alg => 'APPLEID',
			xk_num_words => 3, });
like $p->{ssha}, qr/^\{SSHA\}/, '[h_pwdgen]: APPLEID: ' . $p->{clear};

$p = $t->app->h_pwdgen({pwd_alg => 'NTLM',
			xk_num_words => 3,});
like $p->{ssha}, qr/^\{SSHA\}/, '[h_pwdgen]: NTLM: ' . $p->{clear};

$p = $t->app->h_pwdgen({pwd_alg => 'SECURITYQ',
			xk_num_words => 3,});
like $p->{ssha}, qr/^\{SSHA\}/, '[h_pwdgen]: SECURITYQ: ' . $p->{clear};

$p = $t->app->h_pwdgen({pwd_alg => 'WEB16',
			xk_num_words => 3,});
like $p->{ssha}, qr/^\{SSHA\}/, '[h_pwdgen]: WEB16: ' . $p->{clear};

$p = $t->app->h_pwdgen({pwd_alg => 'WEB32',
			xk_num_words => 3,});
like $p->{ssha}, qr/^\{SSHA\}/, '[h_pwdgen]: WEB32: ' . $p->{clear};

$p = $t->app->h_pwdgen({pwd_alg => 'WIFI',
			xk_num_words => 3,});
like $p->{ssha}, qr/^\{SSHA\}/, '[h_pwdgen]: WIFI: ' . $p->{clear};

#$t->app->h_log($ad);

done_testing;
