# package Umi::Model::Users;

# use strict;
# use warnings;

# use Mojo::Base 'Mojolicious', -signatures;
# use Mojo::Util qw(secure_compare);

# # use Data::Printer colored => 1, caller_info => 1;

# my $USERS = {
#   joel      => 'las3rs',
#   marcus    => 'lulz',
#   sebastian => 'secr3t'
# };

# sub new ($class) { bless {}, $class }

# sub check ($self, $user, $pass) {

#     # $self->log->debug("Users.pm: user: ",$user,"pass: ",$pass);
#     # p $user;
    
#   # Success
#   return 1 if $USERS->{$user} && secure_compare $USERS->{$user}, $pass;

#   # Fail
#   return undef;
# }

# 1;
package Umi::Model::Users;

use strict;
use warnings;
use experimental qw(signatures);

use Mojo::Util qw(secure_compare);

my $USERS = {joel => 'las3rs', marcus => 'lulz', sebastian => 'secr3t'};

sub new ($class) { bless {}, $class }

sub check ($self, $user, $pass) {

  # Success
  return 1 if $USERS->{$user} && secure_compare $USERS->{$user}, $pass;

  # Fail
  return undef;
}

1;
