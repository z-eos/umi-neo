package Umi::Model::Authentication;

use strict;
use warnings;
use experimental qw(signatures);

use Mojo::Base 'Mojolicious', -signatures;
use Mojo::Util qw(secure_compare);
use Mojolicious::Plugin::Authentication;

has 'db';
has name => 'hashy';

sub new ($class) { bless {}, $class }

sub validate_user ($self, $user, $pass) {

    my $account = load_user($user) // return;
  # Success
  return 1 if $USERS->{$user} && secure_compare $USERS->{$user}, $pass;

  # Fail
  return undef;
}

sub load_user ($self, $uid) {
    return $self->model->authentication->load_user($uid);
}

sub validate_user ($controller, $username, $password, $extra) {
   my $authn = $controller->app->model->authentication;
   return $authn->validate_user($username, $password, $extra);
}

1;
