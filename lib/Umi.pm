package Umi;

use strict;
use warnings;
use experimental qw(signatures);

use Mojo::Base 'Mojolicious', -signatures;
use Umi::Model::Users;

# This method will run once at server start
sub startup ($self) {

  # Load configuration from config file
  my $config = $self->plugin('NotYAMLConfig');

  # Configure the application
  $self->secrets($config->{secrets});

  # Router
  my $r = $self->routes;

  $self->log->debug('RESTARTING application');

  $self->helper( users => sub { state $users = Umi::Model::Users->new } );
  my $user = $self->param('user') || '';
  my $pass = $self->param('pass') || '';
  
  # Normal route to controller
  $r->any()->to('Auth#login') unless $self->users->check($user, $pass);

  $r->get('/index')->to('Auth#passed');

  # # Make sure user is logged in for actions in this group
  # group {
  #     under sub ($self) {

  # 	  # Redirect to main page with a 302 response if user is not logged in
  # 	  return 1 if $self->session('user');
  # 	  $self->redirect_to('login');
  # 	  return undef;
  #     };

  #     # A protected page auto rendering "protected.html.ep"
  #     $r->get('/protected')->to();
  # };
  
  # $r->get('/')->to('Error#error');

}

1;
