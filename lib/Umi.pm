package Umi;

use Mojo::Base 'Mojolicious', -signatures;
use Umi::Model::Users;

use strict;
use warnings;

# This method will run once at server start
sub startup ($self) {

  # Load configuration from config file
  my $config = $self->plugin('NotYAMLConfig');

  # Configure the application
  $self->secrets($config->{secrets});

  # Router
  my $r = $self->routes;

  $self->helper( users => sub { state $users = Umi::Model::Users->new } );
  my $user = $self->param('user') || '';
  my $pass = $self->param('pass') || '';

  $r->any()->to('Auth#login') unless $self->users->check($user, $pass);
  $self->session->{'user'} = $user;
  $self->flash(message => 'Thanks for logging in.');
  # say $self->session->{'user'};

  
  $r->get('/logout')->to('Auth#login');
  $r->post('/login')->to('Auth#passed');

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
