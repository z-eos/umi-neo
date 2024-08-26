package Authentication;
use Mojo::Base 'Mojolicious::Controller', -signatures;
use Try::Catch;
use Mojo::Util 'dumper';

# API-level authentication useable example routes

# this can be used in a "under()" scenario to move on towards private
# routes or stop here.
sub api_logout ($self) {
   $self->logout;
   return $self->rendered(204);
}

sub api_login ($self) {
   my $username = $self->param('username');
   my $password = $self->param('password');
   return $self->rendered(204)
      if $self->authenticate($username, $password, {});
   return $self->render(json => {status => 'error'}, status => 401);
}


########################################################################
#
# Local username/password based authentication, either via hash or DB

sub do_logout ($self) {
   $self->logout;
   return $self->redirect_to('/');
}

sub show_login ($self) {
   if ($self->is_user_authenticated) { # no point in showing login
      $self->redirect_to('/');
   }
   else {
      $self->render(template => 'login');
   }
   return;
}

sub do_login ($self) {
   my $username = $self->param('username');
   my $password = $self->param('password');
   if ($self->authenticate($username, $password, {})) {
      $self->flash(message => "Welcome, $username", status => 'ok');
      return $self->redirect_to('/')
   }
   $self->flash(message => 'Authentication error', status => 'error');
   return $self->redirect_to('public_root')
}

1;
