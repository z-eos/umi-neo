# package Umi::Controller::Auth;
# use Mojo::Base 'Mojolicious::Controller', -signatures;

# use Data::Printer colored => 1, caller_info => 1;

# sub login ($self) {

#     # Render template "auth/login.html.ep" with message
#     $self->render(msg => 'Welcome to the login page');
#     # p $self->stash;
# }

# sub logout ($self) {
#     $self->session(expires => 1);
#     $self->redirect_to('login');
# }

# sub passed ($self) {
#     # Render template "auth/passed.html.ep" with message
#     $self->render(msg => 'Welcome to the passed page');
# }

# 1;
package Umi::Controller::Login;
use Mojo::Base 'Mojolicious::Controller', -signatures;

sub index ($self) {
  my $user = $self->param('user') || '';
  my $pass = $self->param('pass') || '';
  return $self->render unless $self->users->check($user, $pass);

  $self->session(user => $user);
  $self->flash(message => 'Thanks for logging in.');
  $self->redirect_to('protected');
}

sub logged_in ($self) {
  return 1 if $self->session('user');
  $self->redirect_to('index');
  return undef;
}

sub logout ($self) {
  $self->session(expires => 1);
  $self->redirect_to('index');
}

1;
