package Umi::Controller::Auth;
use Mojo::Base 'Mojolicious::Controller', -signatures;

# This action will render a template
sub login ($self) {

  # Render template "auth/login.html.ep" with message
  $self->render(msg => 'Welcome to the Mojolicious real-time web framework!');
}

sub logout ($self) {
    $self->session(expires => 1);
    $self->redirect_to('login');
}
# This action will render a template
sub passed ($self) {

  # Render template "auth/login.html.ep" with message
  $self->render(msg => 'Welcome to the Mojolicious real-time web framework!');
}

1;
