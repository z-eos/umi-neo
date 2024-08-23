package Umi::Controller::Error;
use Mojo::Base 'Mojolicious::Controller', -signatures;

# This action will render a template
sub error ($self) {

  # Render template "example/welcome.html.ep" with message
  $self->render(msg => 'AUTH not passed!');
}

1;
