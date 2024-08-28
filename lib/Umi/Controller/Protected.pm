package Umi::Controller::Protected;
use Mojo::Base 'Umi::Controller', -signatures;

sub homepage ($self) { $self->render(template => 'protected/home')  }
sub other    ($self) { $self->render(template => 'protected/other') }

1;
