package Umi::Controller::Protected;
use Mojo::Base 'Umi::Controller', -signatures;

sub homepage ($self) { $self->render(template => 'protected/home')  }
sub other    ($self) { $self->render(template => 'protected/other') }
sub profile  ($self) {
    my $dump = $self->{app}->{cfg}->{ldap}->{user}->{entry}->ldif;
    # $self->flash(dump => "$dump");
    $self->render(template => 'protected/profile' => dump => "$dump" => hash => $self->{app}->{cfg}->{ldap}->{user}->{as_struct})
}

1;
