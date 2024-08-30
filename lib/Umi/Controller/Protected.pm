package Umi::Controller::Protected;
use Mojo::Base 'Umi::Controller', -signatures;

sub homepage ($self) {
    my $session_data = $self->session;
    $self->render(
	template => 'protected/home' =>
	session  => $self->dumper($session_data) =>
	current_user => $self->dumper($self->current_user) =>
	config => $self->{app}->{cfg}
	);
}

sub other    ($self) { $self->render(template => 'protected/other') }

sub profile  ($self) {
    my $r = ref $self->{app}->{cfg}->{ldap};
    $self->log->debug("user: $r");
    my $dump = $self->{app}->{cfg}->{ldap}->{user}->{entry}->ldif;
    # $self->flash(dump => "$dump");
    $self->render(template => 'protected/profile' =>
		  dump => "$dump" =>
		  hash => $self->{app}->{cfg}->{ldap}->{user}->{as_struct});
}

sub ldif_import    ($self) { $self->render(template => 'protected/tool/ldif-import') }

1;
