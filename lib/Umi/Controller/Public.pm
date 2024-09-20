# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Controller::Public;

use Mojo::Base 'Umi::Controller', -signatures;
use Mojo::Util qw( dumper );

use Umi::Ldap;

sub do_login ($self) {

    if ($self->req->method eq 'POST') {
	my $username = $self->param('username');
	my $password = $self->param('password');

	$self->h_log(sprintf("DEBUG: uid<%s> pwd<%s>", $username, $password));

	## IMPORTANT
	# here we prepare data for authentication
	my $ldap = Umi::Ldap->new( $self->{app}, $username, $password )->ldap;

	if ($self->authenticate($username, $password, {ldap => $ldap})) {
	    $self->set_user_session($username, $password);
	    $self->stash({uid => $username => pwd => $password});
	    $self->flash(message => "Successful login as $username", status => 'ok');
	    return $self->redirect_to('protected_root')
	}
    }
    $self->flash(message => 'Authentication error', status => 'error');

    return $self->redirect_to('public_root')
}

sub do_logout ($self) {
    $self->logout;
    $self->session(expires => 1);
    return $self->redirect_to('/');
}

sub homepage ($self) {
    return $self->render(template => 'public/home');
}

sub other ($self) {
    return $self->render(template => 'public/other');
}

1;
