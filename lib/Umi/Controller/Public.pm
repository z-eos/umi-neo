package Umi::Controller::Public;
use Mojo::Base 'Umi::Controller', -signatures;

sub do_login ($self) {

    if ($self->req->method eq 'POST') {
	my $username = $self->param('username');
	my $password = $self->param('password');
	$self->set_user_session($username, $password);

	$self->log->debug(sprintf("SESSION: uid<%s> pwd<%s>",
				 $self->session('uid'),
				 $self->session('pwd')));

	$self->stash({uid => $username => pwd => $password});

	if ($self->authenticate($username, $password, {})) {
	    # $self->set_user_session($username, $password);
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
