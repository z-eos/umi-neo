package Umi::Controller::Protected;

use Mojo::Base 'Umi::Controller', -signatures;

use Umi::Ldap;

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
    my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

    my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		       filter => sprintf("(uid=%s)", $self->session('uid')),
		       scope => 'one' };
    my $search = $ldap->search(	$search_arg );
    if ( $search->code ) {
	$self->log->error(
	    sprintf("Protected.pm: profile(): code: %s; message: %s; text: %s",
		    $search->code,
		    $search->error_name,
		    $search->error_text
	    ));
	return undef;
    }

    $self->render(template => 'protected/profile' =>
		  dump => $search->entry->ldif => hash => $search->as_struct);
}

sub ldif_import    ($self) { $self->render(template => 'protected/tool/ldif-import') }

sub search_common  ($self) {
    # if ($self->req->method eq 'POST') {
	my $ldapsearch_filter = $self->param('ldapsearch_filter');
	$self->log->debug('SEARCH RESULT');
	my $ldap = Umi::Ldap->new( $self->{app},
				   $self->session('uid'),
				   $self->session('pwd') );

	my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
			   filter => $ldapsearch_filter,
			   scope => 'sub' };
	my $search = $ldap->search( $search_arg );
	if ( $search->code ) {
	    $self->log->error(
		sprintf("Protected.pm: profile(): code: %s; message: %s; text: %s",
			$search->code,
			$search->error_name,
			$search->error_text
		));
	    return undef;
	}

	my $s;
	foreach ($search->entries) {
	    $s .= $_->ldif;
	}
	
	$self->render(template => 'protected/search/common' => searchres => $s);

    # } else {
    # 	return 1;
    # }
}

1;
