package Umi::Controller::Protected;

use Mojo::Base 'Umi::Controller', -signatures;
use Mojo::Util qw(b64_encode);

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
    my ( $params, $filter, $filter_meta, $filter_translitall, $base, $sizelimit, $return );
    $params = {
	ldap_base_case      => $self->param('ldap_base_case')  =>
	    ldap_history    => $self->param('ldap_history')    =>
	    ldap_subtree    => $self->param('ldap_subtree')    =>
	    search_filter   => $self->param('search_filter')   =>
	    search_base     => $self->param('search_base')
    };
    my $sort_order = 'reverse';
    my $filter_armor = '';

    if ( $params->{'search_global'} // ! exists $params->{'search_base'}) {
	$base = $self->{app}->{cfg}->{ldap}->{cfg}->{base}->{dc};
	$params->{'search_base'} = $base;
    } elsif ( $params->{'search_by_name'}  //
	      $params->{'search_by_email'} //
	      $params->{'search_by_jid'}   //
	      $params->{'search_by_telephone'} ) {
	$base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    } elsif ( defined $params->{'ldap_subtree'} && $params->{'ldap_subtree'} ne '' ) {
	$base = $params->{'ldap_subtree'};
	$sizelimit = 0;
    } else {
	$base = $params->{search_base};
    }

    if ( defined $params->{'search_filter'} &&
	 $params->{'search_filter'} eq '' ) {
	$filter_meta = '*';
    } else {
	$filter_meta = $params->{'search_filter'};
    }

    if ( $params->{ldap_base_case} eq 'search_by_email' ) {
	$filter = sprintf("|(mail=%s)(&(uid=%s)(authorizedService=mail@*))",
			  $filter_meta, $filter_meta );
	$base   = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
	$params->{'search_base'} = $base;
    } elsif ( $params->{ldap_base_case} eq 'search_by_jid' ) {
	$filter = sprintf("&(authorizedService=xmpp@*)(uid=*%s*)", $filter_meta);
	$base   = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
	$params->{'search_base'} = $base;
    } elsif ( $params->{ldap_base_case} eq 'search_by_ip' ) {
	my @narr = split(/\./, $filter_meta);
	pop @narr if scalar @narr == 4;
	$filter = sprintf("|(dhcpStatements=fixed-address %s)(umiOvpnCfgIfconfigPush=%s*)(umiOvpnCfgIroute=%s.*)(ipHostNumber=%s*)",
			  $filter_meta, $filter_meta, join('.', @narr), $filter_meta);
	$base   = $self->{app}->{cfg}->{ldap}->{base}->{dc};
	$params->{'search_base'} = $base;
    } elsif ( $params->{ldap_base_case} eq 'search_pgp' ) {
	$filter = sprintf("|(pgpCertID=%s)(pgpKeyID=%s)(pgpUserID=%s)",
			  $filter_meta, $filter_meta, $filter_meta);
	$base   = $self->{app}->{cfg}->{ldap}->{base}->{pgp};
	$params->{'search_base'} = $base;
    } elsif ( $params->{ldap_base_case} eq 'search_by_mac' ) {
	my $mac = $self->macnorm({ mac => $filter_meta });
	# log_debug { np($mac) };
	push @{$return->{error}}, 'incorrect MAC address'
	    if ! $mac;
	$filter = sprintf("|(dhcpHWAddress=ethernet %s)(&(uid=%s)(authorizedService=dot1x*))(&(cn=%s)(authorizedService=dot1x*))(hwMac=%s)",
			  $self->macnorm({ mac => $filter_meta, dlm => ':', }),
			  $self->macnorm({ mac => $filter_meta }),
			  $self->macnorm({ mac => $filter_meta }),
			  $self->macnorm({ mac => $filter_meta }) );

	$base   = $self->{app}->{cfg}->{ldap}->{base}->{dc};
	$params->{'search_base'} = $base;
    } elsif ( $params->{ldap_base_case} eq 'search_by_name' ) {
	$params->{'search_base'} = $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
	$filter = sprintf("|(givenName=%s)(sn=%s)(uid=%s)(cn=%s)",
			  $filter_meta, $filter_meta, $filter_meta, $filter_meta);
    } elsif ( $params->{ldap_base_case} eq 'search_by_telephone' ) {
	$params->{'search_base'} = $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
	$filter = sprintf("|(telephoneNumber=%s)(mobile=%s)(homePhone=%s)",
			  $filter_meta, $filter_meta, $filter_meta);
    } elsif ( $params->{ldap_base_case} eq 'search_base' &&
	      $params->{'search_base'} eq $self->{app}->{cfg}->{ldap}->{base}->{org} ) {
	# SPECIAL CASE: we wanna each user (except admins) be able to see only org/s he belongs to
	$filter = $params->{'search_filter'} ne '' ? $params->{'search_filter'} : 'objectClass=*';
	$base   = $params->{'search_base'};
	##$filter_armor = join('', @{[ map { '(associatedDomain=' . $_ . ')' } @{$c_user_d->{success}} ]} ) if ! $ldap_crud->role_admin;
    } elsif ( $params->{ldap_base_case} eq 'search_filter' &&
	      $params->{'search_filter'} ne '' ) {
	$filter = $params->{'search_filter'};
	$base   = $params->{'search_base'};
    } elsif ( defined $params->{'ldap_subtree'} &&
	      $params->{'ldap_subtree'} ne '' ) {
	$filter = 'objectClass=*';
	$base   = $params->{'ldap_subtree'};
    } elsif ( defined $params->{'ldap_history'} &&
	      $params->{'ldap_history'} ne '' ) {
	$filter     = 'reqDN=' . $params->{'ldap_history'};
	$sort_order = 'straight';
	$base       = UMI->config->{ldap_crud_db_log};
    } else {
	$filter = 'objectClass=*';
	$base   = $params->{'search_base'};
    }

    my $scope = $params->{search_scope} // 'sub';

    my $filter4search = $filter_armor eq '' ? sprintf("(%s)", $filter ) : sprintf("&(%s)(|%s)",
										  $filter,
										  $filter_armor );

    $params->{'filter'} = '(' . $filter . ')';
    
    $self->log->debug('SEARCH RESULT');
    my $ldap = Umi::Ldap->new( $self->{app},
			       $self->session('uid'),
			       $self->session('pwd') );

    my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		       filter => $filter4search,
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

    # my $s;
    # foreach ($search->entries) {
    # 	$s .= $_->ldif;
    # }

    $self->render(template => 'protected/search/common' => searchres => $search->as_struct);

}

sub pwdgen ($self) {
    my $par = $self->req->params->to_hash;
    use Data::Printer;
    p $par;
    if (%$par) {
	$self->stash(pwdgen_params => $par);
	return $self->render(template => 'protected/tool/pwdgen' => pwdgen => $self->h_pwdgen($par));
    } else {
	return $self->render(template => 'protected/tool/pwdgen');
    }
}

1;
