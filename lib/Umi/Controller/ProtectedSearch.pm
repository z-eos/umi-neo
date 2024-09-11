# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Controller::Search;

use Mojo::Base 'Umi::Controller', -signatures;
use Mojo::Util qw(b64_encode);

use Umi::Ldap;
use Umi::Helpers::SearchResult;

sub search_common  ($self) {
  my (
      $base,
      $filter,
      $filter4search,
      $filter_armor,
      $filter_meta,
      $filter_translitall,
      $ldap,
      $p,
      $return,
      $scope,
      $search,
      $search_arg,
      $sizelimit,
      $sort_order,
     );

  my $v = $self->validation;
  return $self->render(template => 'protected/search/common' =>
		       search_arg => {} => searchres => {}) unless $v->has_data;

  $p = $self->req->params->to_hash;
  $self->log->debug($self->dumper($p));
  $sort_order = 'reverse';
  $filter_armor = '';

  if ( $p->{'search_global'} ) {
    $base = $self->{app}->{cfg}->{ldap}->{cfg}->{base}->{dc};
  } elsif ( $p->{'search_by_name'}  //
	    $p->{'search_by_email'} //
	    $p->{'search_by_jid'}   //
	    $p->{'search_by_telephone'} ) {
    $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
  } elsif ( defined $p->{'ldap_subtree'} && $p->{'ldap_subtree'} ne '' ) {
    $base = $p->{'ldap_subtree'};
    $sizelimit = 0;
  } else {
    $base = $p->{search_base};
  }

  if ( defined $p->{'search_filter'} &&
       $p->{'search_filter'} eq '' ) {
    $filter_meta = '*';
  } else {
    $filter_meta = $p->{'search_filter'};
  }

  if ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_email' ) {
    $filter = sprintf("|(mail=%s)(&(uid=%s)(authorizedService=mail@*))",
		      $filter_meta, $filter_meta );
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $p->{'search_base'} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_jid' ) {
    $filter = sprintf("&(authorizedService=xmpp@*)(uid=*%s*)", $filter_meta);
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $p->{'search_base'} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_ip' ) {
    my @narr = split(/\./, $filter_meta);
    pop @narr if scalar @narr == 4;
    $filter = sprintf("|(dhcpStatements=fixed-address %s)(umiOvpnCfgIfconfigPush=%s*)(umiOvpnCfgIroute=%s.*)(ipHostNumber=%s*)",
		      $filter_meta, $filter_meta, join('.', @narr), $filter_meta);
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{dc};
    $p->{'search_base'} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_pgp' ) {
    $filter = sprintf("|(pgpCertID=%s)(pgpKeyID=%s)(pgpUserID=%s)",
		      $filter_meta, $filter_meta, $filter_meta);
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{pgp};
    $p->{'search_base'} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_mac' ) {
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
    $p->{'search_base'} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_name' ) {
    $p->{'search_base'} = $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $filter = sprintf("|(givenName=%s)(sn=%s)(uid=%s)(cn=%s)",
		      $filter_meta, $filter_meta, $filter_meta, $filter_meta);
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_telephone' ) {
    $p->{'search_base'} = $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $filter = sprintf("|(telephoneNumber=%s)(mobile=%s)(homePhone=%s)",
		      $filter_meta, $filter_meta, $filter_meta);
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_base' &&
	    $p->{'search_base'} eq $self->{app}->{cfg}->{ldap}->{base}->{org} ) {
    # SPECIAL CASE: we wanna each user (except admins) be able to see only org/s he belongs to
    $filter = $p->{'search_filter'} ne '' ? $p->{'search_filter'} : 'objectClass=*';
    $base   = $p->{'search_base'};
    ##$filter_armor = join('', @{[ map { '(associatedDomain=' . $_ . ')' } @{$c_user_d->{success}} ]} ) if ! $ldap_crud->role_admin;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq '' &&
	    $p->{'search_filter'} ne '' ) {
    $filter = $p->{'search_filter'};
    $base   = $p->{'search_base'};
  } elsif ( defined $p->{'ldap_subtree'} &&
	    $p->{'ldap_subtree'} ne '' ) {
    $filter = 'objectClass=*';
    $base   = $p->{'ldap_subtree'};
  } elsif ( defined $p->{'ldap_history'} &&
	    $p->{'ldap_history'} ne '' ) {
    $filter     = 'reqDN=' . $p->{'ldap_history'};
    $sort_order = 'straight';
    $base       = UMI->config->{ldap_crud_db_log};
  } else {
    $filter = 'objectClass=*';
    $base   = $p->{'search_base'};
  }

  $scope = $p->{search_scope} // 'sub';

  $filter4search = $filter_armor eq '' ? sprintf("(%s)", $filter ) : sprintf("&(%s)(|%s)",
									     $filter,
									     $filter_armor );

  $p->{'filter'} = '(' . $filter . ')';

  $self->log->debug('SEARCH RESULT');
  $ldap = Umi::Ldap->new( $self->{app},
			  $self->session('uid'),
			  $self->session('pwd') );

  $search_arg = { base => $base,
		  filter => $filter4search,
		  scope => 'sub' };
  $search = $ldap->search( $search_arg );
  if ( $search->code ) {
    $self->log->error(
		      sprintf("ProtectedSearch.pm: profile(): code: %s; message: %s; text: %s",
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
    
  $self->stash(search_common_params => $p => search_arg => $search_arg);
  $self->render(template => 'protected/search/common' => searchres => $search->as_struct);

}

1;
