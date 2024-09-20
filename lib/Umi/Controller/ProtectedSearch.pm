# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Controller::Search;

use Mojo::Base 'Umi::Controller', -signatures;
use Mojo::Util qw(b64_encode dumper);

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

  $self->{app}->h_log($self->req->params->pairs);
  $self->{app}->h_log($self->req->params->to_hash);
  $p = $self->req->params->to_hash;
  $sort_order = 'reverse';
  $filter_armor = '';

  if ( defined $p->{ldap_base_case} &&
       ( $p->{ldap_base_case} eq 'search_by_name'  ||
	 $p->{ldap_base_case} eq 'search_by_email' ||
	 $p->{ldap_base_case} eq 'search_by_jid'   ||
	 $p->{ldap_base_case} eq 'search_by_telephone' )) {
    $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
  } elsif ( defined $p->{'ldap_subtree'} && $p->{'ldap_subtree'} ne '' ) {
    $base = $p->{'ldap_subtree'};
    $sizelimit = 0;
  } else {
    $base = $p->{ldap_base_case};
  }

  $filter_meta = defined $p->{search_filter} && $p->{search_filter} eq '' ?
    '*' : $p->{search_filter};

  if ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_global' ) {
    $base = $self->{app}->{cfg}->{ldap}->{base}->{dc};
    $filter = $filter_meta;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_email' ) {
    $filter = sprintf("|(mail=%s)(&(uid=%s)(authorizedService=mail@*))",
		      $filter_meta, $filter_meta );
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $p->{ldap_base_case} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_jid' ) {
    $filter = sprintf("&(authorizedService=xmpp@*)(uid=*%s*)", $filter_meta);
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $p->{ldap_base_case} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_ip' ) {
    my @narr = split(/\./, $filter_meta);
    pop @narr if scalar @narr == 4;
    $filter = sprintf("|(dhcpStatements=fixed-address %s)(umiOvpnCfgIfconfigPush=%s*)(umiOvpnCfgIroute=%s.*)(ipHostNumber=%s*)",
		      $filter_meta, $filter_meta, join('.', @narr), $filter_meta);
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{dc};
    $p->{ldap_base_case} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_pgp' ) {
    $filter = sprintf("|(pgpCertID=%s)(pgpKeyID=%s)(pgpUserID=%s)",
		      $filter_meta, $filter_meta, $filter_meta);
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{pgp};
    $p->{ldap_base_case} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_mac' ) {
    my $mac = $self->macnorm({ mac => $filter_meta });
    push @{$return->{error}}, 'incorrect MAC address'
      if ! $mac;
    $filter = sprintf("|(dhcpHWAddress=ethernet %s)(&(uid=%s)(authorizedService=dot1x*))(&(cn=%s)(authorizedService=dot1x*))(hwMac=%s)",
		      $self->macnorm({ mac => $filter_meta, dlm => ':', }),
		      $self->macnorm({ mac => $filter_meta }),
		      $self->macnorm({ mac => $filter_meta }),
		      $self->macnorm({ mac => $filter_meta }) );

    $base   = $self->{app}->{cfg}->{ldap}->{base}->{dc};
    $p->{ldap_base_case} = $base;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_name' ) {
    $p->{ldap_base_case} = $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $filter = sprintf("|(givenName=%s)(sn=%s)(uid=%s)(cn=%s)",
		      $filter_meta, $filter_meta, $filter_meta, $filter_meta);
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_by_telephone' ) {
    $p->{ldap_base_case} = $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $filter = sprintf("|(telephoneNumber=%s)(mobile=%s)(homePhone=%s)",
		      $filter_meta, $filter_meta, $filter_meta);
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq 'search_base' &&
	    $p->{ldap_base_case} eq $self->{app}->{cfg}->{ldap}->{base}->{org} ) {
    # SPECIAL CASE: we wanna each user (except admins) be able to see only org/s he belongs to
    $filter = $p->{'search_filter'} ne '' ? $p->{'search_filter'} : 'objectClass=*';
    $base   = $p->{ldap_base_case};
    ##$filter_armor = join('', @{[ map { '(associatedDomain=' . $_ . ')' } @{$c_user_d->{success}} ]} ) if ! $ldap_crud->role_admin;
  } elsif ( defined $p->{ldap_base_case} && $p->{ldap_base_case} eq '' &&
	    $p->{'search_filter'} ne '' ) {
    $filter = $p->{'search_filter'};
    $base   = $p->{ldap_base_case};
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
    $base   = $p->{ldap_base_case};
  }
  $self->{app}->h_log(sprintf("base: %s; filter_meta: %s; filter: %s",
			      $base, $filter_meta || 'NA (ldap_subtree called)', $filter));

  $scope = $p->{search_scope} // 'sub';

  $filter4search = $filter_armor eq '' ? sprintf("(%s)", $filter ) : sprintf("&(%s)(|%s)",
									     $filter,
									     $filter_armor );

  $p->{'filter'} = '(' . $filter . ')';

  $self->{app}->h_log('SEARCH RESULT');
  $ldap = Umi::Ldap->new( $self->{app},
			  $self->session('uid'),
			  $self->session('pwd') );

  $search_arg = { base => $base,
		  filter => $filter4search,
		  scope => 'sub' };
  $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  # $self->{app}->h_log($search);

  # my $s;
  # foreach ($search->entries) {
  # 	$s .= $_->ldif;
  # }

  $self->stash(search_common_params => $p => search_arg => $search_arg);
  $self->render(template => 'protected/search/common' => searchres => $search->as_struct);

}

sub search_projects  ($self) {
  my $ldap = Umi::Ldap->new( $self->{app},
			     $self->session('uid'),
			     $self->session('pwd') );
  # $self->h_log($ldap);
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{project},
		     filter => '(cn=*)',
		     scope => 'one',
		     attrs => ['cn'] };
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  my @project_names;
  push @project_names, $_->get_value('cn') foreach ($search->entries());
  my $entries;
  foreach my $proj (@project_names) {
    ### PROJECT
    $search_arg = { base => sprintf("cn=%s,%s", $proj,
				    $self->{app}->{cfg}->{ldap}->{base}->{project}) };
    # $self->h_log($search_arg);
    $search = $ldap->search( $search_arg );
    $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
    $entries->{$proj} = $search->as_struct;

    ### GROUPS
    $search_arg = { base => sprintf("ou=group,%s", $self->{app}->{cfg}->{ldap}->{base}->{project}),
		    filter => sprintf("(cn=%s*)", $proj),
		    attrs => ['*'], };
    # $self->h_log($search_arg);
    $search = $ldap->search( $search_arg );
    $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
    $entries->{$proj}->{group} = $search->as_struct;

    ### TEAM
    $entries->{$proj}->{team} = {};
    my @groups = $search->entries;
    foreach my $gr (@groups) {
      foreach (@{$gr->get_value('memberUid', asref => 1)}) {
	$search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
			filter => sprintf("(uid=%s)", $_),
			scope => 'one',
			attrs => [qw(uid cn gecos givenName sn telephoneNumber mobile mail jpegPhoto)],
		      };

	$search = $ldap->search( $search_arg );
	$self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

	# $self->h_log($search->as_struct);
	%{$entries->{$proj}->{team}} = (%{$entries->{$proj}->{team}}, %{$search->as_struct});
      }
    }

    ### MACHINES
    $entries->{$proj}->{machines} = {};
    foreach (sort(@{
      $entries->{$proj}->
		  {sprintf("cn=%s,%s",$proj,$self->{app}->{cfg}->{ldap}->{base}->{project})}->
		  {associateddomain}
		})) {
      $self->h_log($_);
      $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{machines},
		      filter => sprintf("(cn=*%s)", $_),
		      attrs => ['*'], };
      # $self->h_log($search_arg);
      $search = $ldap->search( $search_arg );
      $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
      %{$entries->{$proj}->{machines}} = (%{$entries->{$proj}->{machines}}, %{$search->as_struct});
    }
  }

  $self->h_log($entries);

  $self->render(
		template => 'protected/search/projects',
		entries => $entries,
		base_proj => $self->{app}->{cfg}->{ldap}->{base}->{project},
		base_acc => $self->{app}->{cfg}->{ldap}->{base}->{acc_root}
	       );
  
}

1;