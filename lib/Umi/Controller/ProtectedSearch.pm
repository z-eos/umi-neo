# -*- mode: cperl; eval: (follow-mode 1); -*-

package Umi::Controller::Search;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojo::Util qw(b64_encode dumper);

use Umi::Ldap;
use Umi::Helpers::SearchResult;

use Encode qw(decode_utf8);

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
  return $self->render( template => 'protected/search/common',
			search_arg => {},
			searchres => {},
			entries => [] ) unless $v->has_data;

  if ($self->session('debug')) {
    $self->stash( debug => $self->session('debug') );
    $self->h_log($self->session('debug'));
    delete $self->session->{debug};
  }

  # $self->h_log($self->req->params->pairs);
  $p = $self->req->params->to_hash;
  $self->h_log($p);
  $p->{params_orig} = $self->req->params->to_hash;
  $sort_order = 'reverse';
  $filter_armor = '';

  if ( defined $p->{search_base_case} &&
       ( $p->{search_base_case} eq 'search_by_name'  ||
	 $p->{search_base_case} eq 'search_by_email' ||
	 $p->{search_base_case} eq 'search_by_jid'   ||
	 $p->{search_base_case} eq 'search_by_telephone' )) {
    $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
  } elsif ( defined $p->{'ldap_subtree'} && $p->{'ldap_subtree'} ne '' ) {
    $base = $p->{'ldap_subtree'};
    $sizelimit = 0;
  } else {
    $base = $p->{search_base_case};
  }

  $filter_meta = defined $p->{search_filter} && $p->{search_filter} eq '' ?
    '*' : $p->{search_filter};

  if ( defined $p->{search_base_case} && $p->{search_base_case} eq 'search_global' ) {
    $base = $self->{app}->{cfg}->{ldap}->{base}->{dc};
    $filter = $filter_meta;
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} eq 'search_by_email' ) {
    $filter = sprintf("|(mail=%s)(&(uid=%s)(authorizedService=mail@*))",
		      $filter_meta, $filter_meta );
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $p->{search_base_case} = $base;
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} eq 'search_by_jid' ) {
    $filter = sprintf("&(authorizedService=xmpp@*)(uid=*%s*)", $filter_meta);
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $p->{search_base_case} = $base;
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} eq 'search_by_ip' ) {
    my @narr = split(/\./, $filter_meta);
    pop @narr if scalar @narr == 4;
    $filter = sprintf("|(dhcpStatements=fixed-address %s)(umiOvpnCfgIfconfigPush=%s*)(umiOvpnCfgIroute=%s.*)(ipHostNumber=%s*)",
		      $filter_meta, $filter_meta, join('.', @narr), $filter_meta);
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{dc};
    $p->{search_base_case} = $base;
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} eq 'search_by_pgp' ) {
    $filter = sprintf("|(pgpCertID=%s)(pgpKeyID=%s)(pgpUserID=%s)",
		      $filter_meta, $filter_meta, $filter_meta);
    $base   = $self->{app}->{cfg}->{ldap}->{base}->{pgp};
    $p->{search_base_case} = $base;
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} eq 'search_by_mac' ) {
    my $mac = $self->macnorm({ mac => $filter_meta });
    push @{$return->{error}}, 'incorrect MAC address'
      if ! $mac;
    $filter = sprintf("|(dhcpHWAddress=ethernet %s)(&(uid=%s)(authorizedService=dot1x*))(&(cn=%s)(authorizedService=dot1x*))(hwMac=%s)",
		      $self->macnorm({ mac => $filter_meta, dlm => ':', }),
		      $self->macnorm({ mac => $filter_meta }),
		      $self->macnorm({ mac => $filter_meta }),
		      $self->macnorm({ mac => $filter_meta }) );

    $base   = $self->{app}->{cfg}->{ldap}->{base}->{dc};
    $p->{search_base_case} = $base;
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} eq 'search_by_name' ) {
    $p->{search_base_case} = $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $filter = sprintf("|(givenName=%s)(sn=%s)(uid=%s)(cn=%s)",
		      $filter_meta, $filter_meta, $filter_meta, $filter_meta);
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} eq 'search_by_telephone' ) {
    $p->{search_base_case} = $base = $self->{app}->{cfg}->{ldap}->{base}->{acc_root};
    $filter = sprintf("|(telephoneNumber=%s)(mobile=%s)(homePhone=%s)",
		      $filter_meta, $filter_meta, $filter_meta);
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} eq 'search_base' &&
	    $p->{search_base_case} eq $self->{app}->{cfg}->{ldap}->{base}->{org} ) {
    # SPECIAL CASE: we wanna each user (except admins) be able to see only org/s he belongs to
    $filter = $p->{'search_filter'} ne '' ? $p->{'search_filter'} : 'objectClass=*';
    $base   = $p->{search_base_case};
    ##$filter_armor = join('', @{[ map { '(associatedDomain=' . $_ . ')' } @{$c_user_d->{success}} ]} ) if ! $ldap_crud->role_admin;
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} eq '' &&
	    $p->{'search_filter'} ne '' ) {
    $filter = $p->{'search_filter'};
    $base   = $p->{search_base_case};
  } elsif ( defined $p->{'ldap_subtree'} &&
	    $p->{'ldap_subtree'} ne '' ) {
    $filter = 'objectClass=*';
    $base   = $p->{'ldap_subtree'};
  } elsif ( defined $p->{'dn_to_history'} &&
	    $p->{'dn_to_history'} ne '' ) {
    $filter     = 'reqDN=' . $p->{'dn_to_history'};
    $sort_order = 'straight';
    $base       = $self->{app}->{cfg}->{ldap}->{accesslog};
  } elsif ( defined $p->{search_base_case} && $p->{search_base_case} ne '' &&
	    $p->{'search_filter'} ne '' ) {
    $filter = $p->{'search_filter'};
    $base   = $p->{search_base_case};
  } else {
    $filter = 'objectClass=*';
    $base   = $p->{search_base_case};
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
  # my @dn_s = map { $_->dn } $search->sorted;
  # $self->{app}->h_log(\@dn_s);

  # hash to keep aux data like disabled state of the root object for branch/leaf
  my $e_info;
  foreach ($search->entries) {
    $e_info->{$_->dn}->{root_dn} = $self->h_get_root_dn($_->dn) if ! exists $e_info->{$_->dn}->{root_dn};
    $e_info->{$_->dn}->{disabled} = 0;
    if ( $e_info->{$_->dn}->{root_dn} eq $_->dn ) {
      $e_info->{$_->dn}->{disabled} = 1 if $_->get_value('gidNumber') eq $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber};
    } else {
      my $e_tmp = $ldap->search( { base => $e_info->{$_->dn}->{root_dn}, scope => 'base' } );
      $e_info->{$_->dn}->{disabled} = 1 if $e_tmp->entry->get_value('gidNumber') eq $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber};
    }
  }
  # $self->h_log($search->as_struct);

  my @entries = $search->sorted;
  $self->stash(search_common_params => $p, search_arg => $search_arg, e_info => $e_info);
  if ( exists $p->{no_layout} ) {
    $self->render( template => 'protected/search/common',
		   layout => undef,
		   entries => [ $search->sorted ] );
  } else {
    $self->render( template => 'protected/search/common',
		   entries => [ $search->sorted ]);
  }
}

sub search_projects  ($self) {
  my $par = $self->req->params->to_hash;

  my $ldap = Umi::Ldap->new( $self->{app},
			     $self->session('uid'),
			     $self->session('pwd') );

  my $proj = $par->{proj} // $self->stash->{proj};
  $proj = '*' if $proj eq 'all';

  # $self->h_log($proj);
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{project},
		     filter => sprintf("(cn=%s)", $proj),
		     scope => 'one',
		     attrs => [qw(cn createTimestamp creatorsName modifiersName modifyTimestamp)] };
  my $search = $ldap->search( $search_arg );
  # $self->h_log( $search );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  my @project_names;
  push @project_names, $_->get_value('cn') foreach ($search->entries());
  my $entries;
  foreach my $p (@project_names) {
    ### PROJECT
    $search_arg = { base => sprintf("cn=%s,%s", $p,
				    $self->{app}->{cfg}->{ldap}->{base}->{project}) };
    # $self->h_log($search_arg);
    $search = $ldap->search( $search_arg );
    $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
    $entries->{$p} = $search->as_struct;

    ### GROUPS
    $search_arg = { base => sprintf("ou=group,%s", $self->{app}->{cfg}->{ldap}->{base}->{project}),
		    filter => sprintf("(cn=%s*)", $p),
		    attrs => ['*'], };
    # $self->h_log($search_arg);
    $search = $ldap->search( $search_arg );
    $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
    $entries->{$p}->{group} = $search->as_struct;
    # $self->h_log($entries->{$p}->{group});
    
    ### TEAM
    $entries->{$p}->{team} = {};
    my @groups = $search->entries;
    foreach my $gr (@groups) {
      foreach my $mu (@{$gr->get_value('memberUid', asref => 1)}) {
	$search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
			filter => sprintf("(uid=%s)", $mu),
			scope => 'one',
			attrs => [qw(uid cn gecos givenName sn telephoneNumber mobile mail jpegPhoto)],
		      };

	$search = $ldap->search( $search_arg );
	$self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

	# $self->h_log($search->as_struct);
	%{$entries->{$p}->{team}} = (%{$entries->{$p}->{team}}, %{$search->as_struct});
      }
    }

    ### MACHINES
    if ( $self->is_role('admin') or  $self->is_role('coadmin') ) {
      $entries->{$p}->{machines} = {};
      if ( exists $entries->{$p}->
	   {sprintf("cn=%s,%s",$p,$self->{app}->{cfg}->{ldap}->{base}->{project})}->
	   {associateddomain}
	 ) {
	foreach (sort(@{
	  $entries->{$p}->
	    {sprintf("cn=%s,%s",$p,$self->{app}->{cfg}->{ldap}->{base}->{project})}->
	    {associateddomain}
	  })) {
	  # $self->h_log($_);
	  $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{machines},
			  filter => sprintf("(cn=*%s)", $_),
			  attrs => ['*'], };
	  # $self->h_log($search_arg);
	  $search = $ldap->search( $search_arg );
	  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
	  %{$entries->{$p}->{machines}} = (%{$entries->{$p}->{machines}}, %{$search->as_struct});
	}
      } else {
	$entries->{$p}->{machines} = {};
      }
    }
  }

  # $self->h_log($entries);

  $self->stash( entries => $entries,
		base_proj => $self->{app}->{cfg}->{ldap}->{base}->{project},
		base_acc => $self->{app}->{cfg}->{ldap}->{base}->{acc_root} );
  $self->render( template => 'protected/search/projects' );

}

1;
