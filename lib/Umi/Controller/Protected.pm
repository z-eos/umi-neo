# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Controller::Protected;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojo::Util qw(b64_encode dumper);
use Mojo::JSON qw(decode_json encode_json to_json);

use Mojolicious::Validator;

use Umi::Ldap;

sub homepage ($self) {
  if ($self->session('debug')) {
    $self->stash( debug => $self->session('debug') );
    delete $self->session->{debug};
  }
  $self->render( template => 'protected/home' );
}

sub other ($self) { $self->render(template => 'protected/other'); }

sub delete ($self) {
  my $par = $self->req->params->to_hash;
  $self->h_log($par);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my $msg = $ldap->delete($par->{delete_dn},
			  exists $par->{delete_recursive} && $par->{delete_recursive} eq 'on' ? 1 : 0);
  $self->session( debug => $msg );

  ### alas, this redirect by nature performs a GET request
  return $self
    ->redirect_to($self->url_for('search_common')
		  ->query( search_base_case => $par->{search_base_case},
			   search_filter => $par->{search_filter},
			   ldap_subtree => $par->{ldap_subtree} )
		 );
}

sub profile ($self) {
  my $par = $self->req->params->to_hash;
  my $reqpath = $self->req->url->to_abs->path;
  my $uid;
  if ( $reqpath =~ /^\/audit\/.*$/ ) {
    $uid = 'all';
  } else {
    $uid = $par->{uid} // $self->stash->{uid} // '';
  }

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  ### USER:
  my $filter;
  if ($uid eq 'all') {
    $filter = '(uid=*)';
  } elsif ($uid eq 'disabled') {
    $filter = sprintf("(&(uid=*)(gidNumber=%s))",
		      $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber});
  } elsif ($uid eq 'active') {
    $filter = sprintf("(&(uid=*)(!(gidNumber=%s)))",
		      $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber});
  } elsif ($uid ne '') {
    $filter = sprintf("(|(uid=%s)(givenName=%s)(sn=%s))", $uid, $uid, $uid);
  } else {
    $filter = sprintf("(uid=%s)", $self->session('uid'));
  }
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     filter => $filter,
		     scope => 'one' };
  $search_arg->{attrs} = [qw( gidNumber givenName mail sn uid modifiersName )] if $reqpath =~ /^\/audit\/.*$/;
  # $self->{app}->h_log( $search_arg);
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  my $profiled_user = $search->as_struct;
  # $self->h_log($profiled_user);

  my ( $cf_svc, $groups, $k, $kk, $modifiersname, $p, $pgp, $pgp_e, $projects, $server_names, $server_alive, $servers, $service, $svc, $svc_details, $svc_msg, $v, $vv, );
  while (($k, $v) = each %$profiled_user) {
    ### name of the last who modified this user root object
    $search_arg = { base => $v->{modifiersname}->[0], scope => 'base', attrs => ['gecos', 'uid'] };
    $search = $ldap->search( $search_arg );
    $modifiersname->{$k} = $search->as_struct->{$v->{modifiersname}->[0]};

    ### only admins and coadmins need this info
    if ( $self->is_role('admin,coadmin', {cmp => 'or'}) || $reqpath eq '/audit/users') {
      ### GROUPS: list of all groups user is a member of
      $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{group},
		      filter => '(memberUid=' . $v->{uid}->[0] . ')',
		      attrs => ['cn'] };
      $search = $ldap->search( $search_arg );
      my $g = $search->as_struct;
      push @{$groups->{$k}}, $vv->{cn}->[0] while (($kk, $vv) = each %$g);

      ### SERVERS: list of all servers available for the user
      $search_arg = { base => 'ou=access,' . $self->{app}->{cfg}->{ldap}->{base}->{netgroup},
		      filter => '(nisNetgroupTriple=*,' . $v->{uid}->[0] . ',*)',
		      attrs => ['nisNetgroupTriple'] };
      $search = $ldap->search( $search_arg );
      $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
      my $netgroups = $search->as_struct;
      my $tuple;
      while (my ($kk, $vv) = each %$netgroups) {
	foreach (@{$vv->{nisnetgrouptriple}}) {
	  @$tuple = split(/,/, substr($_, 1, -1));
	  push @{$server_names->{$k}}, sprintf("%s.%s", $tuple->[0], $tuple->[2]);
	}
      }
      @{$servers->{$k}} = do {
	my %seen;
	sort grep { !$seen{$_}++ } @{$server_names->{$k}};
      };
      foreach (@{$servers->{$k}}) {
	$search_arg = { base => 'cn=' . $_ . ',' . $self->{app}->{cfg}->{ldap}->{base}->{machines},
			attrs => ['cn'] };
	$search = $ldap->search( $search_arg );
	$self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;
	$server_alive->{$k}->{$_} = $search->count;
      }
      # $self->h_log($servers);
    }

    ### SERVICES
    $search_arg = { base => $k,
		    scope => 'one',
		    sizelimit => 0,
		    filter => 'authorizedService=*',
		    attrs => [ 'authorizedService'],};
    $search = $ldap->search( $search_arg );
    $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;

    foreach $svc (@{[$search->sorted( 'authorizedService' )]}) {
      $svc_msg = $ldap->search( { base => $svc->dn, scope => 'children', });
      $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;
      next if ! $svc_msg->count;

      $cf_svc = $self->{app}->{cfg}->{ldap}->{authorizedService}->{(split('@', $svc->get_value('authorizedService')))[0]};

      $svc_details = {
		      branch_dn => $svc->dn,
		      # authorizedService => $svc->get_value('authorizedService'),
		      auth => $cf_svc->{auth},
		      icon => $cf_svc->{icon},
		      descr => $cf_svc->{descr},
		     };

      foreach my $e (@{[$svc_msg->sorted( 'authorizedService' )]}) {
	# !!! WARNING may there be something except `cn` and `uid`?
	# $svc_details->{leaf}->{$e->dn} = $e->get_value('uid') // $e->get_value('cn');
	%{$svc_details->{obj}->{$e->dn}} =
	  map { $_ => $e->get_value($_, asref => 1) } $e->attributes;
      }
      $service->{$k}->{$svc->get_value('authorizedService')} = $svc_details;
      undef $svc_details;
    }
    # $self->h_log($service);

    ### GPG
    $filter = sprintf("(|(pgpUserID=*%s*)", $v->{sn}->[0]);
    $filter .= sprintf("(pgpUserID=*%s*)", $v->{mail}->[0]) if exists $v->{mail};
    $filter .= ')';
    $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{pgp}, filter => $filter };
    $search = $ldap->search( $search_arg );
    $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;
    $pgp_e = $search->as_struct;
    foreach (keys %$pgp_e) {
      $pgp->{$k}->{$pgp_e->{$_}->{pgpuserid}->[0]} =
	{
	 keyid  => $pgp_e->{$_}->{pgpkeyid}->[0],
	 key    => $pgp_e->{$_}->{pgpkey}->[0],
	};
    }
    #$self->h_log($pgp);

    ### PROJECTS: list of all projects user is a member of
    $search_arg = { base => 'ou=group,' . $self->{app}->{cfg}->{ldap}->{base}->{project},
		    filter => '(memberUid=' . $v->{uid}->[0] . ')',
		    attrs => ['cn'] };
    $search = $ldap->search( $search_arg );
    $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
    $p = $search->as_struct;
    @{$projects->{$k}} = sort map { $p->{$_}->{cn}->[0] =~ s/_/:/r } keys(%$p);
  }

  my $template = $reqpath =~ /^\/audit\/.*/ ? 'protected/audit/users' : 'protected/profile';
  # $self->h_log($template);
  $self->render(template => $template,
		hash => $profiled_user,
		groups => $groups,
		group_blocked_gidnumber => $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber},
		pgp => $pgp,
		servers => $servers,
		services => $service,
		server_alive => $server_alive,
		search_base_case => $self->{app}->{cfg}->{ldap}->{base}->{machines},
		projects => $projects,
		modifiersname => $modifiersname,
	       ); #layout => undef);
}

sub ldif_import ($self) { $self->render(template => 'protected/tool/ldif-import') } #, layout => undef) }

sub ldif_export    ($self) {
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/ldif-export') unless $v->has_data;

  my $ldap = Umi::Ldap->new( $self->{app},
			     $self->session('uid'),
			     $self->session('pwd') );

  my $par = $self->req->params->to_hash;
  $par->{dn} =~ s/ //g;
  my $search_arg = { base => substr($par->{dn}, index($par->{dn}, ",")+1),
		     filter => substr($par->{dn}, 0, index($par->{dn}, ",")),
		     scope => $par->{scope} };
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  my $ldif;
  foreach ($search->entries) {
    $ldif .= $_->ldif;
  }

  $self->stash(ldif_export_params => $par => ldif => $ldif);
  return $self->render(template => 'protected/tool/ldif-export'); #, layout => undef);
}

sub sysinfo    ($self) {
  my $ldap = Umi::Ldap->new( $self->{app},
			     $self->session('uid'),
			     $self->session('pwd') );

  my $schema = $ldap->schema;
  my %oc = map { $_->{name} => $_ } $schema->all_objectclasses;
  my %aa = map { $_->{name} => $_ } $schema->all_attributes;
  my %as = map { $_->{name} => $_ } $schema->all_syntaxes;
  my %s;
  $s{all_objectclasses} = \%oc;
  $s{all_attributes} = \%aa;
  $s{all_syntaxes} = \%as;
  return $self->render( template => 'protected/tool/sysinfo',
		        schema => encode_json(\%s),
			); # layout => undef);
}

sub pwdgen ($self) {
  my $par = $self->req->params->to_hash;
  $self->h_log($par);

  ### call from another place (first run)
  if (exists $par->{pwd_vrf} && $par->{pwd_vrf} ne '' && ! exists $self->session->{pw}->{vrf}) {
    $self->stash({ pwd_vrf => $par->{pwd_vrf} });
    $self->session({ pw => { vrf => $par->{pwd_vrf} } });
    # delete $par->{pwd_vrf};
  }
  if (exists $par->{pwd_chg_dn} && $par->{pwd_chg_dn} ne '' && ! exists $self->session->{pw}->{chg}) {
    $self->stash({ pwd_chg_dn  => $par->{pwd_chg_dn},
		   pwd_chg_rdn => $par->{pwd_chg_rdn},
		   pwd_chg_svc => $par->{pwd_chg_svc} });
    $self->session({ pw => { chg => { dn  => $par->{pwd_chg_dn},
				      svc => $par->{pwd_chg_svc},
				      rdn => $par->{pwd_chg_rdn} } } });
    $self->req->params->remove;
    delete $par->{pwd_chg_dn};
    delete $par->{pwd_chg_rdn};
    delete $par->{pwd_chg_svc};
  }
  # $self->h_log($self->session->{pwd_chg});
  # $self->h_log($par);

  return $self->render( template => 'protected/tool/pwdgen' ) unless exists $par->{pwd_alg} || exists $par->{pwd_vrf};

  #   # $v->has_data;
  my $v = $self->validation;
  $v->required('pwd_alg');
  # # $self->h_log($v->error('proj_name'));
  # # $v->error(team_pm => ['Select at least one person.']) if ! exists $par->{team_pm};

  # if (exists $par->{pwd_chg_dn} && $par->{pwd_chg_dn} eq '' && exists $self->session->{pwd_chg}) {
  if ( exists $self->session->{pw}->{vrf} ) {
    $self->stash({ pwd_vrf => $self->session->{pw}->{vrf} });
    $par->{pwd_vrf} = $self->session->{pw}->{vrf};
    delete $self->session->{pw}->{vrf};
  }
  if ( exists $self->session->{pw}->{chg} ) {
    $self->h_log($self->session->{pw}->{chg});
    $self->stash({ pwd_chg_dn  => $self->session->{pw}->{chg}->{dn},
		   pwd_chg_rdn => $self->session->{pw}->{chg}->{rdn},
		   pwd_chg_svc => $self->session->{pw}->{chg}->{svc} });
    delete $self->session->{pw}->{chg};
  }

  my $pwdgen = $self->h_pwdgen($par);
  # $self->h_log($pwdgen);

  my ($ldap, $search, $search_arg, $pwd_from_ldap, $match, $mesg);
  if (exists $self->stash->{pwd_chg_dn}) {
    $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
    if (exists $self->stash->{pwd_vrf}) {
      ### password verification against LDAP
      $search_arg = { base => $self->stash->{pwd_chg_dn}, attrs => ['userPassword'] };
      $search = $ldap->search( $search_arg );
      $pwd_from_ldap = $search->entry->get_value('userPassword');
      $self->h_log($pwd_from_ldap);
      $match = $pwd_from_ldap eq $pwdgen->{ssha} ? 1 : 0;
      $self->stash({debug => { $match ? 'ok' : 'warn' => [ 'password: ' . $pwdgen->{clear}, $match ? 'match' : 'does not match' ]}});
    } else {
      ### userPassword attribute modification
      $mesg = $ldap->modify( $self->stash->{pwd_chg_dn}, [ replace => [ 'userPassword' => $pwdgen->{ssha}, ], ] );
      $self->h_log($mesg );
      # $self->h_log( $self->{app}->h_ldap_err($mesg, undef) ) if $mesg->code;
      $self->stash({debug => { $mesg->{status} => [ $mesg->{message},
						    'new password: <span class="badge text-bg-secondary user-select-all">' .
						    $pwdgen->{clear} .
						    '</span>' ]
			     }});
    }
  } else {
    $self->stash({debug => { $pwdgen->{stats}->{passwords_generated} > 0
			     ? 'ok' : 'warn' => [ 'new password: <span class="badge text-bg-secondary user-select-all">' .
						  $pwdgen->{clear} .
						  '</span>' ]
			   }});
  }


  return $self->render(template => 'protected/tool/pwdgen',
		       pwdgen_params => $par,
		       pwdgen => $pwdgen,
		       ); # layout => undef);
}

sub qrcode ($self) {
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/qrcode') unless $v->has_data;

  my $par = $self->req->params->to_hash;
  $self->stash(qrcode_params => $par);
  return $self->render(template => 'protected/tool/qrcode' => qrcode => $self->h_qrcode($par)); # , layout => undef);
}

sub keygen_ssh ($self) {
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/keygen/ssh') unless $v->has_data;

  my $par = $self->req->params->to_hash;
  $self->stash(kg_ssh_params => $par);
  return $self->render(template => 'protected/tool/keygen/ssh',
		       key => {
			       ssh => $self->h_keygen_ssh($par),
			       name => { real => 'name will be here',
					 email => 'email will be here' }
			      },
		       # layout => undef
		      );
}

sub keygen_gpg ($self) {
  my $par = $self->req->params->to_hash;
  $self->h_log($par);
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/keygen/gpg') unless $v->has_data;

  $par->{name} = {
		  real => sprintf("%s %s", $self->session->{user_obj}->{givenname}, $self->session->{user_obj}->{sn}),
		  email => $self->session->{user_obj}->{mail}
		 };
  my $k = $self->h_keygen_gpg($par);
  # $self->h_log($k);

  return $self->render(template => 'protected/tool/keygen/gpg',
		       key => $k,
		       # layout => undef
		      );
}

=head1 modify

method to modify whole oject or some definite attribute (if parameter
attr_to_modify exists)

=cut

sub modify ($self) {
  my $par = $self->req->params->to_hash;
  my $uploads = $self->req->uploads;
  # $self->h_log($uploads);
  if ( @$uploads ) {
    foreach ( @$uploads ) {
      # $self->h_log($_);
      my $n = $_->name;
      $n =~ s/_binary/;binary/;
      $par->{$n} = $_->slurp;

      if ( $n eq 'userCertificate;binary' ) {
	my $crt = $self->h_cert_info({ cert => $par->{$n}, ts => "%Y%m%d%H%M%S", });
        $par->{umiUserCertificateSn}        = '' . $crt->{'S/N'},
	$par->{umiUserCertificateNotBefore} = '' . $crt->{'Not Before'},
	$par->{umiUserCertificateNotAfter}  = '' . $crt->{'Not  After'},
	$par->{umiUserCertificateSubject}   = '' . $crt->{'Subject'},
	$par->{umiUserCertificateIssuer}    = '' . $crt->{'Issuer'};
      }
    }
  }

  my $attr_to_add = exists $par->{attr_to_add} && $par->{attr_to_add} ne '' ? $par->{attr_to_add} : undef;
  my $dn_to_modify = $par->{dn_to_modify};
  my $attr_to_ignore;
  my $rdn = $self->h_get_rdn($dn_to_modify);
  %{$attr_to_ignore} = map {$_ => 1}
    @{[qw(dn_to_modify attr_to_add attr_unused modifyTimestamp modifiersName creatorsName createTimestamp)]};
  $attr_to_ignore->{$rdn} = 1;

  my $v = $self->validation;
  return $self->render(template => 'protected/tool/modify') unless $v->has_data;
  # return $self->render(template => 'protected/tool/modify') unless %$par;

  # $self->h_log($par);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my $search_arg = { base => $par->{dn_to_modify},
		     filter => '(objectClass=*)',
		     scope => 'base' };
  $search_arg->{attrs} = defined $attr_to_add ? [$attr_to_add] : [];
  $self->h_log( $search_arg );
  my $s = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($s, $search_arg) ) if $s->code;
  # $self->h_log( $s->as_struct );

  my ($e_orig, $e_tmp);
  foreach ($s->entry->attributes) {
    next if $_ eq $rdn;
    $e_tmp = $s->entry->get_value($_, asref => 1);
    if ( scalar @$e_tmp == 1 ) {
      $e_orig->{$_} = $e_tmp->[0];
    } else {
      $e_orig->{$_} = $e_tmp;
    }
  }

  # `UNUSED ATTRIBUTES` select element
  my ($schema, %oc, %aa, %as, @attr_unused);
  if ( ! defined $attr_to_add ) {
    $schema = $ldap->schema;
    %oc = map { $_->{name} => $_ } $schema->all_objectclasses;
    %aa = map { $_->{name} => $_ } $schema->all_attributes;
    %as = map { $_->{name} => $_ } $schema->all_syntaxes;
    @attr_unused = $self->h_attr_unused($s->entry, \%oc);
  }
  # NEED to re-check what it is for :(
  $self->stash({ attr_to_add => $par->{attr_to_add} })
    if defined $attr_to_add;

  if ( keys %$par < 3 ) {
    # here we've just clicked, search result  menu `modify` button
    $self->h_log('~~~~~-> MODIFY [' . $self->req->method . ']: FIRST RUN (search result menu choosen)');
    delete $self->session->{e_orig};
    $self->session->{e_orig} = $e_orig;
  } elsif (exists $par->{add_objectClass}) {
    # new objectClass addition is chosen
    $self->h_log('~~~~~-> MODIFY [' . $self->req->method . ']: ADD OBJECTCLASS');
    # $self->h_log($par);
    # $s = $ldap->search( $search_arg );
    # $self->h_log(sprintf("Protected.pm: modify(): code: %s; message: %s; text: %s",
    # 			      $s->code, $s->error_name, $s->error_text )) if $s->code;
  } else {
    # form modification made
    $self->h_log('~~~~~-> MODIFY [' . $self->req->method . ']: FORM CHANGED?');
    delete $par->{$_} foreach (keys %{$attr_to_ignore});
    foreach (keys %$par) {
      delete $par->{$_} if $par->{$_} eq '';
    }

    # $self->h_log($par);
    # $self->h_log($self->session->{e_orig});

    my $diff = $self->h_hash_diff( $e_orig, $par);
    #$self->h_log($diff);
    my ($add, $delete, $replace, $changes);
    if ( %{$diff->{added}} ) {
      push @$add, $_ => $diff->{added}->{$_} foreach (keys(%{$diff->{added}}));
      push @$changes, add => $add;
    }
    if ( %{$diff->{removed}} ) {
      push @$delete, $_ => [] foreach (keys(%{$diff->{removed}}));
      push @$changes, delete => $delete;
    }
    if ( %{$diff->{changed}} ) {
      push @$replace, $_ => $diff->{changed}->{$_}->{new} foreach (keys(%{$diff->{changed}}));
      push @$changes, replace => $replace;
    }

    if ($changes) {
      $self->h_log($changes);
      my $msg = $ldap->modify($s->entry->dn, $changes);
      $self->stash(debug => {$msg->{status} => [ $msg->{message} ]});
    }
  }

  $search_arg->{base} = $dn_to_modify;
  #$self->h_log( $search_arg );
  $s = $ldap->search( $search_arg );
  #$self->h_log( $s->as_struct );
  foreach ($s->entry->attributes) {
    $e_tmp = $s->entry->get_value($_, asref => 1);
    if ( scalar @$e_tmp == 1 ) {
      $e_orig->{$_} = $e_tmp->[0];
    } else {
      $e_orig->{$_} = $e_tmp;
    }
  }
  $self->session->{e_orig} = $e_orig;
  $self->{app}->h_log( $self->{app}->h_ldap_err($s, $search_arg) ) if $s->code;
  @attr_unused = $self->h_attr_unused($s->entry, \%oc) if ! defined $attr_to_add;

  $self->stash(entry => $s->entry,
	       aa => \%aa, as => \%as, oc => \%oc,
	       attr_unused => \@attr_unused,
	       attr_to_add => $attr_to_add,
	       attr_to_ignore => $attr_to_ignore,
	       #dn_to_modify => $attr_to_add
	      );

  return $self->render(template => 'protected/tool/modify'); #, layout => undef);
}

sub project_new ($self) {
  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     filter => "(&(uid=*)(!(gidNumber=" . $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber} . ")))",
		     scope => "one",
		     attrs => [qw(uid givenName sn)] };
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  my $e = $search->as_struct;
  # $self->h_log($e);
  my $employees;
  foreach my $k (keys(%$e)) {
    next if ! exists $e->{$k}->{givenname} || ! exists $e->{$k}->{sn};
    push @$employees, [ $e->{$k}->{sn}->[0] . " " . $e->{$k}->{givenname}->[0] => $e->{$k}->{uid}->[0] ];
  }
  my $es;
  @$es = sort {$a->[0] cmp $b->[0]} @$employees;
  # $self->h_log($es);

  my $par = $self->req->params->to_hash;
  # $self->h_log($par);
  $self->stash(project_new_params => $par, employees => $es);

  my $v = $self->validation;
  return $self->render(template => 'protected/project/new') unless $v->has_data;

  $v->required('proj_name')->size(3, 100)->like(qr/^[A-Za-z0-9.-_]+$/);
  # $self->h_log($v->error('proj_name'));
  $v->error(team_pm => ['Select at least one person.']) if ! exists $par->{team_pm};
  $v->error(team_backend => ['Select at least one person.']) if ! exists $par->{team_backend};
  $v->error(team_frontend => ['Select at least one person.']) if ! exists $par->{team_frontend};
  $v->error(team_qa => ['Select at least one person.']) if ! exists $par->{team_qa};

  $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{project},
		  filter => "(cn=" . $par->{proj_name} . ")",
		  scope => "one",
		  attrs => ['cn'] };
  $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  $v->error(proj_name => ['Project with such name exists']) if $search->count > 0;

  my $attrs = {
	       objectClass => $self->{app}->{cfg}->{ldap}->{objectClass}->{project},
	       cn => lc $par->{proj_name},
	       description => $par->{proj_descr},
	       associatedDomain => 'unknown'
	      };

  $self->h_log($attrs);

  my $msg = $ldap->add(sprintf("cn=%s,%s",
			       lc $par->{proj_name},
			       $self->{app}->{cfg}->{ldap}->{base}->{project}),
		       $attrs);
  my $debug;
  push @{$debug->{$msg->{status}}}, $msg->{message};
  my @groups = qw(pm tl back front qa devops);
  foreach my $g (@groups) {
    next if ! exists $par->{'team_' . $g};
    $attrs = {
	      objectClass => $self->{app}->{cfg}->{ldap}->{objectClass}->{project_groups},
	      cn => sprintf("%s_%s", lc $par->{proj_name}, $g),
	      memberUid => $par->{'team_' . $g}
	     };
    my $gn = $ldap->last_num($self->{app}->{cfg}->{ldap}->{base}->{project_groups}, 'cn', 'gidNumber');
    if ( $gn->[1] ) {
      $self->h_log($gn->[1]);
      $attrs->{gidNumber} = undef;
    } else {
      $attrs->{gidNumber} = $gn->[0] + 1;
    }
    $self->h_log($attrs);

    $msg = $ldap->add(sprintf("cn=%s,%s",
			      sprintf("%s_%s", lc $par->{proj_name}, $g),
			      $self->{app}->{cfg}->{ldap}->{base}->{project_groups}),
		      $attrs);
    push @{$debug->{$msg->{status}}}, $msg->{message};
  }

  $self->h_log($debug);
  $self->stash(debug => $debug);
  $self->render(template => 'protected/project/new'); #, layout => undef);
}

sub profile_new ($self) {
  my $par = $self->req->params->to_hash;
  $self->h_log($par);
  $self->stash(profile_new_params => $par);

  my $v = $self->validation;
  return $self->render(template => 'protected/profile/new') unless $v->has_data;

  my $re = qr/^\p{Lu}\p{L}*([-']\p{L}+)*$/;
  $v->required('user_first_name')->size(1, 50)->like($re);
  $v->required('user_last_name')->size(1, 50)->like($re);
  $v->required('title')->size(1, 50);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     filter => sprintf("(|(&(givenName=%s)(sn=%s))(uid=%s.%s))",
				       $par->{user_first_name},
				       $par->{user_last_name},
				       lc $par->{user_first_name},
				       lc $par->{user_last_name}),
		     scope => "one" };
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  $v->error(user_first_name => ['User with such first and last names exists']) if $search->count > 0;
  $v->error(user_last_name  => ['User with such first and last names exists']) if $search->count > 0;

  my $attrs = {
	       objectClass => $self->{app}->{cfg}->{ldap}->{objectClass}->{acc_root},
	       givenName => $par->{user_first_name},
	       sn => $par->{user_last_name},
	       gecos => $par->{user_first_name} . ' ' . $par->{user_last_name},
	       cn => $par->{user_first_name} . ' ' . $par->{user_last_name},
	       title => $par->{title},
	       ### just a kludge since there is no attribute for country available
	       registeredAddress => $par->{country},
	       ### just a kludge since there is no attribute for birth date available
	       carLicense => $par->{birth},
	       l => $par->{city},
	       uid => lc $par->{user_first_name} . '.' . lc $par->{user_last_name},
	       homeDirectory => '/usr/local/home/' . lc $par->{user_first_name} . '.' . lc $par->{user_last_name},
	       gidNumber => $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{gidNumber}->{onboarding}
	      };

  my $u = $ldap->last_num($self->{app}->{cfg}->{ldap}->{base}->{acc_root}, 'uid', 'uidNumber');
  if ( $u->[1] ) {
    $self->h_log($u->[1]);
    $attrs->{uidNumber} = undef;
  } else {
    $attrs->{uidNumber} = $u->[0] + 1;
  }

  $self->h_log($attrs);

  my $msg = $ldap->add(sprintf("uid=%s.%s,%s",
			       lc $par->{user_first_name},
			       lc $par->{user_last_name},
			       $self->{app}->{cfg}->{ldap}->{base}->{acc_root}),
		       $attrs);

  my $debug;
  push @{$debug->{$msg->{status}}}, $msg->{message};

  $self->stash(debug => $debug);
  $self->render(template => 'protected/profile/new');
}

sub profile_modify ($self) {
  my $from_form = $self->req->params->to_hash;
  $self->h_log($from_form);

  my $uid = $self->stash->{uid} // $from_form->{uid_to_modify} // '';
  $from_form->{uid_to_modify} = $self->stash->{uid} if exists $self->stash->{uid};

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     filter => '(uid=' . $uid .')',
		     scope => 'one',
		     attrs => [qw(givenName sn mail l registeredAddress title carLicense)], };
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  my ($from_ldap, $dn, $e);
  if ($search->count) {
    # $e = $search->entry;
    # foreach ($e->attributes) {
    #   $from_ldap->{$_} = $e->get_value($_);
    # }
    #$e = $search->entry;
    %$from_ldap = map {$_ => $search->entry->get_value($_)} $search->entry->attributes;
    $dn = $search->entry->dn;
  }
  $self->stash(from_ldap => $from_ldap);

  # $self->h_log($from_form);
  $self->stash(from_form => $from_form);

  $self->stash(debug_status => 'debug', debug_message => sprintf("<pre>%s</pre>", dumper {from_form => $from_form, uid => $self->stash->{uid}, from_ldap => $self->stash->{from_ldap} }));

  my $v = $self->validation;
  return $self->render(template => 'protected/profile/modify') unless $v->has_data;

  my $re = qr/^\p{Lu}\p{L}*([-']\p{L}+)*$/;
  $v->required('givenName')->size(1, 50)->like($re);
  $v->required('sn')->size(1, 50)->like($re);
  $v->required('title')->size(1, 50);

  my ($tmp_k, $tmp_v) = ('uid_to_modify', $from_form->{uid_to_modify});
  delete $from_form->{uid_to_modify};
  my $diff = $self->h_hash_diff( $from_ldap, $from_form);
  $self->h_log($diff);
  my ($add, $delete, $replace, $changes);
  if ( %{$diff->{added}} ) {
    push @$add, $_ => $diff->{added}->{$_} foreach (keys(%{$diff->{added}}));
    push @$changes, add => $add;
  }
  if ( %{$diff->{removed}} ) {
    push @$delete, $_ => [] foreach (keys(%{$diff->{removed}}));
    push @$changes, delete => $delete;
  }
  if ( %{$diff->{changed}} ) {
    push @$replace, $_ => $diff->{changed}->{$_}->{new} foreach (keys(%{$diff->{changed}}));
    push @$changes, replace => $replace;
  }
  $self->h_log($changes);
  $from_form->{$tmp_k} = $tmp_v;

  my $msg = $ldap->modify($dn, $changes);
  $self->stash(debug => {$msg->{status} => [ $msg->{message} ]});

  $self->render(template => 'protected/profile/modify'); #, layout => undef);
}

sub project_modify ($self) {
  my $from_form = $self->req->params->to_hash;
  my $debug;
  #$self->h_log($from_form);

  my $proj = $self->stash->{proj} // $from_form->{proj_to_modify} // '';
  $from_form->{proj_to_modify} = $self->stash->{proj} if exists $self->stash->{proj};
  #$self->h_log($from_form);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  ### PROJECT OBJECT
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{project},
		     filter => '(cn=' . $proj .')',
		     scope => 'one',
		     attrs => [qw(cn description)]};
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  my $from_ldap;
  if ($search->count) {
    %{$from_ldap->{proj}->{obj}} =
      map { $_ => ref($search->entry->get_value($_)) eq 'ARRAY' ? [$search->entry->get_value($_)] : $search->entry->get_value($_) }
      $search->entry->attributes;
    $from_ldap->{proj}->{dn} = $search->entry->dn;
  }

  ### PROJECT GROUPS
  $from_ldap->{groups} = {};
  $search_arg = { base => sprintf("ou=group,%s", $self->{app}->{cfg}->{ldap}->{base}->{project}),
		  filter => '(cn=' . $proj . '*)', };
  $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  $from_ldap->{groups}->{$_->get_value('cn')} = $_->get_value('memberUid', asref => 1)
    foreach ($search->entries);

  ### EMPLOYEES:TEAM MEMBERS SELECT ELEMENTS
  $search_arg =
    { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
      filter => sprintf("(&(uid=*)(!(gidNumber=%s)))",
			$self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber}),
      scope => "one",
      attrs => [qw(uid givenName sn)] };
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  my $e_str = $search->as_struct;
  my ($team, $employees, $employees_sorted);
  foreach my $g (keys(%{$from_ldap->{groups}})) {
    foreach my $k (keys(%$e_str)) {
      next if ! exists $e_str->{$k}->{givenname} || ! exists $e_str->{$k}->{sn};
      my $gecos = $e_str->{$k}->{sn}->[0] . " " . $e_str->{$k}->{givenname}->[0];
      if ( grep {$e_str->{$k}->{uid}->[0] eq $_} @{$from_ldap->{groups}->{$g}} ) {
	push @$team, [ $gecos => $e_str->{$k}->{uid}->[0], selected => 'selected' ];
      } else {
	push @$team, [ $gecos => $e_str->{$k}->{uid}->[0] ];
      }
    }
    @{$from_ldap->{employees}->{$g}} = sort {$a->[0] cmp $b->[0]} @$team;
    $team = undef;
  }

  foreach my $k (keys(%$e_str)) {
    next if ! exists $e_str->{$k}->{givenname} || ! exists $e_str->{$k}->{sn};
    push @$team, [ $e_str->{$k}->{sn}->[0] . " " . $e_str->{$k}->{givenname}->[0] => $e_str->{$k}->{uid}->[0] ];
  }
  @{$from_ldap->{employees}->{asis}} = sort {$a->[0] cmp $b->[0]} @$team;

  ### REST

  #$self->h_log($from_ldap->{groups});
  $self->stash(from_ldap => $from_ldap);

  $self->h_log($from_form);
  $self->stash(from_form => $from_form);

  $self->stash( proj => $self->stash->{proj}, from_ldap => $self->stash->{from_ldap}, project_team_roles => $self->{app}->{cfg}->{ldap}->{defaults}->{project_team_roles} );

  my $v = $self->validation;
  return $self->render(template => 'protected/project/modify') unless $v->has_data;

  my $re = qr/^[a-z0-9_.\-]+$/;
  $v->required('cn')->size(1, 50)->like($re);

  my ($msg, $diff, $add, $delete, $replace, $changes, $chg);
  $diff = $self->h_hash_diff( $from_ldap->{proj}->{obj},
			      { cn => $from_form->{cn},
				description => $from_form->{description} } );
  #$self->h_log($diff);
  if ( %{$diff->{added}} ) {
    push @$add, $_ => $diff->{added}->{$_} foreach (keys(%{$diff->{added}}));
    push @$changes, add => $add;
  }
  if ( %{$diff->{removed}} ) {
    push @$delete, $_ => [] foreach (keys(%{$diff->{removed}}));
    push @$changes, delete => $delete;
  }
  if ( %{$diff->{changed}} ) {
    push @$replace, $_ => $diff->{changed}->{$_}->{new} foreach (keys(%{$diff->{changed}}));
    push @$changes, replace => $replace;
  }

  if (defined $changes) {
    $msg = $ldap->modify($from_ldap->{proj}->{dn}, $changes);
    ### !!! to push to debug_message rather than overwrite
    push @{$debug->{$msg->{status}}}, $msg->{message};
    $chg->{proj} = $changes;
  }
  $diff = $add = $delete = $replace = $changes = undef;

  # $self->h_log($self->{app}->{cfg}->{ldap}->{defaults}->{project_team_roles});

  foreach my $team_role (@{$self->{app}->{cfg}->{ldap}->{defaults}->{project_team_roles}}) {
    my $ldap_group_name = $from_ldap->{proj}->{obj}->{cn} . '_' . $team_role;
    if ( ! exists $from_form->{$team_role} && ! exists $from_ldap->{groups}->{ $ldap_group_name } ) {
      next;
    } elsif ( ! exists $from_form->{$team_role} && exists $from_ldap->{groups}->{ $ldap_group_name } ) {
      push @$changes, delete => [memberUid => []];
    } elsif ( exists $from_form->{$team_role} && ! exists $from_ldap->{groups}->{ $ldap_group_name } ) {
      push @$changes, add =>
	[ memberUid => ref($from_form->{$team_role}) ne 'ARRAY' ? [ $from_form->{$team_role} ] : $from_form->{$team_role} ];
    } else {
      # $self->h_log($from_ldap->{groups}->{ $ldap_group_name });
      # $self->h_log($from_form->{$team_role});
      $diff = $self
	->h_array_diff( $from_ldap->{groups}->{ $ldap_group_name },
			ref($from_form->{$team_role}) ne 'ARRAY' ? [$from_form->{$team_role}] : $from_form->{$team_role});
      $self->h_log($diff);
      if ( @{$diff->{added}} ) {
	push @$add, memberUid => $diff->{added};
	push @$changes, add => $add;
      }
      if ( @{$diff->{removed}} ) {
	push @$delete, memberUid => [];
	push @$changes, delete => $delete;
      }
    }

    if (defined $changes) {
      $msg = $ldap->modify(sprintf("cn=%s,%s",
				   $ldap_group_name,
				   $self->{app}->{cfg}->{ldap}->{base}->{project_groups}),
			   $changes);
      ### !!! to push to debug_message rather than overwrite
      push @{$debug->{$msg->{status}}}, $msg->{message};
      $chg->{group}->{$team_role} = $changes if defined $changes;;
    }
    $diff = $add = $delete = $replace = $changes = undef;
  }
  $self->h_log($chg);

  $self->render(template => 'protected/project/modify', debug => $debug); # , layout => undef);
}

sub resolve ($self) {
  my $p = $self->req->params->to_hash;
  my $a = { query => { A   => $p->{a}   // '',
		       PTR => $p->{ptr} // '',
		       MX  => $p->{mx}  // '', }, };

  my $res;
  while ( my($k, $v) = each %{$a->{query}} ) {
    next if $v eq '';
    $res = ref($v) eq 'ARRAY' ? $v : [ $v ];

    push @{$a->{reply}}, $self->h_dns_resolver({ type  => $k,
						 debug => 0,
						 name  => $_ })
      foreach (@{$res});
  }

  foreach (@{$a->{reply}}) {
    push @{$a->{body}}, $_->{success}         if exists $_->{success};
    push @{$a->{body}}, $_->{error}->{errstr} if exists $_->{error};
  }

  # $self->h_log($_) foreach (@{$a->{body}});

  $self->render( #template => 'protected/tool/resolv',
		 layout => undef,
		 text => join("\n", @{$a->{body}}) // '' );
}


1;
