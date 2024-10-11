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
  my $uid = $par->{uid} // $self->stash->{uid} // '';
  $self->h_log($uid);

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
  # $self->{app}->h_log( $search_arg);
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  my $profiled_user = $search->as_struct;

  my ($modifiersname, $groups, $s, $servers, $server_alive, $p, $projects, $k, $kk, $v, $vv);
  while (($k, $v) = each %$profiled_user) {
    ### name of the last who modified this user root object
    $search_arg = { base => $v->{modifiersname}->[0], scope => 'base', attrs => ['gecos', 'uid'] };
    $search = $ldap->search( $search_arg );
    $modifiersname->{$k} = $search->as_struct->{$v->{modifiersname}->[0]};

    ### only admins and coadmins need this info
    if ( $self->is_role('admin,coadmin', {cmp => 'or'}) ) {
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
      my $n = $search->as_struct;
      my $t;
      while (my ($kk, $vv) = each %$n) {
	foreach (@{$vv->{nisnetgrouptriple}}) {
	  @$t = split(/,/, substr($_, 1, -1));
	  push @{$s->{$k}}, sprintf("%s.%s", $t->[0], $t->[2]);
	}
      }
      @{$servers->{$k}} = do {
	my %seen;
	sort grep { !$seen{$_}++ } @{$s->{$k}};
      };
      foreach (@{$servers->{$k}}) {
	$search_arg = { base => 'cn=' . $_ . ',' . $self->{app}->{cfg}->{ldap}->{base}->{machines},
			attrs => ['cn'] };
	$search = $ldap->search( $search_arg );
	$self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;
	$server_alive->{$k}->{$_} = $search->count;
      }
    }

    ### PROJECTS: list of all projects user is a member of
    $search_arg = { base => 'ou=group,' . $self->{app}->{cfg}->{ldap}->{base}->{project},
		    filter => '(memberUid=' . $v->{uid}->[0] . ')',
		    attrs => ['cn'] };
    $search = $ldap->search( $search_arg );
    $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
    $p = $search->as_struct;
    @{$projects->{$k}} = sort map { $p->{$_}->{cn}->[0] =~ s/_/:/r } keys(%$p);
  }
  # $self->h_log($modifiersname);
  $self->render(template => 'protected/profile',
		hash => $profiled_user,
		groups => $groups,
		group_blocked_gidnumber => $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber},
		servers => $servers,
		server_alive => $server_alive,
		search_base_case => $self->{app}->{cfg}->{ldap}->{base}->{machines},
		projects => $projects,
		modifiersname => $modifiersname);
}

sub ldif_import ($self) { $self->render(template => 'protected/tool/ldif-import') }

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
  return $self->render(template => 'protected/tool/ldif-export');
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
  return $self->render(template => 'protected/tool/sysinfo',
		       schema => encode_json(\%s),
		       last_num => $ldap->last_num({base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
						    filter_by => 'uid',
						    attr => 'uidNumber' }) );
}

sub pwdgen ($self) {
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/pwdgen') unless $v->has_data;

  my $par = $self->req->params->to_hash;
  $self->stash(pwdgen_params => $par);
  return $self->render(template => 'protected/tool/pwdgen' => pwdgen => $self->h_pwdgen($par));
}

sub qrcode ($self) {
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/qrcode') unless $v->has_data;

  my $par = $self->req->params->to_hash;
  $self->stash(qrcode_params => $par);
  return $self->render(template => 'protected/tool/qrcode' => qrcode => $self->h_qrcode($par));
}

sub keygen_ssh ($self) {
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/keygen/ssh') unless $v->has_data;

  my $par = $self->req->params->to_hash;
  $self->stash(kg_ssh_params => $par);
  return $self->render(template => 'protected/tool/keygen/ssh' =>
		       key => {
			       ssh => $self->h_keygen_ssh($par),
			       name => { real => 'name will be here',
					 email => 'email will be here' }
			      }
		      );
}

sub modify ($self) {
  my $par = $self->req->params->to_hash;
  # p $par;
  # my $v = $self->validation;
  # return $self->render(template => 'protected/tool/modify') unless $v->has_data;
  return $self->render(template => 'protected/tool/modify') unless %$par;

  my $ldap = Umi::Ldap->new( $self->{app},
			     $self->session('uid'),
			     $self->session('pwd') );

  my $search_arg = { base => $par->{dn_to_modify},
		     filter => '(objectClass=*)',
		     attrs => []};
  my $s = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($s, $search_arg) ) if $s->code;

  # `UNUSED ATTRIBUTES` select element
  my $schema = $ldap->schema;
  my %oc = map { $_->{name} => $_ } $schema->all_objectclasses;
  my %aa = map { $_->{name} => $_ } $schema->all_attributes;
  my %as = map { $_->{name} => $_ } $schema->all_syntaxes;

  my @attr_unused = $self->h_attr_unused($s->entry, \%oc);

  if ( keys %$par == 1 ) {
    # here we've just clicked, search result  menu `modify` button
    $self->h_log('~~~~~-> MODIFY: SEARCH RESULT MENU CHOOSEN');
    my ($e_orig, $e_tmp);
    foreach ($s->entry->attributes) {
      $e_tmp = $s->entry->get_value($_, asref => 1);
      if ( scalar @$e_tmp == 1 ) {
	$e_orig->{$_} = $e_tmp->[0];
      } else {
	$e_orig->{$_} = $e_tmp;
      }
    }
    $self->session->{e_orig} = $e_orig;
    # p $e_orig;
  } elsif (exists $par->{add_objectClass}) {
    # new objectClass addition is chosen
    $self->h_log('~~~~~-> MODIFY: ADD OBJECTCLASS');
    $self->h_log($par);
    # $s = $ldap->search( $search_arg );
    # $self->h_log(sprintf("Protected.pm: modify(): code: %s; message: %s; text: %s",
    # 			      $s->code, $s->error_name, $s->error_text )) if $s->code;
  } else {
    # form modification made
    $self->h_log('~~~~~-> MODIFY: FORM CHANGED?');
    delete $par->{dn_to_modify};
    delete $par->{attr_unused};
    my $diff = $self->h_hash_diff( $self->session->{e_orig}, $par);
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
  }

  $self->stash(entry => $s->entry, aa => \%aa, as => \%as, oc => \%oc, attr_unused => \@attr_unused);

  return $self->render(template => 'protected/tool/modify');
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
  $self->h_log($par);
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
  $self->render(template => 'protected/project/new');
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

  my $ldap = Umi::Ldap->new( $self->{app},
			     $self->session('uid'),
			     $self->session('pwd') );

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
  $self->stash(debug_status => $msg->{status}, debug_message => $msg->{message});

  $self->render(template => 'protected/profile/modify');
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

  $self->render(template => 'protected/project/modify', debug => $debug);
}

1;
