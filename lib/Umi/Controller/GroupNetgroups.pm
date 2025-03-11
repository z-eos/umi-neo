# -*- mode: cperl; eval: (follow-mode 1); -*-

package Umi::Controller::Group;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojolicious::Validator;

use Net::LDAP::Constant qw(
			    LDAP_SUCCESS
			    LDAP_PROTOCOL_ERROR
			    LDAP_NO_SUCH_OBJECT
			    LDAP_INVALID_DN_SYNTAX
			    LDAP_INSUFFICIENT_ACCESS
			    LDAP_CONTROL_SORTRESULT
			 );

use Umi::Ldap;

sub new_grp ($self) {
  my (%debug, $p);
  $p = $self->req->params->to_hash;
  $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my ($emploees, $err);
  ($emploees, $err) = $ldap->all_users;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;
  # $self->h_log($emploees);

  $self->stash( debug => \%debug,
		emploees => $emploees );

  my $v = $self->validation;
  return $self->render(template => 'protected/group/new_grp') unless $v->has_data;

  my $re_cn = qr/^[[:alnum:]]+$/;
  $v->required('cn')->like($re_cn);
  $v->error( cn => ['ASCII alnum characters only'] ) if $v->error('cn');

  my $attrs = {
	       objectClass => $self->{app}->{cfg}->{ldap}->{objectClass}->{group},
	       cn => $p->{cn},
	       memberUid => $p->{memberUid}
	      };
  my $gn = $ldap->last_num($self->{app}->{cfg}->{ldap}->{base}->{group}, '(cn=*)', 'gidNumber');
  if ( $gn->[1] ) {
    $self->h_log($gn->[1]);
    $attrs->{gidNumber} = undef;
  } else {
    $attrs->{gidNumber} = $gn->[0] + 1;
  }
  $self->h_log($attrs);

  my $msg = $ldap->add(sprintf("cn=%s,%s", $p->{cn}, $self->{app}->{cfg}->{ldap}->{base}->{group}),
		       $attrs);
  push @{$debug{$msg->{status}}}, $msg->{message};


  $self->render(template => 'protected/group/new_grp');
}

sub new_netgrp ($self) {
  my (%debug, $p);
  # $p = $self->req->params->to_hash;
  $p = $self->h_nested_params;
  $self->h_log($p);
  foreach (keys %$p) {
    delete $p->{$_} if $p->{$_} eq '';
  }
  $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my ($i, $l, $r, $memberUid, $hosts, $err, $msg, $entry, $search_arg, @tuples, @t, $attrs);
  ($memberUid, $err) = $ldap->all_users({with => 'root_and_ssh'});
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;
  my %memberUid_hash = map { $_->[1] => $_->[0] } @$memberUid;
  ($hosts, $err) = $ldap->all_hosts;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;
  my %hosts_hash = map { $_ => 1 } @$hosts;

  $self->stash( debug => \%debug,
		memberUid => [[]],
		hosts => [[]],
		memberUid_orig => $memberUid,
		hosts_orig => $hosts );

  if ( ! exists $p->{dn_to_modify_netgr} ) {
    ### ---[ new object creation ]-------------------------------

    my $v = $self->validation;
    return $self->render(template => 'protected/group/new_netgrp') unless $v->has_data;

    my $re_cn = qr/^[[:alnum:]_-]+$/;
    $v->required('cn')->like($re_cn);
    # $self->h_log($v->input);
    $v->error( cn => ['ASCII alnum characters only'] ) if $v->error('cn');
    $v->required('memberUid[0]');
    $v->error( 'memberUid[0]' => ['can not be empty'] ) if ! $self->h_is_empty_nested_arr($memberUid);
    $v->required('hosts[0]');
    $v->error( 'hosts[0]' => ['can not be empty'] ) if ! $self->h_is_empty_nested_arr($hosts);

    $i = 0;
    foreach my $n (@{$p->{memberUid}}) {
      @t = map {
	my ($hostname, $domain) = split /\./, $_, 2;
	map {
	  sprintf("(%s,%s,%s)", $hostname, $_, $domain)
	} @{$p->{memberUid}->[$i]} }
	@{$p->{hosts}->[$i]};
      @tuples = (@tuples, @t);
      $i++;
    }

    $attrs = {
	      objectClass => $self->{app}->{cfg}->{ldap}->{objectClass}->{netgroup},
	      cn => $p->{cn},
	      nisNetgroupTriple => \@tuples
	     };

    $msg = $ldap->add(sprintf("cn=%s,ou=access,%s", $p->{cn}, $self->{app}->{cfg}->{ldap}->{base}->{netgroup}),
		      $attrs);
    push @{$debug{$msg->{status}}}, $msg->{message};

    ($hosts, $err) = $ldap->all_hosts;
    push @{$debug{$err->{status}}}, $err->{message} if defined $err;
    undef $err;

    # $self->h_log($p);
    $self->stash( attrs => $attrs,
		  memberUid => $p->{memberUid},
		  hosts => $p->{hosts},
		  hosts_orig => $hosts );

  } else {
    ### ---[ object modification (Cartesian product grouping) ]------------------------

    $search_arg = { base => $p->{dn_to_modify_netgr}, scope => 'base' };
    $msg = $ldap->search( $search_arg );
    $self->h_log( $self->h_ldap_err($msg, $search_arg) ) if $msg->code;
    $entry = $msg->entry;

    #- STEP1: Build a mapping of `hostname.domain` to `user`s
    my %host_to_users;
    my $nisNetgroupTriple = $entry->get_value('nisNetgroupTriple', asref => 1);
    for my $triple ( @$nisNetgroupTriple ) {
      my ($hostname, $user, $domain) = split /,/, substr($triple,1,-1);
      my $host_domain = "$hostname.$domain";
      push @{ $host_to_users{$host_domain} }, { user => $user, host => $hostname, domain => $domain };
    }

    #- STEP2: Identify unique sets of users (Cartesian product groups)
    my %grouped;
    for my $host_domain (keys %host_to_users) {
      my @users = sort map { $_->{user} } @{ $host_to_users{$host_domain} };
      my $key   = join ',', @users; # Unique signature for this user set
      push @{ $grouped{$key} }, @{ $host_to_users{$host_domain} };
    }

    #- STEP3: Convert to a flat format to be compared with data from LDAP object
    my @tuples_grouped = map {
      map { "($_->{host},$_->{user},$_->{domain})" } @$_
    } values %grouped;
    # $self->h_log(\@tuples_grouped);

    if ( exists $p->{memberUid} ) {
      $i = 0;
      foreach my $n (@{$p->{memberUid}}) {
	@t = map {
	  my ($hostname, $domain) = split /\./, $_, 2;
	  map {
	    sprintf("(%s,%s,%s)", $hostname, $_, $domain)
	  } @{$p->{memberUid}->[$i]} }
	  @{$p->{hosts}->[$i]};
	@tuples = (@tuples, @t);
	$i++;
      }
    }

    my @keys = sort keys %grouped;
    my @tuples_users = map {
      my @all = map { $_->{user} } @{ $grouped{$_} };
      my %seen;
      [ grep { !$seen{$_}++ } @all ];
    } @keys;

    my @tuples_hosts = map {
      my @all = map { "$_->{host}.$_->{domain}" } @{ $grouped{$_} };
      my %seen;
      [ grep { !$seen{$_}++ } @all ];
    } @keys;

    # $self->h_log(\@tuples_users);
    # $self->h_log(\@tuples_hosts);

    ### ---[ start existence check for users/hosts ]--------------------

    # Build uniqueness hashes for users and hosts
    my (%object_unique_tuples_users, %object_unique_tuples_hosts);
    for my $group (values %grouped) {
      $object_unique_tuples_users{ $_->{user} } = 1 for @$group;
      $object_unique_tuples_hosts{ "$_->{host}.$_->{domain}" } = 1 for @$group;
    }

    # Extract sorted unique keys
    my @all_object_unique_tuples_users = sort keys %object_unique_tuples_users;
    my @all_object_unique_tuples_hosts = sort keys %object_unique_tuples_hosts;

    # Push warnings for users not in %memberUid_hash
    my @memberUid_warnings = map {
      sprintf("no active user <mark>%s</mark> was found, corresponding tuple will be removed on submit", $_)
    } grep { ! exists $memberUid_hash{$_} } @all_object_unique_tuples_users;
    push @{$debug{warn}}, @memberUid_warnings if @memberUid_warnings;

    # Push warnings for hosts not in %hosts_hash
    my @hosts_warnings = map {
      sprintf("no host <mark>%s</mark> was found, corresponding tuple will be removed on submit", $_)
    } grep { ! exists $hosts_hash{$_} } @all_object_unique_tuples_hosts;
    push @{$debug{warn}}, @hosts_warnings if @hosts_warnings;

    ### ---[ stop  existence check for users/hosts ]--------------------

    # on form submit
    $self->h_log($p);
    if ( keys %$p > 1 ) { # no data ==> no changes
      my $diff = $self->h_array_diff($nisNetgroupTriple, \@tuples);
      # $self->h_log($diff);
      my ($add, $delete, $changes);
      if ( @{$diff->{added}} ) {
	push @$add, nisNetgroupTriple => $diff->{added};
	push @$changes, add => $add;
      }
      if ( @{$diff->{removed}} ) {
	push @$delete, nisNetgroupTriple => [];
	push @$changes, delete => $delete;
      }

      if ($changes) {
	$self->h_log($changes);
	$msg = $ldap->modify($entry->dn, $changes);
	$self->stash(debug => {$msg->{status} => [ $msg->{message} ]});
      }

      ($hosts, $err) = $ldap->all_hosts;
      push @{$debug{$err->{status}}}, $err->{message} if defined $err;
      undef $err;

      $self->stash( hosts_orig => $hosts );
    }

    $self->stash( dn_to_modify_netgr => $p->{dn_to_modify_netgr},
		  cn => $entry->get_value('cn'),
		  tuples_grouped => \@tuples_grouped,
		  memberUid => \@tuples_users,
		  hosts => \@tuples_hosts );

  }

  $self->render(template => 'protected/group/new_netgrp');
}

1;
