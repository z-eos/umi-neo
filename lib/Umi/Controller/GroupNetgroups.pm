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

  my ($i, $l, $r, $memberUid, $hosts, $err, $msg, $entry, $search_arg, @tuples, @t);
  ($memberUid, $err) = $ldap->all_users({with => 'root_and_ssh'});
  $self->h_log($memberUid);
  $self->h_log($err);
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
  $self->stash( host => $p->{host} ) if exists $p->{host};

  if ( ! exists $p->{dn_to_modify_netgr} ) {

    ### ---[ start of new object creation ]-------------------------------

    my $v = $self->validation;
    return $self->render(template => 'protected/group/new_netgrp') unless $v->has_data;

    my $re_cn = qr/^[[:alnum:]_-]+$/;
    $v->required('cn')->like($re_cn);
    $v->error( cn => ['ASCII alnum characters only'] ) if $v->error('cn');
    $v->required('memberUid');
    $v->error( hosts => ['can not be empty'] ) if ! exists $p->{hosts} && ! exists $p->{host};

    $i = 0;
    foreach my $n (@{$p->{memberUid}}) {
      @t = map {
	my ($hostname, $domain) = split /\./, $_, 2;
	map {
	  sprintf("%s,%s,%s", $hostname, $_, $domain)
	} @{$p->{memberUid}->[$i]} }
	@{$p->{hosts}->[$i]};
      @tuples = (@tuples, @t);
      $i++;
    }

    # my $attrs = {
    # 	       objectClass => $self->{app}->{cfg}->{ldap}->{objectClass}->{netgroup},
    # 	       cn => $p->{cn},
    # 	       memberUid => $p->{memberUid}
    # 	      };
    # my $gn = $ldap->last_num($self->{app}->{cfg}->{ldap}->{base}->{group}, '(cn=*)', 'gidNumber');
    # $self->h_log($attrs);

    # my $msg = $ldap->add(sprintf("cn=%s,%s", $p->{cn}, $self->{app}->{cfg}->{ldap}->{base}->{group}),
    # 		       $attrs);
    # push @{$debug{$msg->{status}}}, $msg->{message};

    ### ---[ stop  of new object creation ]-------------------------------

    $self->h_log(\@tuples);
    $self->stash( tuples => \@tuples,
		  memberUid => $p->{memberUid},
		  hosts => $p->{hosts} );

  } else {

    $search_arg = { base => $p->{dn_to_modify_netgr}, scope => 'base' };
    $msg = $ldap->search( $search_arg );
    $self->h_log( $self->h_ldap_err($msg, $search_arg) ) if $msg->code;
    $entry = $msg->entry;

    ### ---[ start of Cartesian product grouping ]------------------------

    #- STEP1: Build a mapping of `hostname.domain` to `user`s
    my %host_to_users;
    for my $triple ( @{$entry->get_value('nisNetgroupTriple', asref => 1)} ) {
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

    #- STEP3: Convert to the required flat format
    my @tuples_grouped = map {
      [ map { "$_->{host},$_->{user},$_->{domain}" } @$_ ]
    } values %grouped;
    # $self->h_log(\%grouped);

    ### ---[ stop  of Cartesian product grouping ]------------------------

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

    ### ---[ start object users/hosts existence check ]-----------------

    my %object_unique_tuples_users;
    my %object_unique_tuples_hosts;

    # Iterate over all groups (values of %grouped)
    for my $group (values %grouped) {
      # Iterate over each record in the group
      for my $entry (@$group) {
        $object_unique_tuples_users{$entry->{user}} = 1;
        $object_unique_tuples_hosts{"$entry->{host}.$entry->{domain}"} = 1;
      }
    }

    my @all_object_unique_tuples_users  = sort keys %object_unique_tuples_users;
    my @all_object_unique_tuples_hosts  = sort keys %object_unique_tuples_hosts;

    foreach (@all_object_unique_tuples_users) {
      push @{$debug{warn}}, sprintf("no active user <mark>%s</mark> was found, corresponding tuple will be ignored", $_)
	       if ! exists $memberUid_hash{$_};
    }
    foreach (@all_object_unique_tuples_hosts) {
      push @{$debug{warn}}, sprintf("no host <mark>%s</mark> was found, corresponding tuple will be ignored", $_)
	       if ! exists $hosts_hash{$_};
    }

    ### ---[ start object users/hosts existence check ]-----------------

    $self->stash( dn_to_modify_netgr => $p->{dn_to_modify_netgr},
		  cn => $entry->get_value('cn'),
		  tuples_grouped => \@tuples_grouped,
		  memberUid => \@tuples_users,
		  hosts => \@tuples_hosts );

    # my $attrs = {
    # 	       objectClass => $self->{app}->{cfg}->{ldap}->{objectClass}->{group},
    # 	       cn => $p->{cn},
    # 	       memberUid => $p->{memberUid}
    # 	      };
    # my $gn = $ldap->last_num($self->{app}->{cfg}->{ldap}->{base}->{group}, '(cn=*)', 'gidNumber');
    # if ( $gn->[1] ) {
    #   $self->h_log($gn->[1]);
    #   $attrs->{gidNumber} = undef;
    # } else {
    #   $attrs->{gidNumber} = $gn->[0] + 1;
    # }
    # $self->h_log($attrs);

    # my $msg = $ldap->add(sprintf("cn=%s,%s", $p->{cn}, $self->{app}->{cfg}->{ldap}->{base}->{group}),
    # 		       $attrs);
    # push @{$debug{$msg->{status}}}, $msg->{message};

  }

  $self->render(template => 'protected/group/new_netgrp');
}

1;
