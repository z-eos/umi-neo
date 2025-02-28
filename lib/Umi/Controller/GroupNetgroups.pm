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

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     scope => 'one',
		     filter => "(&(uid=*)(!(gidNumber=" . $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber} . ")))",
		     attrs => ['givenName', 'sn', 'uid'] };
  # $self->h_log($search_arg);
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;

  my $emploees = [ map {
    [ $_->get_value('sn') . ' ' . $_->get_value('givenName') => $_->get_value('uid') ]
  } $search->entries ];
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
  $p = $self->req->params->to_hash;
  foreach (keys %$p) {
    delete $p->{$_} if $p->{$_} eq '';
  }
  $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     scope => 'one',
		     filter => "(&(uid=*)(!(gidNumber=" . $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber} . ")))",
		     attrs => ['givenName', 'sn', 'uid'] };
  # $self->h_log($search_arg);
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;

  my ($i, $l,$r);
  my $emploees = [
		  map {
		    $i = sprintf("%s %s",
				 $_->get_value('sn') // '',
				 $_->get_value('givenName') // '');
		    utf8::decode($i) if ! utf8::is_utf8($i);

		    [ $i => $_->get_value('uid') ]

		  } $search->entries
		 ];
# input #   my $emploees = [
# input # 		  map {
# input # 		    $i = sprintf("%s %s",
# input # 				 $_->get_value('sn') // '',
# input # 				 $_->get_value('givenName') // '');
# input # 		    utf8::decode($i) if ! utf8::is_utf8($i);
# input # 
# input # 		    { label => $i, value => $_->get_value('uid') }
# input # 
# input # 		  } $search->entries
# input # 		 ];
  # $self->h_log($emploees);



  ### SERVERS: list of all servers available for the user
  $search_arg = { base => 'ou=access,' . $self->{app}->{cfg}->{ldap}->{base}->{netgroup},
		  filter => '(nisNetgroupTriple=*)',
		  attrs => ['nisNetgroupTriple'] };
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;
  my $netgroups = $search->as_struct;
  my (@tuple, %servers, $hostnames);
  while (my ($kk, $vv) = each %$netgroups) {
    foreach (@{$vv->{nisnetgrouptriple}}) {
      @tuple = split(/,/, substr($_, 1, -1));
      $servers{sprintf("%s.%s", $tuple[0], $tuple[2])} = 1;
    }
  }
  $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{machines},
		  attrs => ['cn'] };
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;
  $servers{$_->get_value('cn')} = 1 foreach ($search->entries);
  my $hosts = [ map { [ $_ => $_ ] } sort keys %servers ];
  # $self->h_log($hosts);

  $self->stash( debug => \%debug,
		emploees => $emploees,
		hosts => $hosts );
  $self->stash( host => $p->{host} ) if exists $p->{host};

  my $v = $self->validation;
  return $self->render(template => 'protected/group/new_netgrp') unless $v->has_data;

  my $re_cn = qr/^[[:alnum:]]+$/;
  $v->required('cn')->like($re_cn);
  $v->error( cn => ['ASCII alnum characters only'] ) if $v->error('cn');
  $v->required('memberUid');
  $v->error( host => ['can not be empty'] ) if ! exists $p->{hosts} && ! exists $p->{host};
  $v->error( hosts => ['can not be empty'] ) if ! exists $p->{hosts} && ! exists $p->{host};

  $hostnames = [
		map { defined($_) ? (ref $_ eq 'ARRAY' ? @$_ : $_) : () }
		($p->{hosts}, $p->{host})
	       ];

  my (@tuples, @t);
  my @memberUid = ref($p->{memberUid}) eq 'ARRAY'
    ? @{ $p->{memberUid} }
    : ($p->{memberUid});

  foreach my $j ( ref($p->{memberUid}) eq 'ARRAY' ? @{$p->{memberUid}} : ($p->{memberUid})) {
    @t = map {
      ($l, $r) = split(/\./, $_, 2);
      sprintf("(%s,%s,%s)", $l, $j, $r)
    } @$hostnames;
    push @tuples, @t;
  }
  $self->h_log(\@tuples);
  $self->stash( tuples => \@tuples );
  
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


  $self->render(template => 'protected/group/new_netgrp');
}

1;
