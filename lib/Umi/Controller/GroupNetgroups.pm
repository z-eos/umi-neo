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
  $p = $self->req->params->to_hash;
  foreach (keys %$p) {
    delete $p->{$_} if $p->{$_} eq '';
  }
  $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my ($i, $l, $r, $emploees, $hosts, $err, $search, $search_arg);
  ($emploees, $err) = $ldap->all_users;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;
  ($hosts, $err) = $ldap->all_hosts;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;

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

  my $hostnames = [
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
