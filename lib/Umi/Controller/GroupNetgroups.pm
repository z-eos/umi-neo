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
  # my (%debug, $p);
  # $p = $self->req->params->to_hash;
  # $self->h_log($p);

  # my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  # my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
  # 		     scope => 'one',
  # 		     filter => "(&(uid=*)(!(gidNumber=" . $self->{app}->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber} . ")))",
  # 		     attrs => ['givenName', 'sn', 'uid'] };
  # # $self->h_log($search_arg);
  # my $search = $ldap->search( $search_arg );
  # $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;

  # my $emploees = [ map {
  #   [ $_->get_value('sn') . ' ' . $_->get_value('givenName') => $_->get_value('uid') ]
  # } $search->entries ];
  # # $self->h_log($emploees);

  # $self->stash( debug => \%debug,
  # 		emploees => $emploees );

  # my $v = $self->validation;
  # return $self->render(template => 'protected/group/new_grp') unless $v->has_data;

  # my $re_cn = qr/^[[:alnum:]]+$/;
  # $v->required('cn')->like($re_cn);
  # $v->error( cn => ['ASCII alnum characters only'] ) if $v->error('cn');

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
