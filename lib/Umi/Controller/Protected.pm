# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Controller::Protected;

use Mojo::Base 'Umi::Controller', -signatures;
use Mojo::Util qw(b64_encode dumper);

use Umi::Ldap;

sub homepage ($self) {
  $self->render(
		template => 'protected/home',
		session  => $self->session,
		current_user => $self->helpers->current_user,
		config => $self->{app}->{cfg}
	       );
}

sub other    ($self) { $self->render(template => 'protected/other') }

sub profile  ($self) {
  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     filter => sprintf("(uid=%s)", $self->session('uid')),
		     scope => 'one' };

  my $search = $ldap->search( $search_arg );
  if ( $search->code ) {
    $self->h_log(
		 sprintf("\n\n
Protected.pm: profile(): search:\n
ERROR message: %s\n
code: %s; errname: %s; text: %s; desc: %s\n
options: %s\n",
			      $search->error,
			      $search->code,
			      $search->error_name,
			      $search->error_text,
			      $search->error_desc,
			      $self->dumper($search_arg)
			     ));
  }

  $self->render(template => 'protected/profile' =>
		dump => $search->entry->ldif => hash => $search->as_struct);
}

sub ldif_import    ($self) { $self->render(template => 'protected/tool/ldif-import') }

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
  use Data::Printer;
  p $search_arg;
  my $search = $ldap->search( $search_arg );
  if ( $search->code ) {
    $self->h_log(
		 sprintf("Protected.pm: ldif_export(): code: %s; message: %s; text: %s",
			 $search->code,
			 $search->error_name,
			 $search->error_text
			));
  }

  my $ldif;
  foreach ($search->entries) {
    $ldif .= $_->ldif;
  }

  $self->stash(ldif_export_params => $par => ldif => $ldif);
  return $self->render(template => 'protected/tool/ldif-export');
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
  $self->h_log(sprintf("Protected.pm: modify(): code: %s; message: %s; text: %s",
		       $s->code, $s->error_name, $s->error_text )) if $s->code;

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

1;
