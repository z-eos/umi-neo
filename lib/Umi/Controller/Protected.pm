# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Controller::Protected;

use Mojo::Base 'Umi::Controller', -signatures;
use Mojo::Util qw(b64_encode);

use Umi::Ldap;

sub homepage ($self) {
  my $session_data = $self->session;
  $self->render(
		template => 'protected/home' =>
		session  => $self->dumper($session_data) =>
		current_user => $self->dumper($self->current_user) =>
		config => $self->{app}->{cfg}
	       );
}

sub other    ($self) { $self->render(template => 'protected/other') }

sub profile  ($self) {
  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     filter => sprintf("(uid=%s)", $self->session('uid')),
		     scope => 'one' };
  my $search = $ldap->search(	$search_arg );
  if ( $search->code ) {
    $self->log->error(
		      sprintf("Protected.pm: profile(): code: %s; message: %s; text: %s",
			      $search->code,
			      $search->error_name,
			      $search->error_text
			     ));
    return undef;
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
    $self->log->error(
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

use Data::Printer caller_info => 1;
sub modify ($self) {
  my $par = $self->req->params->to_hash;
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/modify') unless $v->has_data;

  my $ldap = Umi::Ldap->new( $self->{app},
			     $self->session('uid'),
			     $self->session('pwd') );

  p $par;

  my $search_arg = { base => substr($par->{dn}, index($par->{dn}, ",")+1),
		     filter => substr($par->{dn}, 0, index($par->{dn}, ",")),
		     attrs => []};
  my $search = $ldap->search( $search_arg );
  if ( $search->code ) {
    $self->log->error(
		      sprintf("Protected.pm: modify(): code: %s; message: %s; text: %s",
			      $search->code,
			      $search->error_name,
			      $search->error_text
			     ));
  }

  my $schema = $ldap->schema;
  my ($oc, $aa, $as);
  $oc->{$_->{name}} = $_ foreach $schema->all_objectclasses;
  $aa->{$_->{name}} = $_ foreach $schema->all_attributes;
  $as->{$_->{name}} = $_ foreach $schema->all_syntaxes;
  my @attr_unused = $self->h_attr_unused($search->entry, $oc);
  $self->stash(modify_params => $par, entry => $search->entry, aa => $aa, as => $as, oc => $oc, attr_unused => \@attr_unused);
  return $self->render(template => 'protected/tool/modify');
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

1;
