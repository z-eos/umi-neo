# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Controller::Newsvc;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojo::Util qw(b64_encode dumper trim);
use Mojo::JSON qw(decode_json encode_json to_json);

use Mojolicious::Validator;

use IO::Compress::Gzip qw(gzip $GzipError);
use POSIX qw(strftime);
use Encode qw(decode_utf8);

use Umi::Ldap;

sub newsvc ($self) {
  my ($debug, $p);
  my $par = $self->req->params->to_hash;
  %$p = map { $_ => $par->{$_} } grep { defined $par->{$_} && $par->{$_} ne '' } keys %$par;
  # $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my %schema = map { $_->{name} => $_ } $ldap->schema->all_attributes;

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{project},
		     scope => 'one',
		     filter => '(cn=*)',
		     attrs => ['associatedDomain'] };
  # $self->h_log($search_arg);
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;

  my ($domains, $domains_ref);
  foreach ($search->entries) {
    $domains_ref = $_->get_value('associatedDomain', asref => 1);
    push @$domains, @$domains_ref if $domains_ref->[0] ne 'unknown';
  }
  @$domains = sort @$domains;

  $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{rad_groups},
		  filter => '(cn=*)' };
  # $self->h_log($search_arg);
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;

  my $rad_groups;
  %$rad_groups = map { $_->dn => $_->exists('description') ? $_->get_value('description') : $_->get_value('cn') } $search->entries;
  # $self->h_log($rad_groups);

  $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{rad_profiles},
		  filter => '(cn=*)' };
  # $self->h_log($search_arg);
  $search = $ldap->search( $search_arg );
  # $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;

  my $rad_profiles;
  %$rad_profiles = map { $_->dn => $_->exists('description') ? $_->get_value('description') : $_->get_value('cn') } $search->entries;
  # $self->h_log($rad_profiles);

  $search_arg = { base => $p->{dn_to_new_svc}, scope => 'base', };
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;

  $self->stash( dn_to_new_svc => $p->{dn_to_new_svc},
		root => $search->entry,
		schema => \%schema,
		domains => $domains,
		rad_groups => $rad_groups,
		rad_profiles => $rad_profiles );

  # $self->h_log($self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{data_fields});
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/newsvc') unless exists $p->{authorizedService};
  foreach (@{$self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{data_fields}}) {
    next if $_ eq 'description';
    if ( $_ eq 'userPassword' ) {
      $v->required('password1');
      $v->required('password2');
      $v->error( password1 => [ 'field password1 is required' ] ) if ! exists $p->{password1};
      $v->error( password2 => [ 'field password2 is required' ] ) if ! exists $p->{password2};
      $v->error( password1 => [ 'new password and its confirmation do not match' ] ) if $p->{password1} ne $p->{password2};
      $v->error( password2 => [ 'new password and its confirmation do not match' ] ) if $p->{password1} ne $p->{password2};
    } else {
      # $self->h_log($_);
      $v->required($_);
      # $v->error( $_ => ['reuired'] ) if $v->error($_);
      $v->error( $_ => [ 'field ' . $_ . ' is required'] ) if ! exists $p->{$_};
    }
  }

  $self->h_log($p);
  #---------------------------------------------------------------------
  # newsvc branch
  #---------------------------------------------------------------------
  my $br_dn = sprintf('authorizedService=%s@%s,%s',
		      $p->{authorizedService},
		      $p->{associatedDomain},
		      $p->{dn_to_new_svc} );
  my $if_exist = $ldap->search( { base => $br_dn, scope => 'base', attrs => [ 'authorizedService' ], } );
  if ( $if_exist->count ) {
  } else {
    my $br_attrs =
      { uid => sprintf('%s@%s_%s', $p->{authorizedService}, $p->{associatedDomain}, $p->{login}),
	objectClass       => [ @{$self->{app}->{cfg}->{ldap}->{objectClass}->{acc_svc_branch}} ],
	associatedDomain  => $p->{associatedDomain},
	authorizedService => sprintf('%s@%s',
				     $p->{authorizedService},
				     $p->{associatedDomain}), };

    my $msg = $ldap->add( $br_dn, $br_attrs );
    if ( $msg ) {
      push @{$debug->{$msg->{status}}}, $msg->{message};
    }
  }

  #---------------------------------------------------------------------
  # newsvc account
  #---------------------------------------------------------------------
  my $svc_dn = sprintf('%s=%s,%s',
		       exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{rdn} ?
		       $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{rdn} :
		       $self->{app}->{cfg}->{ldap}->{default}->{rdn},
		       $p->{login},
		       $br_dn
		      );

  $self->session( debug => $debug );

  $self->render(template => 'protected/tool/newsvc');
}

1;
