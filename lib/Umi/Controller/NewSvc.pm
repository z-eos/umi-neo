# -*- mode: cperl; eval: (follow-mode 1); -*-

package Umi::Controller::Newsvc;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojo::Util qw(b64_encode dumper trim);
use Mojo::JSON qw(decode_json encode_json to_json);

use Mojolicious::Validator;

use IO::Compress::Gzip qw(gzip $GzipError);
use POSIX qw(strftime);
use Encode qw(decode_utf8);
use Net::LDAP::Constant qw(
			    LDAP_SUCCESS
			    LDAP_PROTOCOL_ERROR
			    LDAP_NO_SUCH_OBJECT
			    LDAP_INVALID_DN_SYNTAX
			    LDAP_INSUFFICIENT_ACCESS
			    LDAP_CONTROL_SORTRESULT
			 );

use Umi::Ldap;

sub newsvc ($self) {
  my (%debug, $p, $err);
  my $par = $self->req->params->to_hash;
  %$p = map { $_ => $par->{$_} } grep { defined $par->{$_} && $par->{$_} ne '' } keys %$par;
  $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my %schema_all_attributes = map { $_->{name} => $_ } $ldap->schema->all_attributes;

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{project},
		     scope => 'one',
		     filter => '(cn=*)',
		     attrs => ['associatedDomain'] };
  # $self->h_log($search_arg);
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;

  my ($domains, $domains_arr, $domains_ref);
  foreach ($search->entries) {
    $domains_ref = $_->get_value('associatedDomain', asref => 1);
    push @$domains_arr, @$domains_ref if $domains_ref->[0] ne 'unknown';
  }

  ($domains, $err) = $ldap->all_hosts;
  $self->h_log( $err ) if $err;
  my $axfr = $self->h_dns_resolver({ type => 'AXFR', ns_custom => 1 })->{success};
  my %seen;
  @{$domains} = grep { !$seen{$_}} (@$domains, sort keys %{$axfr});

  $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{rad_groups},
		  filter => '(cn=*)' };
  # $self->h_log($search_arg);
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;

  my $rad_groups;
  %$rad_groups = map { $_->dn => $_->exists('description') ? $_->get_value('description') : $_->get_value('cn') } $search->entries;
  # $self->h_log($rad_groups);

  $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{rad_profiles},
		  filter => '(cn=*)' };
  # $self->h_log($search_arg);
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;

  my $rad_profiles;
  %$rad_profiles = map { $_->dn => $_->exists('description') ? $_->get_value('description') : $_->get_value('cn') } $search->entries;
  # $self->h_log($rad_profiles);

  $search_arg = { base => $p->{dn_to_new_svc}, scope => 'base', };
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;
  my $root = $search->entry;

  $self->stash( dn_to_new_svc => $p->{dn_to_new_svc},
		root => $root,
		schema => \%schema_all_attributes,
		domains => $domains,
		rad_groups => $rad_groups,
		rad_profiles => $rad_profiles );

  my $uploads = $self->req->uploads;
  # $self->h_log($uploads);
  if ( @$uploads ) {
    foreach ( @$uploads ) {
      # $self->h_log($_);
      my $n = $_->name;
      $n =~ s/_binary/;binary/;
      $p->{$n} = $_->slurp;
    }
  }

  # $self->h_log($self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{data_fields});
  my $v = $self->validation;
  return $self->render(template => 'protected/profile/newsvc') unless exists $p->{authorizedService};
  foreach (@{$self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{data_fields}}) {
    next if $_ eq 'description';
    if ( $_ eq 'userPassword' ) {
      # $v->required('password1');
      # $v->required('password2');
      # $v->error( password1 => [ 'field password1 is required' ] ) if ! exists $p->{password1};
      # $v->error( password2 => [ 'field password2 is required' ] ) if ! exists $p->{password2};
      $v->error( password1 => [ 'new password and its confirmation do not match' ] )
	if exists $p->{password1} && exists $p->{password2} && $p->{password1} ne $p->{password2};
    } elsif ( $_ eq 'umiOvpnCfgIfconfigPush' ) {
      my ($l, $r) = split / /, $p->{umiOvpnCfgIfconfigPush};
      $v->error( umiOvpnCfgIfconfigPush => [ 'wrong ip address/es' ] )
	if exists $p->{umiOvpnCfgIfconfigPush} && (! $self->h_is_ip($l) || ! $self->h_is_ip($r) );
    } elsif ( $_ eq 'umiOvpnCfgIroute' ) {
      if ( $_ =~ /^\S+\s+\S+$/ ) {
	$v->error( umiOvpnCfgIroute => [ 'wrong network address and/or netmask' ] )
	  if exists $p->{umiOvpnCfgIroute} && ! $self->h_is_ip_pair($_);
      } else {
	$v->error( umiOvpnCfgIroute => [ 'wrong network address' ] )
	  if exists $p->{umiOvpnCfgIroute} && ! $self->h_is_ip($_);
      }
    } else {
      # # $self->h_log($_);
      # $v->required($_);
      # # $v->error( $_ => ['reuired'] ) if $v->error($_);
      # $v->error( $_ => [ 'field ' . $_ . ' is required'] ) if ! exists $p->{$_};
    }
  }

  # $self->h_log($p);

  if ( ! $v->has_error ) {
    #---------------------------------------------------------------------
    # newsvc branch
    #---------------------------------------------------------------------

    my $br = $self->h_branch_add_if_not_exists($p, $ldap, $root, \%debug);
    # $self->h_log(\%debug);

    #---------------------------------------------------------------------
    # newsvc account
    #---------------------------------------------------------------------

    my $svc = $self->h_service_add_if_not_exists($p, $ldap, $root, $br, \%debug);
    # $self->h_log(\%debug);
  }

  $self->stash( debug => \%debug );

  $self->render(template => 'protected/profile/newsvc');
}

1;
