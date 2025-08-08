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
  my (%debug, $p); #, $err);
  my $par = $self->req->params->to_hash;
  %$p = map { $_ => $par->{$_} } grep { defined $par->{$_} && $par->{$_} ne '' } keys %$par;
  $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my %schema_all_attributes = map { $_->{name} => $_ } $ldap->schema->all_attributes;

  my ($domains, $err) = $ldap->all_hosts;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;

  ########################
  # RADIUS related stuff #
  ########################
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{rad_groups},
		  filter => '(cn=*)' };
  # $self->h_log($search_arg);
  my $search = $ldap->search( $search_arg );
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
      next unless $_->size;
      my $n = $_->name;
      $n =~ s/_binary/;binary/;
      $p->{$n} = $_->slurp;
    }
  }

  ##########################
  # form fields validation #
  ##########################
  # $self->h_log($self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{data_fields});
  my $v = $self->validation;
  return $self->render(template => 'protected/profile/newsvc') unless exists $p->{authorizedService};
  foreach (@{$self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{data_fields}}) {
    next if $_ eq 'description';
    if ( $_ eq 'associatedDomain' ) {
      $v->error(associatedDomain  => ['Domain is not set, it is mandatory!']) unless exists $p->{associatedDomain};
    } elsif ( $_ eq 'userPassword' ) {
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

  ##############################
  # service related validation #
  ##############################
  if ( $p->{authorizedService} eq 'gitlab' && ! $root->exists('mail') ) {
    # gitlab service depends on mail attribute root object
    $v->error( login => [ 'Missing required attribute mail in root object, fix before proceeding.' ] );
  } elsif ( $p->{authorizedService} eq 'ssh-acc' && ! exists $p->{sshKeyText} && ! exists $p->{sshKeyFile} ) {
    $v->error( sshKeyFile => [ 'At least ssh key file or ssh key string is expected.' ] );
    $v->error( sshKeyText => [ 'At least ssh key file or ssh key string is expected.' ] );
  } elsif ( $p->{authorizedService} eq 'ovpn' ) {
    $v->error( userCertificate_binary => [ 'Certificate is mandatory.' ] ) unless exists $p->{'userCertificate;binary'};
    $v->error( umiOvpnCfgIfconfigPush => [ 'IP endpoints for client tunnel are mandatory.' ] ) unless exists $p->{umiOvpnCfgIfconfigPush};
    $v->error( umiOvpnAddDevOS => [ 'OS of device is expected.' ] ) unless exists $p->{umiOvpnAddDevOS};
    $v->error( umiOvpnAddDevType => [ 'Type of device is expected.' ] ) unless exists $p->{umiOvpnAddDevType};
  }

  if ( ! $v->has_error ) {

    #################
    # newsvc branch #
    #################
    my $br = $self->h_branch_add_if_not_exists($p, $ldap, $root, \%debug);
    # $self->h_log(\%debug);

    ##################
    # newsvc account #
    ##################
    my $svc = $self->h_service_add_if_not_exists($p, $ldap, $root, $br, \%debug);
    # $self->h_log(\%debug);
  }

  $self->stash( debug => \%debug );

  $self->render(template => 'protected/profile/newsvc');
}

1;
