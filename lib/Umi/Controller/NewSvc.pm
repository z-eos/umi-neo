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
  my %schema_all_attributes = map { $_->{name} => $_ } $ldap->schema->all_attributes;

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
  my $root = $search->entry;

  $self->stash( dn_to_new_svc => $p->{dn_to_new_svc},
		root => $root,
		schema => \%schema_all_attributes,
		domains => $domains,
		rad_groups => $rad_groups,
		rad_profiles => $rad_profiles );

  my $uploads = $self->req->uploads;
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
  return $self->render(template => 'protected/tool/newsvc') unless exists $p->{authorizedService};
  foreach (@{$self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{data_fields}}) {
    next if $_ eq 'description';
    if ( $_ eq 'userPassword' ) {
      # $v->required('password1');
      # $v->required('password2');
      # $v->error( password1 => [ 'field password1 is required' ] ) if ! exists $p->{password1};
      # $v->error( password2 => [ 'field password2 is required' ] ) if ! exists $p->{password2};
      $v->error( password1 => [ 'new password and its confirmation do not match' ] )
	if exists $p->{password1} && exists $p->{password2} && $p->{password1} ne $p->{password2};
    } else {
      # # $self->h_log($_);
      # $v->required($_);
      # # $v->error( $_ => ['reuired'] ) if $v->error($_);
      # $v->error( $_ => [ 'field ' . $_ . ' is required'] ) if ! exists $p->{$_};
    }
  }

  $self->h_log($p);
  my $msg;
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
      { uid => sprintf('%s@%s_%s',
		       $p->{authorizedService},
		       $p->{associatedDomain},
		       exists $p->{login} ? $p->{login} : lc(sprintf("%s.%s", $root->get_value('givenName'), $root->get_value('sn')))
		      ),
	objectClass       => [ @{$self->{app}->{cfg}->{ldap}->{objectClass}->{acc_svc_branch}} ],
	associatedDomain  => $p->{associatedDomain},
	authorizedService => sprintf('%s@%s',
				     $p->{authorizedService},
				     $p->{associatedDomain}), };

    $msg = $ldap->add( $br_dn, $br_attrs );
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
		       $self->{app}->{cfg}->{ldap}->{defaults}->{rdn},
		       exists $p->{login} ? $p->{login} : lc(sprintf("%s.%s", $root->get_value('givenName'), $root->get_value('sn'))),
		       $br_dn
		      );

  my %objectclasses = map { $_->{name} => $_ } $ldap->schema->all_objectclasses;
  my ($schema, $all_sup, $svc_attrs_must, $svc_attrs_may);
  $schema = $ldap->schema;
  foreach my $oc_name (@{$self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{objectClass}}) {
    $all_sup->{$oc_name} = 1;
    my @sup = $ldap->get_all_superior_classes($schema, $oc_name);
    $all_sup->{$_} = 1 for @sup;
  }
  # $self->h_log($all_sup);
  foreach my $oc (keys(%$all_sup)) {
    if ( exists $objectclasses{$oc}->{must} ) {
      foreach (@{$objectclasses{$oc}->{must}}) {
	if ( $_ eq 'userid' ) {
	  $svc_attrs_must->{uid}++;
	} else {
	  $svc_attrs_must->{$_}++;
	}
      }
    }
    if ( exists $objectclasses{$oc}->{may} ) {
      foreach (@{$objectclasses{$oc}->{may}}) {
	next if ! exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$_};
	if ( $_ eq 'userid' ) {
	  $svc_attrs_may->{uid}++;
	} else {
	  $svc_attrs_may->{$_}++;
	}
      }
    }
  }
  $self->h_log($svc_attrs_must);
  $self->h_log($svc_attrs_may);

  my $uidNumber_last;
  if (exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{last_num_filter}) {
    $uidNumber_last = $ldap->last_num(
				      undef,
				      $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{last_num_filter},
				      undef,
				      'sub'
				     );
  } else {
    $uidNumber_last = $ldap->last_num;
  }

  my $pwd = $self->h_pwdgen;
  my $svc_attrs;
  $svc_attrs->{objectClass} = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{objectClass};
  foreach my $df (@{$self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{data_fields}}) {
    if ( $df eq 'login' ) {
      $svc_attrs->{uid} = defined $p->{$df} ? $p->{$df} : lc(sprintf("%s.%s", $root->get_value('givenName'), $root->get_value('sn')));
    } elsif ( $df eq 'userPassword' ) {
      $svc_attrs->{userPassword} = exists $p->{password2} ? $p->{password2} : $pwd->{ssha};
    } elsif ( $df eq 'sshKeyText' || $df eq 'sshKeyFile' ) {
      push @{$svc_attrs->{sshPublicKey}}, $p->{$df} if $p->{$df} ne '';
    } elsif ( ! exists $p->{$df} ) {
      if (exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$df . '_prefix'}) {
	$svc_attrs->{$df} = sprintf("%s/%s.%s",
				    $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$df . '_prefix'},
				    lc $root->get_value('givenName'),
				    lc $root->get_value('sn'));
      } elsif (exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$df}) {
	$svc_attrs->{$df} = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$df};
      }
    } else {
      $svc_attrs->{$df} = $p->{$df};
    }
  }

  #---------------------------------------------------------------------
  # substitution for keywords like: `%...%`, used in config file
  #---------------------------------------------------------------------
  my %replace;
  $replace{'%uid%'} = $svc_attrs->{uid};
  $replace{'%associatedDomain%'} = $svc_attrs->{associatedDomain} if exists $svc_attrs->{associatedDomain};
  $replace{'%givenName%'} = $root->get_value('givenName'),
  $replace{'%sn%'} = $root->get_value('sn') // 'NA';
  foreach (keys(%$svc_attrs_must)) {
    next if exists $svc_attrs->{$_};
    if ( $_ eq 'uidNumber' ) {
      $svc_attrs->{$_} = $uidNumber_last->[0] + 1;
    } elsif (exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$_}) {
      $svc_attrs->{$_} = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$_};
      $svc_attrs->{$_} =~ s/%(\w+)%/exists $replace{"%$1%"} ? $replace{"%$1%"} : $&/ge;
    } else {
      $svc_attrs->{$_} = undef;
      $self->h_log('ERROR: absent must attribute: ' . $_);
    }
  }
  foreach (keys(%$svc_attrs_may)) {
    next if exists $svc_attrs->{$_} || ! exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$_};
    $svc_attrs->{$_} = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$_};
    $svc_attrs->{$_} =~ s/%(\w+)%/exists $replace{"%$1%"} ? $replace{"%$1%"} : $&/ge;
  }

  $self->h_log($svc_attrs);

  $msg = $ldap->add( $svc_dn, $svc_attrs );
  if ( $msg ) {
    push @{$debug->{$msg->{status}}}, $msg->{message};
    push @{$debug->{$msg->{status}}}, sprintf('password: <span class="badge text-bg-secondary user-select-all">%s</span>', $pwd->{clear}) if $msg->{status} eq 'ok';
  }
  $self->h_log($debug);

  $self->stash( debug => $debug );

  $self->render(template => 'protected/tool/newsvc');
}

1;
