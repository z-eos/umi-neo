# -*- mode: cperl; eval: (follow-mode 1); -*-

package Umi::Controller::Public;

use Mojo::Base 'Umi::Controller', -signatures;
use Mojo::Util qw( dumper b64_decode );

use Umi::Ldap;

sub do_login ($self) {

  if ($self->req->method eq 'POST') {
    my $username = $self->param('username');
    my $password = $self->param('password');

    # $self->h_log(sprintf("DEBUG: uid<%s> pwd<%s>", $username, $password));

    ## NB
    # the very authentication is a result of bind with credentials provided
    # the bind is done here, though the check is being done in
    # Umi::Authentication::validate_user() which is called by
    # Mojolicious::Plugin::Authentication::authenticate()
    my $ldap = Umi::Ldap->new( $self->{app}, $username, $password );
    # $self->h_log($ldap->{ldap});
    if ($self->authenticate($username, $password, {ldap => $ldap->ldap})) {
      my ($search_arg, $search, $user_obj, $role, %privileges);

      ### user's role
      $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		      filter => '(uid=' . $username . ')',
		      scope => 'one',
		      attrs => [qw(uid givenName sn cn gecos mail title description)] };
      $search = $ldap->search($search_arg);
      if ( $search->code ) {
	$self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) );
	$self->session( debug => { error => ['Authentication failed'] } );
	return $self->redirect_to('public_root');
      }

      my $e = $search->entry;
      %$user_obj = map { lc($_) => $e->get_value($_) // '' } @{[$e->attributes]};
      $user_obj->{dn} = $e->dn;

      ### user's role
      $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{system_role},
		      filter => '(memberUid=' . $username . ')',
		      attrs => ['cn'] };
      $search = $ldap->search($search_arg);
      $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
      $role = $search->count ? $search->entry->get_value('cn') : 'missing';
      $self->{app}->h_log( 'WARNING: user has no role' ) if ! defined $role;

      ### user's privileges
      $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{system_priv},
		      filter => '(memberUid=' . $username . ')',
		      attrs => ['cn'] };
      $search = $ldap->search($search_arg);
      $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
      %privileges = map { $_->get_value('cn') => 1 } $search->entries if $search->count;
      $privileges{missing} = 1 if ! %privileges;

      $self->set_user_session({ uid => $username,
				pwd => $password,
				# debug => { ok => ["Successful login as $username"] },
				user_obj => $user_obj,
				role => $role,
				privileges => \%privileges });
      $self->log->info(sprintf("=== connect from %s, user %s logged in", $self->tx->remote_address, $username));
      return $self->redirect_to('protected_root');
    }
  }

  $self->session( debug => { error => ['Authentication failed'] } );
  return $self->redirect_to('public_root');
}

sub do_logout ($self) {
  $self->log->info(sprintf("user %s logged out", $self->session->{uid}));
  $self->logout;
  $self->session(expires => 1);
  return $self->redirect_to('/');
}

sub homepage ($self) {
  if ($self->session('debug')) {
    $self->stash( debug => $self->session('debug') );
    delete $self->session->{debug};
  }
  return $self->render(template => 'public/home');
}

sub other ($self) {
  return $self->render(template => 'public/other');
}

=head1 get_gpg_keys

public (BASIC AUTH) endpoint to get GPG key by keyword matched against a
value of pgpUserID attribute

curl -X GET -u uid=john,ou=People,dc=foo,dc=bar:*** -H "Content-Type: application/json" -d @FILE.json -s http://10.0.0.1:3000/public/gpg/john@foo | jq


=cut

sub get_gpg_key ($self) {
  my ($filter, $state );

  my $ldap = $self->h_auth_basic;

  if ( defined $ldap ) {
    my $key = $self->stash->{key};
    $self->h_log($key);
    return $self->render(json => {})
      unless defined $key
      && $key =~ /^[[:alnum:] _\-@.,]+$/;

    if ($key ne '') {
      $filter = sprintf("(pgpUserID=*%s*)", $self->stash->{key});
    }
    # $self->h_log($self->stash->{key});

    my $attrs = [qw(pgpCertID pgpKeyID pgpUserID pgpKeyCreateTime pgpKeyExpireTime pgpKey)];
    my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{pgp},
		       filter => $filter,
		       attrs => $attrs};
    my $search = $ldap->search( $search_arg );
    $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

    my %gpg;
    my $now = localtime;
    foreach ($search->entries) {
      my $exp_ts = $_->get_value('pgpKeyExpireTime') if $_->exists('pgpKeyExpireTime');
      # $self->h_log($exp_ts);
      my $exp = Time::Piece->strptime($exp_ts, '%Y%m%d%H%M%SZ') if defined $exp_ts;

      next if $self->stash->{key} eq 'active'  && defined $exp && $now > $exp;
      next if $self->stash->{key} eq 'expired' && ((defined $exp && $now < $exp) || ! defined $exp);

      $gpg{$_->get_value('pgpCertID')} = {
					  pgpKeyID => $_->get_value('pgpKeyID'),
					  pgpUserID => $_->get_value('pgpUserID'),
					  pgpKeyCreateTime => $_->get_value('pgpKeyCreateTime'),
					  pgpKeyExpireTime => $exp_ts // '',
					  pgpKey => $_->get_value('pgpKey'),
					 };
    }

    return $self->render(json => \%gpg);
  }
}

1;
