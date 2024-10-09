# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Controller::Public;

use Mojo::Base 'Umi::Controller', -signatures;
use Mojo::Util qw( dumper );

use Umi::Ldap;

sub do_login ($self) {

  if ($self->req->method eq 'POST') {
    my $username = $self->param('username');
    my $password = $self->param('password');

    $self->h_log(sprintf("DEBUG: uid<%s> pwd<%s>", $username, $password));

    ## NB
    # the very authentication is a result of bind with credentials provided
    # the bind is done here, though the check is being done in
    # Umi::Authentication::validate_user() which is called by
    # Mojolicious::Plugin::Authentication::authenticate()
    my $ldap = Umi::Ldap->new( $self->{app}, $username, $password );
    # $self->h_log($ldap);
    if ($self->authenticate($username, $password, {ldap => $ldap->ldap})) {
      my ($search_arg, $search, $user_obj, $role, %privileges);

      ### user's role
      $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		      filter => '(uid=' . $username . ')',
		      scope => 'one',
		      attrs => [qw(uid givenName sn cn gecos title description)] };
      $search = $ldap->search($search_arg);
      $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
      my ($k, $v) = each %{$search->as_struct};
      $user_obj = $v;
      $user_obj->{dn} = $k;

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
				user_obj => $user_obj,
				role => $role,
				privileges => \%privileges });
      $self->stash({uid => $username => pwd => $password});
      $self->stash(message => "Successful login as $username", status => 'ok');
      return $self->redirect_to('protected_root')
    }
  }

  $self->stash(message => 'Authentication error', status => 'error');
  return $self->redirect_to('public_root')
}

sub do_logout ($self) {
  $self->logout;
  $self->session(expires => 1);
  return $self->redirect_to('/');
}

sub homepage ($self) {
  return $self->render(template => 'public/home');
}

sub other ($self) {
  return $self->render(template => 'public/other');
}

1;
