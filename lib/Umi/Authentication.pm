# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Authentication;

use Mojo::Base qw( -base -signatures );

sub new {
    my ($class, $app) = @_;
    my $self = bless {}, $class;
    $self->{app} = $app;
    return $self;
}

sub load_user ($self, $uid) {
    # $self->{app}->h_log("Authentication.pm: load_user() HAS BEEN CALLED");
    return $uid
}

sub validate_user ($self, $username, $password, $extra) {
  $self->{app}->h_log("Authentication.pm: validate_user() HAS BEEN CALLED");
  # $self->{app}->h_log($extra->{ldap});
  return $username if defined $extra->{ldap} && $extra->{ldap}->isa('Net::LDAP');
}

1;
