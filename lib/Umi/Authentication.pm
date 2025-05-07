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
  # $self->{app}->h_log("Authentication.pm: validate_user() HAS BEEN CALLED");
  # $self->{app}->h_log($extra->{ldap});
  if ( defined $extra->{ldap} ) {
    if ( $extra->{ldap}->isa('Net::LDAP') ) {
      return $username;
    } else {
      # $self->{app}->h_log($extra->{ldap});
      # $self->{app}->h_log( $self->{app}->h_ldap_err($extra->{ldap}, {}) );
    }
  } else {
      my $msg = 'ERROR: not defined $extra->{ldap}';
      $self->{app}->h_log($msg);
  }
}

1;
