package Umi::Authentication;

use Mojo::Base qw< -base -signatures >;

use Umi::Ldap;

sub new {
    my ($class, $app, $stash) = @_;
    my $self = bless {}, $class;
    $self->{app} = $app;
    return $self;
}

sub load_user ($self, $uid) {
    $self->{app}->{log}->debug("LOAD_USER() HAS BEEN CALLED");
    return $uid
}

sub validate_user ($self, $username, $password, $extra) {
    $self->{app}->{log}->debug("VALIDATE_USER() HAS BEEN CALLED");

    my $ldap = Umi::Ldap->new( $self->{app}, $username, $password );
    
    return $username if defined $ldap;
}

1;
