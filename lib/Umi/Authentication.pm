package Umi::Authentication;
use Mojo::Base qw< -base -signatures >;

use Net::LDAP qw/LDAP_INVALID_CREDENTIALS/;

# In this example we assume that our users have username (which double
# down as user identifiers too) and password.
has 'db' => sub {
    return {
	map { $_->{username} => $_ }
	{ name => 'Foo Ish' => username => foo    => password => 123 },
	{ name => 'Bar Ong' => username => bar    => password => 456 },
	{ name => 'Baz Ing' => username => baz    => password => 789 },
	{ name => 'Gal Ook' => username => galook => password => 0   },
    };
};

sub new {
    my ($class, $app) = @_;
    my $self = bless {}, $class;
    $self->{app} = $app;
    return $self;
}

# the methods below might be compacted into two
# (load_user+get_user_from_db, validate_user+password_is_right) but we
# keep them separated for sake of clarity about what the plugin
# interface needs and what we need to do towards our user database

# In theory, we might keep load_user and validate_user as coded below,
# and only hack on get_user_from_db and password_is_right to adapt the
# implementation to any LDAP querying need.


# this function takes a user identifier (same as username for us) and
# returns the user's object.
sub load_user ($self, $id) {
    my $user = $self->get_user_from_db($id);
    return $user;
}

use Data::Printer;

# this function takes the parameters provided and makes sure that the
# password is the right one for the username.
sub validate_user ($self, $username, $password, $extra) {
    # return the user identifier if the password check is good
    # return $username if $self->password_is_right($username, $password);
    p $self->{app}->{cfg};
    my $ldap = Net::LDAP->new( $self->{app}->{cfg}->{ldap}->{store}->{ldap_server} ) ||
	$self->{app}->{log}->warn("Couldn't connect to LDAP server $self->{app}->{cfg}->{ldap}->{store}->{ldap_server}: $@"), return;

    my $mesg = $ldap->bind(
	sprintf("uid=%s,%s",
		$username,
		$self->{app}->{cfg}->{ldap}->{store}->{user_basedn}),
	password => $password,
	version  => 3,);
    $mesg->code &&
	$self->log->error(sprintf("code: %s; message: %s; text: %s",
				  $mesg->code,
				  $mesg->error_name,
				  $mesg->error_text ));

    my $search = $ldap->search(
	base => $self->{app}->{cfg}->{ldap}->{store}->{user_basedn},
	filter => join('=',
		       $self->{app}->{cfg}->{ldap}->{store}->{user_field},
		       $username),
	);
    
    my $entry = $search->pop_entry();
    if ( $entry->code ) {
	$self->log->error(sprintf("code: %s; message: %s; text: %s",
				  $entry->code,
				  $entry->error_name,
				  $entry->error_text
			  ));
    } else {
	$self->{app}->{cfg}->{ldap}->{user_entry} = $entry->as_struct;
    }
    use Data::Printer;
    p $self->{app}->{cfg}->{ldap}->{user_entry};
    return unless $self->{app}->{cfg}->{ldap}->{user_entry}; # does user exist?

    # return 1 on success, 0 on failure with the ternary operator
    return $entry->code == LDAP_INVALID_CREDENTIALS ? 0	: 1;
}


########################################################################
#### methods below are specific for the user database technology    ####

sub get_user_from_db ($self, $userid) {
    # In a LDAP setup, this is where we query the directory to get the
    # user's record with the attributes we're interested into.

    # But we're using a hash here, so...
    my $user = $self->db->{$userid} or return;
    return { $user->%*, password => '***' };  # protect the record
}

# sub get_user_from_db ($self, $userid) {
#    # In a LDAP setup, this is where we query the directory to get the
#    # user's record with the attributes we're interested into.

#    # But we're using a hash here, so...
#    my $user = $self->db->{$userid} or return;
#    return { $user->%*, password => '***' };  # protect the record
# }

sub password_is_right ($self, $username, $password) {
    # In a LDAP setup, this is where we ask the directory to check the
    # provided username/password pair.
    warn "password_is_right <$username>/<$password>";
    # But we're using a hash here, so...
    my $user = $self->db->{$username} or return;
    warn "password_is_right <$password> vs $user->{password}>";
    return $user->{password} eq $password;
}

1;
