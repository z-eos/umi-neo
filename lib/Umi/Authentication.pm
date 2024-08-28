package Umi::Authentication;
use Mojo::Base qw< -base -signatures >;

use Net::LDAP qw/LDAP_INVALID_CREDENTIALS/;

# to rm # # In this example we assume that our users have username (which double
# to rm # # down as user identifiers too) and password.
# to rm # has 'db' => sub {
# to rm #     return {
# to rm # 	map { $_->{username} => $_ }
# to rm # 	{ name => 'Foo Ish' => username => foo    => password => 123 },
# to rm # 	{ name => 'Bar Ong' => username => bar    => password => 456 },
# to rm # 	{ name => 'Baz Ing' => username => baz    => password => 789 },
# to rm # 	{ name => 'Gal Ook' => username => galook => password => 0   },
# to rm #     };
# to rm # };

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
    return $self->{app}->{cfg}->{ldap}->{user}->{as_struct};
}

# this function takes the parameters provided and makes sure that the
# password is the right one for the username.
sub validate_user ($self, $username, $password, $extra) {
    # return the user identifier if the password check is good
    # return $username if $self->password_is_right($username, $password);

    my $ldap = Net::LDAP->new( $self->{app}->{cfg}->{ldap}->{store}->{ldap_server} );
    if ( ! defined $ldap ) {
	p $@;
	$self->{app}->{log}->error("Error connecting to $self->{app}->{cfg}->{ldap}->{store}->{ldap_server}");
	return 0;
    }
    
    my $mesg = $ldap->bind(
	sprintf("uid=%s,%s",
		$username,
		$self->{app}->{cfg}->{ldap}->{store}->{user_basedn}),
	password => $password,
	version  => 3,);
    if ( $mesg->is_error ) {
	$self->{app}->{log}->error(sprintf("code: %s; message: %s; text: %s",
				  $mesg->code,
				  $mesg->error_name,
				  $mesg->error_text ));
	return $mesg->code == LDAP_INVALID_CREDENTIALS ? 0	: 1;
    }
    
    my $search = $ldap->search(
	base => $self->{app}->{cfg}->{ldap}->{store}->{user_basedn},
	filter => join('=',
		       $self->{app}->{cfg}->{ldap}->{store}->{user_field},
		       $username),
	scope => "one"
	);
    if ( $search->code ) {
	$self->{app}->{log}->error(sprintf("code: %s; message: %s; text: %s",
				  $search->code,
				  $search->error_name,
				  $search->error_text
			  ));
	return $search->code == LDAP_INVALID_CREDENTIALS ? 0	: 1;
    } elsif ( $search->count != 1 ) {
	$self->{app}->{log}->error(sprintf("there are %d users with uid %s",
					   $search->count,
					   $username
				   ));
	return 0;
    }

    
    $self->{app}->{cfg}->{ldap}->{user}->{as_struct} = $search->as_struct;
    $self->{app}->{cfg}->{ldap}->{user}->{entry} = $search->pop_entry;

    return $username;
}


# to rm # ########################################################################
# to rm # #### methods below are specific for the user database technology    ####
# to rm # 
# to rm # sub get_user_from_db ($self, $userid) {
# to rm #     # In a LDAP setup, this is where we query the directory to get the
# to rm #     # user's record with the attributes we're interested into.
# to rm # 
# to rm #     # But we're using a hash here, so...
# to rm #     my $user = $self->db->{$userid} or return;
# to rm #     return { $user->%*, password => '***' };  # protect the record
# to rm # }
# to rm # 
# to rm # # sub get_user_from_db ($self, $userid) {
# to rm # #    # In a LDAP setup, this is where we query the directory to get the
# to rm # #    # user's record with the attributes we're interested into.
# to rm # 
# to rm # #    # But we're using a hash here, so...
# to rm # #    my $user = $self->db->{$userid} or return;
# to rm # #    return { $user->%*, password => '***' };  # protect the record
# to rm # # }
# to rm # 
# to rm # sub password_is_right ($self, $username, $password) {
# to rm #     # In a LDAP setup, this is where we ask the directory to check the
# to rm #     # provided username/password pair.
# to rm #     warn "password_is_right <$username>/<$password>";
# to rm #     # But we're using a hash here, so...
# to rm #     my $user = $self->db->{$username} or return;
# to rm #     warn "password_is_right <$password> vs $user->{password}>";
# to rm #     return $user->{password} eq $password;
# to rm # }

1;