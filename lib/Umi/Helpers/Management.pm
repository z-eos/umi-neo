# -*- mode: cperl; eval(follow-mode); -*-

package Umi::Helpers::Management;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util qw( b64_decode );

use Net::LDAP::Util qw(generalizedTime_to_time);
use Net::LDAP::Constant qw( LDAP_COMPARE_FALSE LDAP_COMPARE_TRUE );

sub register {
  my ($self, $app) = @_;

=head2 h_healthcheck

Simple healthcheck. It uses predefined in config file credentials for quering LDAP.
Returns a simple health status hash with HTTP status:

{

=over 4

=item status  => I<NUM>    # 200 = healthy, 500 = failed

=item message => I<STRING> # commentary

=back

}

=cut

  $app->helper( h_healthcheck => sub {
		  my $self = shift;
		  my $res;
		  my $cf = $self->{app}->{cfg}->{ldap}->{conn}->{management};
		  # $self->h_log($cf);

		  my $ldap = Umi::Ldap->new( $self->{app}, $cf->{binddn}, $cf->{bindpw}, 1 );

		  return { status => 500, message => $ldap }
		    unless ( ref($ldap->ldap) eq 'Net::LDAP' );

		  my $mesg = $ldap->compare( $cf->{healthcheck_dn},
					     $cf->{healthcheck_attr},
					     $cf->{healthcheck_value} );

		  if ( $mesg->code == LDAP_COMPARE_TRUE ) {
		    $res = { status => 200, message => 'OK' };
		  } else {
		    $res = { status => 500,
			     message => sprintf('FATAL: %s (%d): %s',
						$mesg->error_name,
						$mesg->code,
						$mesg->error_text) };
		  }
		  return $res;
		}
	     );


  ### END OF REGISTER --------------------------------------------------------------------------------------------
}

1;
