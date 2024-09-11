# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Ldap;

use Mojo::Base qw( -base -signatures );
use Mojo::Log;
use Mojo::Util qw( dumper );

use Net::LDAP;
use Net::LDAP::Schema;
use Net::LDAP::Constant qw(
			    LDAP_SUCCESS
			    LDAP_PROTOCOL_ERROR
			    LDAP_NO_SUCH_OBJECT
			    LDAP_INVALID_DN_SYNTAX
			    LDAP_INSUFFICIENT_ACCESS
			    LDAP_CONTROL_SORTRESULT
			 );
use Net::LDAP::Util qw(
			ldap_error_text
			ldap_error_name
			ldap_error_desc
			ldap_explode_dn
			escape_filter_value
			canonical_dn
			generalizedTime_to_time
			time_to_generalizedTime
		     );

use Data::Printer;

sub new {
  my ($class, $app, $uid, $pwd) = @_;
  my $self =
    bless {
	   app => $app,
	   uid => $uid,
	   pwd => $pwd,
	   log => Mojo::Log->new
	  }, $class;
  return $self;
}

sub ldap ($self) {

  $self->{log}->debug('Umi::Ldap->ldap() HAS BEEN CALLED');

  my $ldap = Net::LDAP->new( $self->{app}->{cfg}->{ldap}->{conn}->{host} );
  if ( ! defined $ldap ) {
    $self->{log}->error("Error connecting to $self->app->{cfg}->{ldap}->{store}->{ldap_server}: $@");
    return undef;
  }
    
  my $m = $ldap->bind(
		      sprintf("uid=%s,%s",
			      $self->{uid},
			      $self->{app}->{cfg}->{ldap}->{base}->{acc_root}),
		      password => $self->{pwd},
		      version  => 3,);
  if ( $m->is_error ) {
    $self->log->error(
		      sprintf("code: %s; mesg: %s; txt: %s", $m->code, $m->error_name, $m->error_text)
		     );
    return undef;
  }

  return $ldap;
}

sub search {
  my ($self, $a) = @_;
  my $cf = $self->{app}->{cfg}->{ldap};
  my $o =
    {
     base   => $a->{base}   // $cf->{base}->{dc},
     attrs  => $a->{attrs}  // $cf->{defaults}->{attrs},
     deref  => $a->{deref}  // $cf->{defaults}->{deref},
     filter => $a->{filter} // $cf->{defaults}->{filter},
     scope  => $a->{scope}  // $cf->{defaults}->{scope},
     sizelimit => $a->{sizelimit} // $cf->{defaults}->{sizelimit},
    };

  #$self->{log}->debug(dumper($o));

  return $self->ldap->search( %{$o} );
}

sub schema ($self) {
  return $self->ldap->schema();
}

1;
