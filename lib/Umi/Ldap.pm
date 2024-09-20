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

use Try::Tiny;

sub new {
  my ($class, $app, $uid, $pwd) = @_;
  my $self =
    bless {
	   app => $app,
	   uid => $uid,
	   pwd => $pwd,
	  }, $class;

  my $cf = $self->{app}->{cfg}->{ldap};
  $self->{app}->h_log('Umi::Ldap->ldap() HAS BEEN CALLED');

  my $ldap = Net::LDAP->new( $cf->{conn}->{host} );
  if ( ! defined $ldap ) {
    $self->{app}->h_log("Error connecting to $cf->{conn}->{host}: $@");
    return undef;
  }
    
  my $m = $ldap->bind(sprintf("uid=%s,%s",
			      $self->{uid},
			      $cf->{base}->{acc_root}),
		      password => $self->{pwd},
		      version  => 3,);
  if ( $m->is_error ) {
    $self->{app}->h_log(sprintf("Ldap.pm: ldap(): code: %s; mesg: %s; txt: %s",
				$m->code, $m->error_name, $m->error_text) );
      return $m;
  }

  if ( exists $cf->{conn}->{start_tls} ) {
    # $self->{log}->debug(dumper($cf->{conn}->{start_tls}));
    $m = try {
      $ldap->start_tls(
		       verify     => $cf->{conn}->{start_tls}->{verify},
		       cafile     => $cf->{conn}->{start_tls}->{cafile},
		       checkcrl   => $cf->{conn}->{start_tls}->{checkcrl},
		       sslversion => $cf->{conn}->{start_tls}->{sslversion},
		      );
    }
    catch {
      $self->{app}->h_log("Net::LDAP start_tls error: $@") if $m->error;
      return $m;
    }
  }
  # $self->{log}->debug(dumper($mesg));

  $self->{ldap} = $ldap;

  return $self;
}

# sub new {
#   my ($class, $app, $uid, $pwd) = @_;
#   my $self =
#     bless {
# 	   app => $app,
# 	   uid => $uid,
# 	   pwd => $pwd,
# 	  }, $class;
#   return $self;
# }

# sub ldap ($self) {
#   my $cf = $self->{app}->{cfg}->{ldap};
#   $self->{app}->h_log('Umi::Ldap->ldap() HAS BEEN CALLED');

#   my $ldap = Net::LDAP->new( $cf->{conn}->{host} );
#   if ( ! defined $ldap ) {
#     $self->{app}->h_log("Error connecting to $cf->{conn}->{host}: $@");
#     return undef;
#   }
    
#   my $m = $ldap->bind(sprintf("uid=%s,%s",
# 			      $self->{uid},
# 			      $cf->{base}->{acc_root}),
# 		      password => $self->{pwd},
# 		      version  => 3,);
#   if ( $m->is_error ) {
#     $self->{app}->h_log(sprintf("Ldap.pm: ldap(): code: %s; mesg: %s; txt: %s",
# 				$m->code, $m->error_name, $m->error_text) );
#       return $m;
#   }

#   if ( exists $cf->{conn}->{start_tls} ) {
#     # $self->{log}->debug(dumper($cf->{conn}->{start_tls}));
#     $m = try {
#       $ldap->start_tls(
# 		       verify     => $cf->{conn}->{start_tls}->{verify},
# 		       cafile     => $cf->{conn}->{start_tls}->{cafile},
# 		       checkcrl   => $cf->{conn}->{start_tls}->{checkcrl},
# 		       sslversion => $cf->{conn}->{start_tls}->{sslversion},
# 		      );
#     }
#     catch {
#       $self->{app}->h_log("Net::LDAP start_tls error: $@") if $m->error;
#       return $m;
#     }
#   }
#   # $self->{log}->debug(dumper($mesg));

#   return $ldap;
# }

sub ldap ($self) {
  return $self->{ldap};
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

  # $self->{log}->debug(dumper($o));

  return $self->ldap->search( %{$o} );
}

sub schema ($self) {
  return $self->ldap->schema();
}

1;
