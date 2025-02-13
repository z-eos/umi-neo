# -*- mode: cperl; eval(follow-mode); -*-

package Umi::Helpers::SearchResult;

use Mojo::Base 'Mojolicious::Plugin';

use Net::DNS;
use Net::LDAP::Util qw(generalizedTime_to_time);

sub register {
  my ($self, $app) = @_;

  $app->helper(
	       h_rewrite_dn => sub {
		 my ($c, $dn, $delim) = @_;
		 $delim = ' > ' if ! defined $delim;
		 my @x = split(/,/, $dn);
		 if ( $dn !~ /^.*,cn=accesslog$/ ) {
		   pop @x;
		   pop @x;
		 }
		 my @y = map { substr($_, index($_, '=') + 1) } @x;
		 return join($delim, @y);
	       });

  $app->helper(
	       h_dn_color => sub {
		 my ($c, $e) = @_;

		 if ( $e->exists('gidNumber') &&
		      $e->get_value('gidNumber') eq $app->{cfg}->{ldap}->{defaults}->{group_blocked_gidnumber} ) {
		   return 'danger';
		 } elsif ( $e->dn =~ /^cn=.*,authorizedService=ovpn@.*/ && $e->exists('umiUserCertificateNotAfter') &&
			   time > generalizedTime_to_time($e->get_value('umiUserCertificateNotAfter') . 'Z') ) {
		   return 'danger';
		 } elsif ( $e->dn =~ /^pgpCertID=.*,$app->{cfg}->{ldap}->{base}->{pgp}/ &&
			   time > generalizedTime_to_time($e->get_value('pgpKeyExpireTime') . 'Z') ) {
		   return 'danger';
		 } elsif ( $e->dn =~ /^author/ ) {
		   return 'warning';
		 } elsif ( $e->dn =~ /^(cn|uid)=[^,]+,auth/ ) {
		   return 'success';
		 } elsif ( $e->dn =~ /^uid=[^,]+,ou=People,dc=/i ) {
		   return 'info';
		 } elsif ( $e->dn =~ /^.*,cn=accesslog$/ ) {
		   return 'info-subtle bg-opacity-25';
		 } else {
		   return 'secondary';
		 }
	       });

  $app->helper(
	       h_get_root_dn => sub {
		 my ($c, $dn) = @_;
		 my $root_dn;
		 my $re = qr/^.*(uid=[^,]+,$app->{cfg}->{ldap}->{base}->{acc_root})$/i;
		 $root_dn = $1 if $dn =~ /$re/;
		 return $root_dn;
	       });


=head1 h_attr_unused

expected arguments: entry object and a hash by objectclasses and may/must arguments for each objectclass

returns a list of each objectclass attributes (both 'must' and 'may')
across all objectclasses of the entry, excluding attributes that are
already present

=cut

  $app->helper(
	       h_attr_unused => sub {
		 my ($c, $e, $s) = @_;
		 my $au;
		 foreach my $oc (@{$e->get_value('objectClass', asref => 1)}) {
		   if ( exists $s->{$oc}->{must} ) {
		     $au->{$_} = 0 foreach (@{$s->{$oc}->{must}});
		   }
		   if ( exists $s->{$oc}->{may} ) {
		     $au->{$_} = 0 foreach (@{$s->{$oc}->{may}});
		   }
		 }
		 foreach my $a ($e->attributes) {
		   $a =~ s/;binary//;
		   delete $au->{$a};
		 }
		 return sort(keys %$au);
	       });

=head2 h_dns_resolver

Net::DNS wrapper to resolve A, MX and PTR mainly
on input:

    fqdn   - FQDN to resolve (types A, MX)
    type   - DNS query type (A, MX, PTR)
    name   - IP address to resolve
    legend - part of legend for debug

    Net::DNS::Resolver options
    debug          - default: 0
    force_v4       - default: 1
    persistent_tcp - default: 1
    persistent_udp - default: 1
    recurse        - default: 1
    retry          - default: 1
    tcp_timeout    - default: 1
    udp_timeout    - default: 1

=cut

  $app->helper(
	       h_dns_resolver => sub {
		 my ($self, $A) = @_;
		 my $a = { name           => $A->{name},
			     fqdn           => $A->{fqdn}           // $A->{name},
			     type           => $A->{type}           // 'PTR',
			     legend         => $A->{legend}         // '',
			     debug          => $A->{debug}          // 0,
			     force_v4       => $A->{force_v4}       // 1,
			     persistent_tcp => $A->{persistent_tcp} // 1,
			     persistent_udp => $A->{persistent_udp} // 1,
			     recurse        => $A->{recurse}        // 1,
			     retry          => $A->{retry}          // 1,
			     tcp_timeout    => $A->{tcp_timeout}    // 1,
			     udp_timeout    => $A->{udp_timeout}    // 1,
			   };

		 my $dns_rcode =
		   { NOERROR           => { dec =>  0, RFC => 1035, descr => 'No Error', },
		     FORMERR           => { dec =>  1, RFC => 1035, descr => 'Format Error', },
		     SERVFAIL          => { dec =>  2, RFC => 1035, descr => 'Server Failure', },
		     NXDOMAIN          => { dec =>  3, RFC => 1035, descr => 'Non-Existent Domain', },
		     NOTIMP            => { dec =>  4, RFC => 1035, descr => 'Not Implemented', },
		     REFUSED           => { dec =>  5, RFC => 1035, descr => 'Query Refused', },
		     YXDOMAIN          => { dec =>  6, RFC => 2136, descr => 'Name Exists when it should not',},
		     YXRRSET           => { dec =>  7, RFC => 2136, descr => 'RR Set Exists when it should not',},
		     NXRRSET           => { dec =>  8, RFC => 2136, descr => 'RR Set that should exist does not', },
		     NOTAUTH           => { dec =>  9, RFC => 2136, descr => 'Server Not Authoritative for zone', },
		     NOTZONE           => { dec => 10, RFC => 2136, descr => 'Name not contained in zone', },
		     BADVERS           => { dec => 16, RFC => 2671, descr => 'Bad OPT Version', },
		     BADSIG            => { dec => 16, RFC => 2845, descr => 'TSIG Signature Failure', },
		     BADKEY            => { dec => 17, RFC => 2845, descr => 'Key not recognized', },
		     BADTIME           => { dec => 18, RFC => 2845, descr => 'Signature out of time window', },
		     BADMODE           => { dec => 19, RFC => 2930, descr => 'Bad TKEY Mode', },
		     BADNAME           => { dec => 20, RFC => 2930, descr => 'Duplicate key name', },
		     BADALG            => { dec => 21, RFC => 2930, descr => 'Algorithm not supported', },
		     'query timed out' => { dec => '', RFC => '',   descr => 'query timed out'}, };

		 my $return;
		 my $r = new Net::DNS::Resolver(
						debug          => $a->{debug},
						force_v4       => $a->{force_v4},
						persistent_tcp => $a->{persistent_tcp},
						persistent_udp => $a->{persistent_udp},
						recurse        => $a->{recurse},
						retry          => $a->{retry},
						tcp_timeout    => $a->{tcp_timeout},
						udp_timeout    => $a->{udp_timeout},
					       );

		 if ( defined $self->{app}->{cfg}->{network}->{nameservers} ) {
		   $r->nameservers( $_ ) foreach ( @{$self->{app}->{cfg}->{network}->{nameservers}} );
		 }

		 my $rr = $r->search($a->{name});
		 $return->{errstr}  = $r->errorstring;

		 if ( defined $rr) {
		   foreach ($rr->answer) {
		     if ( $a->{type} eq 'PTR' ) {
		       $return->{success} = $_->ptrdname if $_->type eq $a->{type};
		     } elsif ( $a->{type} eq 'A' ) {
		       $return->{success} = $_->address if $_->type eq $a->{type};
		     } elsif ( $a->{type} eq 'MX' ) {
		       my @mx_arr = mx( $r, $a->{fqdn} );
		       if (@mx_arr) {
			 $return->{success} = $mx_arr[0]->exchange;
		       }
		     }

		     if ( $return->{errstr} ne 'NOERROR' ) {
		       $return->{error}->{html} = sprintf("<i class='h6'>dns_resolver()</i>: %s %s: %s ( %s )",
							  $a->{fqdn},
							  $a->{legend},
							  $dns_rcode->{ $r->errorstring }->{descr},
							  $r->errorstring );
		       $return->{error}->{errdescr} = $dns_rcode->{ $r->errorstring }->{descr};
		       $return->{error}->{errcode}  = $dns_rcode->{ $r->errorstring }->{dec};
		       $return->{error}->{errstr}   = $r->errorstring;
		     }

		   }
		 } else {
		   if ( $return->{errstr} ne 'NOERROR') {
		     $return->{error}->{html} = sprintf("<i class='h6'>dns_resolver()</i>: %s %s: %s ( %s )",
							$a->{fqdn},
							$a->{legend},
							$dns_rcode->{ $r->errorstring }->{descr} // 'NA',
							$r->errorstring // 'NA' );
		     $return->{error}->{errdescr} = $dns_rcode->{ $r->errorstring }->{descr};
		     $return->{error}->{errstr}   = $r->errorstring;
		   }
		 }

		 $return->{errcode} = $dns_rcode->{ $r->errorstring }->{descr}
		   if exists $return->{errstr};

		 # p $a->{fqdn}; p $r;
		 # $self->h_log( $return );
		 return $return;
	       });

}

1;
