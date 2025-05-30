# -*- mode: cperl; eval(follow-mode); -*-

package Umi::Helpers::SearchResult;

use Mojo::Base 'Mojolicious::Plugin';

use Umi::Constants qw( DNS UMIAUTH );

use Net::DNS;
use Net::LDAP::Util qw(generalizedTime_to_time);

use POSIX qw(strftime);

sub register {
  my ($self, $app) = @_;

=head1 h_rewrite_dn

returns dn rewritten to be used in a header of the object on a search page

=cut

  $app->helper( h_rewrite_dn => sub {
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

=head1 h_dn_color

returns fa- class color to be used for the entr

=cut

  $app->helper( h_dn_color => sub {
		 my ($c, $e) = @_;
		 my $time = time;

		 if ( $e->exists('gidNumber') &&
		      $e->get_value('gidNumber') eq $app->{cfg}->{ldap}->{defaults}->{group}->{blocked}->{gidnumber} ) {
		   return 'danger';
		 } elsif ( $e->dn =~ /^cn=.*,authorizedService=ovpn@.*/ && $e->exists('umiUserCertificateNotAfter') &&
			   $time > generalizedTime_to_time($e->get_value('umiUserCertificateNotAfter') . 'Z') ) {
		   return 'danger';
		 } elsif ( $e->dn =~ /^pgpCertID=.*,$app->{cfg}->{ldap}->{base}->{pgp}/ &&
			   $time > generalizedTime_to_time($e->get_value('pgpKeyExpireTime')) ) {
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

=head1 h_col_to_bg

converts color class to bg color class

    text-info -> text-bg-info

    umi-text-orange -> umi-text-bg-orange

=cut

  $app->helper( h_col_to_bg => sub {
		  my ($c, $col) = @_;
		  my $bg = $col =~ s/-(?!.*-)/-bg-/r;
		  return $bg;
	       });

=head1 h_get_col

gets color part after the last dash

    text-info -> info

    umi-text-orange -> orange

=cut

  $app->helper( h_get_col => sub {
		  my ($c, $col) = @_;
		  $col =~ /-([^-]+)$/;
		  return $1;
	       });

=head1 h_get_root_dn

returns root object dn (root account dn) from current object dn if it
matches $app->{cfg}->{ldap}->{base}->{acc_root}

returns undef if it doesn't

=cut

  $app->helper( h_get_root_dn => sub {
		 my ($c, $dn) = @_;
		 my $root_dn;
		 my $re = qr/^.*(uid=[^,]+,$app->{cfg}->{ldap}->{base}->{acc_root})$/i;
		 $root_dn = $1 if $dn =~ /$re/;
		 return $root_dn;
	       });

=head1 h_get_root_uid_val

returns uid value of root dn if dn matches $app->{cfg}->{ldap}->{base}->{acc_root}

returns undef if it doesn't

=cut

  $app->helper( h_get_root_uid_val => sub {
		 my ($self, $dn) = @_;
		 my $val;
		 my $re = qr/^.*uid=([^,]+),$app->{cfg}->{ldap}->{base}->{acc_root}$/i;
		 $val = $1 if $dn =~ /$re/;
		 return $val;
	       });


=head2 h_is_authorized

Returns 0 or 1 depending on whether the role of the current user is superior
to the role of the user to whom the manipulated object belongs.

The current user's role number must be less than the role number of the user
to whom the manipulated object belongs.

The relationship between roles is defined by the constant `UMIAUTH` in
`lib/Umi/Constants.pm`.

=cut

  $app->helper( h_is_authorized => sub {
		 my ($self, $dn) = @_;
		 # $self->h_log( $dn );
		 my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
		 my $uid = $self->h_get_root_uid_val($dn);
		 # $self->h_log( $uid );
		 my $role = $ldap->get_role($uid);
		 # $self->h_log( $role );

		 my $auth =
		   defined $role
		   && exists UMIAUTH->{role}->{$role}
		   && UMIAUTH->{role}->{$self->session('role')} > UMIAUTH->{role}->{$role}
		   ? 0 : 1;

		 return $auth;
	       });

=head2 h_modify_get_e_orig

strip original Net::LDAP::Entry object from binary attributes

used in I<modify> to avoid comparison of those attributes

=cut

  $app->helper( h_modify_get_e_orig => sub {
		  my ($self, $e, $rdn, $p) = @_;

		  my %skip = (
			      jpegPhoto => 1,
			      cACertificate => 1,
			      certificateRevocationList => 1,
			      umiUserCertificateSubject => 1,
			      umiUserCertificateNotBefore => 1,
			      umiUserCertificateNotAfter => 1,
			      umiUserCertificateSn => 1,
			      umiUserCertificateIssuer => 1,
			      'userCertificate;binary' => 1,
			     );

		  my ($e_orig, $e_tmp);
		  foreach my $a ($e->entry->attributes) {
		    next if $a eq $rdn;
		    # change only on non empty field
		    next if $skip{$a} && exists $p->{$a} && $p->{$a} eq '';
		    $e_tmp = $e->entry->get_value($a, asref => 1);
		    if ( scalar @$e_tmp == 1 ) {
		      $e_orig->{$a} = $e_tmp->[0];
		    } else {
		      $e_orig->{$a} = [ @$e_tmp ];
		    }
		  }
		  return $e_orig;
		});

=head1 h_attr_unused

expected arguments: entry object and a hash by objectclasses and may/must arguments for each objectclass

returns a list of each objectclass attributes (both 'must' and 'may')
across all objectclasses of the entry, excluding attributes that are
already present

=cut

  $app->helper( h_attr_unused => sub {
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

=head1 h_dns_resolver

Net::DNS wrapper to resolve A, MX, PTR records and AXFR zones from NS-es
from config file

    fqdn      - FQDN to resolve (types A, MX)
    type      - DNS query type (A, MX, PTR, AXFR)
    name      - IP address to resolve
    legend    - part of legend for debug
    ns_custom - name servers configured in UMI config file

    Net::DNS::Resolver options
    debug          - default: 0
    force_v4       - default: 1
    persistent_tcp - default: 1
    persistent_udp - default: 1
    recurse        - default: 1
    retry          - default: 1
    tcp_timeout    - default: 1
    udp_timeout    - default: 1

Returns:

    for A / PTR
    {
      success => x.x.x.x / FQDN,
      error   => { errdescr => ..., errcode => ..., errstr => ...  }
    }

    for AXFR
    {
      success => { FQDN => { type => A/CNAME, rdstring => x.x.x.x} },
      error   => { errdescr => ..., errcode => ..., errstr => ...  }
    }

=cut

  $app->helper( h_dns_resolver => sub {
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
			    ns_custom      => $A->{ns_custom}      // 0,
			    with_txt       => $A->{with_txt}       // 0,
			  };

		  my (%return, %domains);
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

		  if ( $a->{ns_custom} == 1
		       && exists $self->{app}->{cfg}->{tool}->{dns}->{ns}
		       && @{$self->{app}->{cfg}->{tool}->{dns}->{ns}} ) {

		    $r->nameservers( $_ )
		      foreach ( @{$self->{app}->{cfg}->{tool}->{dns}->{ns}} );
		  }

		  if ( $a->{type} eq 'AXFR'
		       && exists $self->{app}->{cfg}->{tool}->{dns}->{zone}
		       && @{$self->{app}->{cfg}->{tool}->{dns}->{zone}}) {

		    foreach my $z (@{$self->{app}->{cfg}->{tool}->{dns}->{zone}}) {
		      my @zone_rrs = $r->axfr($z);

		      if (@zone_rrs) {
			my %txt_by_name;

			# First, collect all TXT records indexed by name
			foreach my $rr (@zone_rrs) {
			  if ($rr->type eq 'TXT') {
			    push @{ $txt_by_name{ $rr->name }{txt} }, $rr->txtdata;
			    $txt_by_name{ $rr->name }{owner} = $rr->owner;
			    # $self->h_log($rr->string);
			  }
			}
			# $self->h_log(\%txt_by_name);

			# Now process A and CNAME records
			foreach my $rr (@zone_rrs) {
			  #next unless $rr->type eq 'A' || $rr->type eq 'CNAME' || $rr->type eq 'SRV';

			  my $txt = '';
			  if ($a->{with_txt} == 1) {
			    if (exists $txt_by_name{ $rr->name }) {
			      $txt = ref($txt_by_name{$rr->name}{txt}) eq 'ARRAY' ? join("", @{$txt_by_name{$rr->name}{txt}}) : $txt_by_name{$rr->name}{txt};
			    }
			  }

			  $domains{ $rr->name } = {
						   type     => $rr->type,
						   rdstring => $rr->type ne 'TXT'? $rr->rdstring : '',
						   zone     => $z,
						   txt      => $txt
						  };
			}

		      } else {
			if (exists $return{errstr} && $return{errstr} ne 'NOERROR') {
			  $return{error}{html} = sprintf(
							 "<i class='h6'>dns_resolver()</i>: zone: %s %s ( %s )",
							 $z,
							 DNS->{ $r->errorstring }->{descr},
							 $r->errorstring
							);
			  $return{error}{errdescr} = DNS->{ $r->errorstring }->{descr};
			  $return{error}{errcode}  = DNS->{ $r->errorstring }->{dec};
			  $return{error}{errstr}   = $r->errorstring;
			}
		      }
		    }

		    %{$return{success}} = %domains;

		  } else {
		    my $rr = $r->search($a->{name});
		    $return{errstr}  = $r->errorstring;

		    if ( defined $rr) {
		      foreach ($rr->answer) {
			if ( $a->{type} eq 'PTR' ) {
			  $return{success} = $_->ptrdname if $_->type eq $a->{type};
			} elsif ( $a->{type} eq 'A' ) {
			  $return{success} = $_->address if $_->type eq $a->{type};
			} elsif ( $a->{type} eq 'MX' ) {
			  my @mx_arr = mx( $r, $a->{fqdn} );
			  if (@mx_arr) {
			    $return{success} = $mx_arr[0]->exchange;
			  }
			}

			if ( $return{errstr} ne 'NOERROR' ) {
			  $return{error}{html} = sprintf("<i class='h6'>dns_resolver()</i>: %s %s: %s ( %s )",
							 $a->{fqdn},
							 $a->{legend},
							 DNS->{ $r->errorstring }->{descr},
							 $r->errorstring );
			  $return{error}{errdescr} = DNS->{ $r->errorstring }->{descr};
			  $return{error}{errcode}  = DNS->{ $r->errorstring }->{dec};
			  $return{error}{errstr}   = $r->errorstring;
			}

		      }
		    } else {
		      if ( $return{errstr} ne 'NOERROR') {
			$return{error}{html} = sprintf("<i class='h6'>dns_resolver()</i>: %s %s: %s ( %s )",
							   $a->{fqdn},
							   $a->{legend},
							   DNS->{ $r->errorstring }->{descr} // 'NA',
							   $r->errorstring // 'NA' );
			$return{error}{errdescr} = DNS->{ $r->errorstring }->{descr};
			$return{error}{errstr}   = $r->errorstring;
		      }
		    }
		    $return{errcode} = DNS->{ $r->errorstring }->{descr}
		      if exists $return{errstr};
		  }




		  # p $a->{fqdn}; p $r;
		  # $self->h_log( \%return );
		  return \%return;
		});

=head1 h_is_contextCSN

is there contextCSN variable in stash

=cut

  $app->helper( h_is_contextCSN => sub {
		  my  ($self) = @_;
		  my $res = '';
		  if ( defined $self->stash->{contextCSN} ) {
		    my $contextCSN = $self->stash->{contextCSN};
		    if (defined $contextCSN) {
		      $res = sprintf('<sup class="umi-text-xxs ms-3 text-secondary align-top"><i>cache on %s</i></sup>',
				     strftime("%F %T", gmtime($contextCSN)));
		    }
		  }
		  # $self->h_log( $res );
		  return $res;
	       });

}

1;
