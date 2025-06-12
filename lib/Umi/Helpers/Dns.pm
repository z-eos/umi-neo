# -*- mode: cperl; eval: (follow-mode 1); -*-

package Umi::Helpers::Dns;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util qw( b64_encode b64_decode encode url_escape );

use Umi::Constants qw(RE DNS UMIAUTH );

use Encode qw(decode_utf8);
use Net::DNS;

=pod

=head1 Umi::Helpers::Dns

DNS Resolver Helpers - Enhanced DNS resolution helpers for Mojolicious

=head1 DESCRIPTION

This module provides a comprehensive set of DNS resolution helpers for
Mojolicious applications, supporting A, CNAME, PTR, TXT record queries and
AXFR zone transfers with zone-specific nameserver configuration.

=cut


sub register {
  my ($self, $app) = @_;
  my $re = RE; # defined in Umi::Constants;

  ### BEGINNING OF REGISTER

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
			    whole_axfr     => $A->{whole_axfr}     // 0,
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

			  next if $a->{whole_axfr} == 0 && $rr->type ne 'A' && $rr->type ne 'CNAME';

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


# {
#     error   {
#         errcode    3,
#         errdescr   "Non-Existent Domain",
#         errstr     "NXDOMAIN",
#         html       "<i class='h6'>dns_single_query()</i>: 10.11.9.10 Non-Existent Domain ( NXDOMAIN )"
#     }
# }
# [2025-06-12 16:16:32.24793] [3589] [info] Successfull authentication occured, protected routes are available.
# Umi::Controller::Protected /home/zeus/src/umi-neo/umi-neo/lib/Umi/Controller/Protected.pm:1730
# {
#     ptr   "10.11.9.11" (dualvar: 10.11)
# }
# Umi::Controller::Protected /home/zeus/src/umi-neo/umi-neo/lib/Umi/Controller/Protected.pm:1736
# {
#     success   [
#         [0] {
#                 name       "11.9.11.10.in-addr.arpa" (dualvar: 11.9),
#                 rdstring   "gray-home.vpn.norse.digital.",
#                 ttl        600,
#                 type       "PTR"
#             }
#     ]
# }

# Enhanced DNS resolver helpers for Mojo

=head2 h_dns_rr

Main DNS resolver helper - entry point for all DNS operations.

B<Input:> Hashref with parameters:

  {
    name           => 'query_name',        # Name for logging/identification
    fqdn           => 'domain.com',        # FQDN to query (defaults to name)
    type           => 'A',                 # Query type: A, CNAME, PTR, TXT, AXFR
    legend         => 'description',       # Optional description
    debug          => 0,                   # Enable debug mode (0/1)
    force_v4       => 1,                   # Force IPv4 (0/1)
    persistent_tcp => 1,                   # Use persistent TCP (0/1)
    persistent_udp => 1,                   # Use persistent UDP (0/1)
    recurse        => 1,                   # Enable recursion (0/1)
    retry          => 1,                   # Retry count
    tcp_timeout    => 1,                   # TCP timeout in seconds
    udp_timeout    => 1,                   # UDP timeout in seconds
    ns_custom      => 0,                   # Use custom nameservers (0/1)
    with_txt       => 0,                   # Include TXT records in AXFR (0/1)
    whole_axfr     => 0,                   # Include all record types in AXFR (0/1)
  }

B<Return:> Hashref with results:

  Success:
  {
    success => {
      'domain1.com' => {
	type     => 'A',
	rdstring => '192.168.1.1',
	zone     => 'example.com',         # For AXFR results
	txt      => 'associated txt',      # If with_txt enabled
	ttl      => 3600,
      },
      # ... more records
    }
  }

  Error:
  {
    error => {
      html     => 'HTML formatted error message',
      errdescr => 'Human readable error description',
      errcode  => 123,                     # Numeric error code
      errstr   => 'DNS_ERROR_STRING',
    },
    errors => [                            # For AXFR with multiple zones
      {
	zone     => 'failed.zone.com',
	errstr   => 'ERROR_STRING',
	# ... other error fields
      }
    ]
  }

=cut

  $app->helper( h_dns_rr => sub {
		  my ($self, $A) = @_;
		  my $a = {
			   name           => $A->{name},
			   fqdn           => $A->{fqdn}           // $A->{name},
			   type           => $A->{type}           // 'PTR',
			   legend         => $A->{legend}         // '',
			   debug          => $A->{debug}          // $self->config->{tool}->{dns}->{resolver}->{debug} // 0,
			   force_v4       => $A->{force_v4}       // $self->config->{tool}->{dns}->{resolver}->{force_v4} // 1,
			   persistent_tcp => $A->{persistent_tcp} // $self->config->{tool}->{dns}->{resolver}->{persistent_tcp} // 1,
			   persistent_udp => $A->{persistent_udp} // $self->config->{tool}->{dns}->{resolver}->{persistent_udp} // 1,
			   recurse        => $A->{recurse}        // $self->config->{tool}->{dns}->{resolver}->{recurse} // 1,
			   retry          => $A->{retry}          // $self->config->{tool}->{dns}->{resolver}->{retry} // 1,
			   tcp_timeout    => $A->{tcp_timeout}    // $self->config->{tool}->{dns}->{resolver}->{tcp_timeout} // 1,
			   udp_timeout    => $A->{udp_timeout}    // $self->config->{tool}->{dns}->{resolver}->{udp_timeout} // 1,
			   ns_custom      => $A->{ns_custom}      // 0,
			   with_txt       => $A->{with_txt}       // 0,
			   whole_axfr     => $A->{whole_axfr}     // 0,
			  };

		  my %return;

		  if ($a->{type} eq 'AXFR') {
		    return $self->h_dns_axfr_all_zones($a);
		  } else {
		    return $self->h_dns_single_query($a);
		  }
		});

=head2 h_dns_single_query

Performs single DNS queries for A, CNAME, PTR, TXT record types.

B<Input:> Hashref with parameters (same as h_dns_rr but excludes AXFR-specific options):

  {
    fqdn           => 'domain.com',        # Required: FQDN to query
    type           => 'A',                 # Required: A, CNAME, PTR, or TXT
    debug          => 0,                   # DNS resolver debug mode
    force_v4       => 1,                   # Force IPv4 resolution
    # ... other Net::DNS::Resolver options
  }

B<Return:> Hashref with results:

  Success:
  {
    success => [
      {
	name     => 'domain.com',
	type     => 'A',
	rdstring => '192.168.1.1',
	ttl      => 3600,
      },
      {
	name     => 'domain.com',
	type     => 'A',
	rdstring => '192.168.1.2',
	ttl      => 3600,
      },
      # ... additional records
    ]
  }

  Error:
  {
    error => {
      html     => 'HTML formatted error message',
      errdescr => 'Human readable error description',
      errcode  => 123,
      errstr   => 'NXDOMAIN',
    }
  }

=cut

  $app->helper( h_dns_single_query => sub {
		  my ($self, $a) = @_;
		  my %return;

		  my $r = $self->h_dns_create_resolver($a);
		  return { error => { errstr => 'Failed to create resolver' } } unless $r;

		  my $query = $r->search($a->{fqdn}, $a->{type});

		  if ($query) {
		    my @results;
		    foreach my $rr ($query->answer) {
		      push @results, {
				      name     => $rr->name,
				      type     => $rr->type,
				      rdstring => $rr->rdstring,
				      ttl      => $rr->ttl,
				     };
		    }
		    $return{success} = \@results;
		  } else {
		    $return{error} = {
				      html     => sprintf("<i class='h6'>dns_single_query()</i>: %s %s ( %s )",
							  $a->{fqdn},
							  DNS->{$r->errorstring}->{descr} // 'Unknown error',
							  $r->errorstring),
				      errdescr => DNS->{$r->errorstring}->{descr} // 'Unknown error',
				      errcode  => DNS->{$r->errorstring}->{dec} // 0,
				      errstr   => $r->errorstring,
				     };
		  }

		  return \%return;
		});

=head2 h_dns_axfr_all_zones

Performs AXFR (zone transfer) on all zones configured in the application config.
Uses zone-specific nameservers from configuration.

B<Input:> Hashref with AXFR parameters:

  {
    debug          => 0,                   # DNS resolver debug mode
    with_txt       => 0,                   # Include TXT records (0/1)
    whole_axfr     => 0,                   # Include all record types vs A/CNAME only (0/1)
    # ... other Net::DNS::Resolver options
  }

B<Return:> Hashref with aggregated results from all zones:

  Success:
  {
    success => {
      'host1.zone1.com' => {
	type     => 'A',
	rdstring => '192.168.1.1',
	zone     => 'zone1.com',
	txt      => 'optional txt data',   # If with_txt enabled
	ttl      => 3600,
      },
      'host2.zone2.com' => {
	type     => 'CNAME',
	rdstring => 'target.zone2.com',
	zone     => 'zone2.com',
	txt      => '',
	ttl      => 1800,
      },
      # ... records from all zones
    }
  }

  Error (when no zones configured):
  {
    error => {
      errstr => 'No zones configured for AXFR',
      html   => "<i class='h6'>dns_axfr_all_zones()</i>: No zones configured"
    }
  }

  Partial success (some zones failed):
  {
    success => { /* successful zone records */ },
    errors => [
      {
	zone     => 'failed.zone.com',
	errstr   => 'connection timed out',
	errdescr => 'Connection timeout',
	errcode  => 110,
	html     => 'HTML formatted error'
      },
      # ... other zone failures
    ]
  }

=cut

  $app->helper( h_dns_axfr_all_zones => sub {
		  my ($self, $a) = @_;
		  my %return;
		  my %domains;

		  my $zone_config = $self->config->{tool}->{dns}->{zones} // {};

		  unless (keys %$zone_config) {
		    $return{error} = {
				      errstr => 'No zones configured for AXFR',
				      html => "<i class='h6'>dns_axfr_all_zones()</i>: No zones configured"
				     };
		    return \%return;
		  }

		  foreach my $zone_name (keys %$zone_config) {
		    my $zone_result = $self->h_dns_axfr_single_zone($zone_name, $a);

		    if (exists $zone_result->{success}) {
		      # Merge successful results
		      %domains = (%domains, %{$zone_result->{success}});
		    } elsif (exists $zone_result->{error}) {
		      # Collect errors but continue with other zones
		      push @{$return{errors}}, {
						zone => $zone_name,
						%{$zone_result->{error}}
					       };
		    }
		  }

		  $return{success} = \%domains if keys %domains;
		  return \%return;
		});

=head2 h_dns_axfr_single_zone

Performs AXFR (zone transfer) on a single specified zone using its configured nameservers.

B<Input:>
  - $zone_name: String - name of the zone to transfer
  - $config: Hashref with AXFR parameters (same as h_dns_axfr_all_zones)

  Example:
  $self->h_dns_axfr_single_zone('example.com', {
    with_txt   => 1,
    whole_axfr => 0,
    debug      => 0
  });

B<Return:> Hashref with zone-specific results:

  Success:
  {
    success => {
      'host1.example.com' => {
	type     => 'A',
	rdstring => '192.168.1.1',
	zone     => 'example.com',
	txt      => 'associated txt record',
	ttl      => 3600,
      },
      'mail.example.com' => {
	type     => 'A',
	rdstring => '192.168.1.10',
	zone     => 'example.com',
	txt      => '',
	ttl      => 3600,
      },
      # ... more records from the zone
    }
  }

  Error:
  {
    error => {
      html     => "<i class='h6'>dns_axfr_single_zone()</i>: zone: example.com REFUSED ( REFUSED )",
      errdescr => 'Zone transfer refused',
      errcode  => 5,
      errstr   => 'REFUSED',
    }
  }

=cut

  $app->helper( h_dns_axfr_single_zone => sub {
		  my ($self, $zone_name, $a) = @_;
		  my %return;
		  my %domains;

		  my $zone_config = $self->config->{tool}->{dns}->{zones}->{$zone_name};

		  unless ($zone_config) {
		    $return{error} = {
				      errstr => "Zone $zone_name not configured",
				      html => "<i class='h6'>dns_axfr_single_zone()</i>: Zone $zone_name not configured"
				     };
		    return \%return;
		  }

		  # Create resolver with zone-specific nameservers
		  my $resolver_config = { %$a };
		  $resolver_config->{zone_nameservers} = $zone_config->{nameservers};

		  my $r = $self->h_dns_create_resolver($resolver_config);

		  unless ($r) {
		    $return{error} = {
				      errstr => "Failed to create resolver for zone $zone_name",
				      html => "<i class='h6'>dns_axfr_single_zone()</i>: Failed to create resolver for zone $zone_name"
				     };
		    return \%return;
		  }

		  my @zone_rrs = $r->axfr($zone_name);

		  if (@zone_rrs) {
		    my %txt_by_name;

		    # First pass: collect all TXT records
		    foreach my $rr (@zone_rrs) {
		      if ($rr->type eq 'TXT') {
			push @{ $txt_by_name{ $rr->name }{txt} }, $rr->txtdata;
			$txt_by_name{ $rr->name }{owner} = $rr->owner;
		      }
		    }

		    # Second pass: process other records
		    foreach my $rr (@zone_rrs) {
		      next if $a->{whole_axfr} == 0 && $rr->type ne 'A' && $rr->type ne 'CNAME';

		      my $txt = '';
		      if ($a->{with_txt} == 1 && exists $txt_by_name{ $rr->name }) {
			$txt = ref($txt_by_name{$rr->name}{txt}) eq 'ARRAY'
			  ? join("", @{$txt_by_name{$rr->name}{txt}})
			  : $txt_by_name{$rr->name}{txt};
		      }

		      $domains{ $rr->name } = {
					       type     => $rr->type,
					       rdstring => $rr->type ne 'TXT' ? $rr->rdstring : '',
					       zone     => $zone_name,
					       txt      => $txt,
					       ttl      => $rr->ttl,
					      };
		    }

		    $return{success} = \%domains;

		  } else {
		    $return{error} = {
				      html     => sprintf("<i class='h6'>dns_axfr_single_zone()</i>: zone: %s %s ( %s )",
							  $zone_name,
							  DNS->{$r->errorstring}->{descr} // 'Unknown error',
							  $r->errorstring),
				      errdescr => DNS->{$r->errorstring}->{descr} // 'Unknown error',
				      errcode  => DNS->{$r->errorstring}->{dec} // 0,
				      errstr   => $r->errorstring,
				     };
		  }

		  return \%return;
		});

=head2 h_dns_create_resolver

Creates a properly configured Net::DNS::Resolver instance with settings from
application configuration and optional overrides.

B<Input:> Hashref with resolver configuration:

  {
    debug             => 0,                # Override default debug setting
    force_v4          => 1,                # Override default IPv4 setting
    zone_nameservers  => ['ns1.com'],      # Zone-specific nameservers (priority)
    ns_custom         => 1,                # Use default_nameservers from config
    # ... any Net::DNS::Resolver options
  }

B<Return:> Net::DNS::Resolver object or undef on failure

  Success: Net::DNS::Resolver instance configured with:
  - Zone-specific nameservers (highest priority)
  - Default nameservers from config (if ns_custom set)
  - System nameservers (fallback)
  - All resolver options from config + overrides

  Failure: undef

B<Nameserver Priority:>
  1. zone_nameservers (for AXFR operations)
  2. default_nameservers from config (if ns_custom = 1)
  3. System default nameservers

=cut

  $app->helper( h_dns_create_resolver => sub {
		  my ($self, $config) = @_;

		  my $resolver_defaults = $self->config->{tool}->{dns}->{resolver} // {};

		  my $r = Net::DNS::Resolver->new(
						  debug          => $config->{debug}          // $resolver_defaults->{debug}          // 0,
						  force_v4       => $config->{force_v4}       // $resolver_defaults->{force_v4}       // 1,
						  persistent_tcp => $config->{persistent_tcp} // $resolver_defaults->{persistent_tcp} // 1,
						  persistent_udp => $config->{persistent_udp} // $resolver_defaults->{persistent_udp} // 1,
						  recurse        => $config->{recurse}        // $resolver_defaults->{recurse}        // 1,
						  retry          => $config->{retry}          // $resolver_defaults->{retry}          // 1,
						  tcp_timeout    => $config->{tcp_timeout}    // $resolver_defaults->{tcp_timeout}    // 1,
						  udp_timeout    => $config->{udp_timeout}    // $resolver_defaults->{udp_timeout}    // 1,
						 );

		  # Set nameservers based on priority:
		  # 1. Zone-specific nameservers (for AXFR)
		  # 2. Custom nameservers (if ns_custom is set)
		  # 3. Default system nameservers

		  if ($config->{zone_nameservers} && @{$config->{zone_nameservers}}) {
		    $r->nameservers(@{$config->{zone_nameservers}});
		  } elsif ($config->{ns_custom} &&
			   exists $self->config->{tool}->{dns}->{default_nameservers} &&
			   @{$self->config->{tool}->{dns}->{default_nameservers}}) {
		    $r->nameservers(@{$self->config->{tool}->{dns}->{default_nameservers}});
		  }

		  return $r;
		});

=head2 h_dns_get_zone_authority

Retrieves SOA (Start of Authority) record information for a zone to determine
the authoritative nameserver and zone metadata.

B<Input:>
  - $zone_name: String - name of the zone to query

  Example:
  my $soa = $self->h_dns_get_zone_authority('example.com');

B<Return:> Hashref with SOA information or undef if not found:

  Success:
  {
    primary_ns => 'ns1.example.com',       # Primary nameserver
    admin      => 'admin.example.com',     # Administrative contact
    serial     => 2023121501,              # Zone serial number
    refresh    => 3600,                    # Refresh interval (seconds)
    retry      => 1800,                    # Retry interval (seconds)
    expire     => 604800,                  # Expire time (seconds)
    minimum    => 86400,                   # Minimum TTL (seconds)
  }

  Failure: undef (zone not found or no SOA record)

=cut

  $app->helper( h_dns_get_zone_authority => sub {
		  my ($self, $zone_name) = @_;

		  my $r = Net::DNS::Resolver->new();
		  my $soa_query = $r->search($zone_name, 'SOA');

		  if ($soa_query) {
		    foreach my $rr ($soa_query->answer) {
		      if ($rr->type eq 'SOA') {
			return {
				primary_ns => $rr->mname,
				admin      => $rr->rname,
				serial     => $rr->serial,
				refresh    => $rr->refresh,
				retry      => $rr->retry,
				expire     => $rr->expire,
				minimum    => $rr->minimum,
			       };
		      }
		    }
		  }

		  return undef;
		});

=head2 h_dns_discover_nameservers

Discovers authoritative nameservers for a zone by querying NS records.
Useful for auto-configuring zone nameservers.

B<Input:>
  - $zone_name: String - name of the zone to discover nameservers for

  Example:
  my $nameservers = $self->h_dns_discover_nameservers('example.com');

B<Return:> Arrayref of nameserver names or empty arrayref if none found:

  Success:
  [
    'ns1.example.com',
    'ns2.example.com',
    'ns3.example.com'
  ]

  No nameservers found: []

B<Usage:> This helper is useful for dynamically discovering nameservers
before performing AXFR operations or for updating zone configuration.

=cut

  $app->helper( h_dns_discover_nameservers => sub {
		  my ($self, $zone_name) = @_;

		  my $r = Net::DNS::Resolver->new();
		  my $ns_query = $r->search($zone_name, 'NS');

		  my @nameservers;
		  if ($ns_query) {
		    foreach my $rr ($ns_query->answer) {
		      if ($rr->type eq 'NS') {
			push @nameservers, $rr->nsdname;
		      }
		    }
		  }

		  return \@nameservers;
		});

  ### END OF REGISTER --------------------------------------------------------------------------------------------
}

=head1 CONFIGURATION

The helpers expect the following configuration structure in your Mojolicious app:

  tool:
    dns:
      resolver:                            # Default Net::DNS::Resolver options
	debug: 0
	force_v4: 1
	persistent_tcp: 1
	persistent_udp: 1
	recurse: 1
	retry: 1
	tcp_timeout: 1
	udp_timeout: 1

      default_nameservers:                 # For general queries when ns_custom=1
	- 8.8.8.8
	- 1.1.1.1

      zones:                               # Zone-specific configuration
	example.com:
	  nameservers:
	    - ns1.example.com
	    - ns2.example.com
	  description: "Main zone"

=head1 USAGE EXAMPLES

=head2 A Record Query

  my $result = $self->h_dns_rr({
    fqdn => 'www.example.com',
    type => 'A'
  });

  # Result:
  # {
  #   success => [
  #     {
  #       name     => 'www.example.com',
  #       type     => 'A',
  #       rdstring => '192.168.1.100',
  #       ttl      => 300,
  #     },
  #     {
  #       name     => 'www.example.com',
  #       type     => 'A',
  #       rdstring => '192.168.1.101',
  #       ttl      => 300,
  #     }
  #   ]
  # }

=head2 PTR Record Query (Reverse DNS)

  my $result = $self->h_dns_rr({
    fqdn => '100.1.168.192.in-addr.arpa',
    type => 'PTR'
  });

  # Or using IP address (helper will convert):
  my $result = $self->h_dns_rr({
    fqdn => '192.168.1.100',
    type => 'PTR'
  });

  # Result:
  # {
  #   success => [
  #     {
  #       name     => '100.1.168.192.in-addr.arpa',
  #       type     => 'PTR',
  #       rdstring => 'www.example.com',
  #       ttl      => 3600,
  #     }
  #   ]
  # }

=head2 TXT Record Query

  my $result = $self->h_dns_rr({
    fqdn => 'example.com',
    type => 'TXT'
  });

  # Result:
  # {
  #   success => [
  #     {
  #       name     => 'example.com',
  #       type     => 'TXT',
  #       rdstring => 'v=spf1 include:_spf.google.com ~all',
  #       ttl      => 300,
  #     },
  #     {
  #       name     => 'example.com',
  #       type     => 'TXT',
  #       rdstring => 'google-site-verification=abcdef123456',
  #       ttl      => 300,
  #     }
  #   ]
  # }

=head2 CNAME Record Query

  my $result = $self->h_dns_rr({
    fqdn => 'www.example.com',
    type => 'CNAME'
  });

  # Result:
  # {
  #   success => [
  #     {
  #       name     => 'www.example.com',
  #       type     => 'CNAME',
  #       rdstring => 'example.com',
  #       ttl      => 300,
  #     }
  #   ]
  # }

=head2 Multiple Record Types Query

  # Query for all A records, then follow up with TXT
  my $a_result = $self->h_dns_rr({
    fqdn => 'mail.example.com',
    type => 'A'
  });

  my $txt_result = $self->h_dns_rr({
    fqdn => 'mail.example.com',
    type => 'TXT'
  });

=head2 AXFR Examples

  # AXFR all configured zones with TXT records
  my $result = $self->h_dns_rr({
    type => 'AXFR',
    with_txt => 1,
    whole_axfr => 0  # Only A and CNAME records
  });

  # AXFR specific zone with all record types
  my $result = $self->h_dns_axfr_single_zone('example.com', {
    with_txt => 1,
    whole_axfr => 1,  # Include all record types
    debug => 1
  });

  # Result structure for AXFR:
  # {
  #   success => {
  #     'host1.example.com' => {
  #       type     => 'A',
  #       rdstring => '192.168.1.10',
  #       zone     => 'example.com',
  #       txt      => 'server description',
  #       ttl      => 300,
  #     },
  #     'mail.example.com' => {
  #       type     => 'CNAME',
  #       rdstring => 'host1.example.com',
  #       zone     => 'example.com',
  #       txt      => '',
  #       ttl      => 300,
  #     }
  #   }
  # }

=head2 Utility Examples

  # Discover nameservers for zone configuration
  my $ns_list = $self->h_dns_discover_nameservers('example.com');
  # Returns: ['ns1.example.com', 'ns2.example.com']

  # Get zone authority information
  my $soa = $self->h_dns_get_zone_authority('example.com');
  # Returns: { primary_ns => 'ns1.example.com', serial => 2023121501, ... }

=head2 Error Handling Examples

  my $result = $self->h_dns_rr({
    fqdn => 'nonexistent.example.com',
    type => 'A'
  });

  if (exists $result->{error}) {
    say "DNS Error: " . $result->{error}->{errdescr};
    say "Error Code: " . $result->{error}->{errcode};
    say "Raw Error: " . $result->{error}->{errstr};
    # Display HTML: $result->{error}->{html}
  }

=head2 Custom Nameserver Examples

  # Use custom nameservers for query
  my $result = $self->h_dns_rr({
    fqdn => 'example.com',
    type => 'A',
    ns_custom => 1,  # Uses default_nameservers from config
    debug => 1
  });

  # Force specific resolver settings
  my $result = $self->h_dns_rr({
    fqdn => 'example.com',
    type => 'TXT',
    tcp_timeout => 5,
    udp_timeout => 3,
    retry => 3
  });

=head1 ERROR HANDLING

All helpers return structured error information:
- B<errstr>: Raw DNS error string (NXDOMAIN, REFUSED, etc.)
- B<errdescr>: Human-readable error description
- B<errcode>: Numeric DNS error code
- B<html>: HTML-formatted error message for display

Multiple zone operations (h_dns_axfr_all_zones) collect errors per zone
in the 'errors' arrayref while still returning successful results.

=cut

1;
