# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Controller::Ldaptree;

use Mojo::Base 'Umi::Controller', -signatures;
use Mojo::Util qw( dumper );

use Umi::Ldap;

use Umi::Noder;

sub obj ($self) {
  my $par = $self->req->params->to_hash;
  # $self->h_log($par);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my ( $return, $as_hash );

  my $search_arg =
    { base   => $par->{base}   // $self->{app}->{cfg}->{ldap}->{base}->{dc},
      filter => $par->{filter} // '(objectClass=*)',
      scope     => 'children',
      sizelimit => 0,
      typesonly => 1,
      attrs     => [ '1.1' ], };
  # $self->h_log($search_arg);

  my $search = $ldap->search($search_arg);
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  my $tree = Umi::Noder->new();
  $tree->insert($_->dn) foreach ( $search->entries );
  $as_hash = $tree->as_json_vue;
  # $as_hash = $tree->as_hash;

  # $self->h_log($as_hash);

  # $self->stash( json_tree => $as_hash );

  $self->render(json => $as_hash);

}

=head2 ipa

method to retieve IP addresses used and unused

if option naddr is passed, then unused addresses are returned (naddr
is expected to be first 3 bytes of one single /24 network)

=cut

sub ipa {
  my ( $self, $args ) = @_;

  my $re = {
	     ip    => '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-5][0-9])',
	     net3b => '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}',
	     net2b => '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){1}',
	    };



  my $arg = { svc    => $args->{svc}    // 'ovpn',
              naddr  => $args->{naddr}  // '',
              fqdn   => $args->{fqdn}   // '*',
              base   => $args->{base}   // $self->{app}->{cfg}->{ldap}->{base}->{ovpn},
              filter => $args->{filter} // '(&(objectClass=umiOvpnCfg)(cn=*))',
              scope  => $args->{scope}  // 'base',
              attrs  => $args->{attrs}  // [ 'cn', 'umiOvpnCfgServer', 'umiOvpnCfgRoute' ],
            };
  my $return;
  $return->{arg} = $arg;

  my ( $key, $val, $k, $v, $l, $r, $f, $tmp, $entry_svc, $entry_dhcp, $entry_ovpn, $ipspace, $ip_used );

  my $ipa = Net::CIDR::Set->new;

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  if ( $arg->{naddr} =~ /$re->{net2b}/ || $arg->{naddr} =~ /$re->{net3b}/ ) {
    $f = sprintf('(|(umiOvpnCfgIfconfigPush=*%s.*)(umiOvpnCfgIroute=%s.*)(dhcpStatements=fixed-address %s.*)(ipHostNumber=%s.*))',
                 $arg->{naddr},
                 $arg->{naddr},
                 $arg->{naddr},
                 $arg->{naddr},
                 $arg->{fqdn});
  } else {
    $f = sprintf('(|(&(authorizedService=ovpn@%s)(cn=*))(dhcpStatements=fixed-address *)(ipHostNumber=*))',
                 $arg->{fqdn});
  }

  my $search_arg = { base      => $self->{app}->{cfg}->{ldap}->{base}->{dc},
		     sizelimit => 0,
		     filter    => $f,
		     attrs     => [ qw( umiOvpnCfgIfconfigPush
					umiOvpnCfgIroute
					ipHostNumber
					dhcpStatements ) ], };
  my $search = $ldap->search($search_arg);
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  $val = $search->as_struct;
    # log_debug { np($val) };
    foreach $key (keys ( %{$val} )) {
      undef $l;
      undef $r;

      # log_debug { np($key) };
      # log_debug { np($val->{$key}) };

      # OpenVPN option --ifconfig-push local remote-netmask [alias]
      if ( exists $val->{$key}->{umiovpncfgifconfigpush} ) {
        foreach ( @{$val->{$key}->{umiovpncfgifconfigpush}} ) {
          # log_debug { np($_) };
          ($l, $r, $tmp) = split(/ /, $_);
          if ( $self->h_ipam_ip2dec($r) - $self->h_ipam_ip2dec($l) == 1 ) {
            $ipa->add($l . '/30');
          } else {
            $ipa->add($l);
          }
        }
        undef $tmp;
      }

      # # OpenVPN option  --iroute network [netmask]
      # # Generate an internal route to a specific client.
      # # The netmask parameter, if omitted, defaults to 255.255.255.255.
      # if ( exists $val->{$key}->{umiovpncfgiroute} ) {
      #   foreach ( @{$val->{$key}->{umiovpncfgiroute}} ) {
      #     next if $_ eq 'NA';
      #     # log_debug { np($_) };
      #     ($l, $r) = split(/ /, $_);
      #     if ( length($r) == 0 ) {
      #       $ipa->add($l);
      #     } else {
      #       $ipa->add($l . '/' . $self->ipam_msk_ip2dec($r));
      #     }
      #   }
      # }

      # ISC DHCP Manual Pages - dhcpd.conf
      # The fixed-address declaration `fixed-address address [, address ... ];`
      # The fixed-address declaration is used to assign one or more fixed IP addresses to a client.
      # BUT WE EXPECT ONE SINGLE IP ADDRESS
      if ( exists $val->{$key}->{dhcpstatements} ) {
      	foreach ( @{$val->{$key}->{dhcpstatements}} ) {
      	  next if $_ !~ /^fixed-address/;
          # log_debug { np($_) };
      	  ($l, $r) = split(/ /, $_);
      	  $ipa->add($r);
      	}
      }

      if ( exists $val->{$key}->{iphostnumber} ) {
        foreach ( @{$val->{$key}->{iphostnumber}} ) {
          next if $_ eq 'NA' || ! $self->h_is_ip($_);
          # log_debug { np($_) };
          $ipa->add($_);
        }
      }

    }

  # log_debug { np(@{[$ipa->as_address_array]}) };

  # log_debug { np($arg) };
  if ( length($arg->{naddr}) > 0 ) {
    my $re_net3b = $re->{net3b};
    my $net_sufix;
    if ( $arg->{naddr} =~ /$re->{net3b}/ ) {
      $net_sufix = '.0/24';
    } elsif ( $arg->{naddr} =~ /$re->{net2b}/ ) {
      $net_sufix = '.0.0/16';
    }
    # log_debug { $arg->{naddr} . ' - ' . $net_sufix };
    my $ipa_this = Net::CIDR::Set->new;
    $ipa_this->add($arg->{naddr} . $net_sufix);
    my $xset = $ipa_this->diff($ipa);
    # log_debug { np(@{[$xset->as_address_array]}) };
    $ipa = $xset;
  }

  my $ipa_tree = Umi::Noder->new();
  foreach ( @{[ $ipa->as_address_array ]} ) {
    $tmp = join(',', reverse split(/\./, $_));
    # log_debug{ np($tmp) };
    $key = $ipa_tree->insert($tmp);
    # log_debug{ np($key->dn) };
  }
  # my $as_str = $ipa_tree->as_string;
  # log_debug { np($as_str) };
  my $as_hash = $ipa_tree->as_json_ipa(1);
  # log_debug { np($as_hash) };
  $return->{ipa} = length($arg->{naddr}) > 0 ? $as_hash->{children}->[0]->{children}->[0]->{children}->[0] : $as_hash;
  $return->{ipa} = {} if ! defined $return->{ipa};

  #$self->h_log($return->{ipa});

  $self->render(json => $return->{ipa});
}

1;
