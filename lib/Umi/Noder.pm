# -*- mode: cperl; mode: follow; -*-
#
## idea and main code is provided by Sergey Poznyakoff
#

package Umi::Noder;

use Mojo::Base qw( -base -signatures );
use Mojo::Util qw( dumper );

use Carp;
# use Net::DNS;

=head1 NAME

Noder

=head1 DESCRIPTION

Noder - class to build object (tree) of LDAP DNs list provided

The result object structure is in accordance with DNs relations to each other

=head1 METHODS

=cut

=head2 dn

attribute to hold DN

=cut

has 'dn';

=head2 has_subnodes

method to define, whether obj has subnodes

=cut

sub has_subnodes { exists(shift->{subnode}) }

=head2 is_leaf

method to define, whether obj is leaf

=cut

sub is_leaf { !shift->has_subnodes() }

=head2 locate_nearest

traverses DN, splitted by ',' and returns triplet:

    - last existent subnode
    - DN, splitted by ',' array rest (parts for which there is no subnode yet)
    - first chunk of DN, splitted by ',' for which there is no subnode

=cut

sub locate_nearest {
  my $self = shift;
  my $arg;
  while (defined($arg = pop)) {
    if (exists($self->{subnode}) && exists($self->{subnode}{$arg})) {
      $self = $self->{subnode}{$arg};
    } else {
      last;
    }
  }
  return ($self, @_, $arg);
}

=head2 insert

method to create object branch of subnode/s according to DN, splitted by ','

=cut

sub insert {
  my ($self, $dn) = @_;
  my ($found, @rest) = $self->locate_nearest(split /,/, $dn);
  my $dn_cur;
  my $arg;
  if ($#rest >= 0) {
    while (defined($arg = pop @rest)) {
      $dn_cur                   = $found->dn;
      $found->{subnode}{$arg}   = Umi::Noder->new();
      $found                    = $found->{subnode}{$arg};
      $dn_cur eq '' ? $found->dn($arg) : $found->dn($arg . ',' . $dn_cur);
    }
  }
  # p $found->dn;
  return $found
}

=head2 nodenames

method to return all names of all nodes

=cut

sub nodenames {
  my $self = shift;
  keys(%{$self->{subnode}}) if $self->has_subnodes;
}

=head2 as_string

method to print the object as string

    'dc=umidb:
      ou=People:
       uid=naf.nafus:
        authorizedService=dot1x-eap-md5@ferengi.ears.com:
         uid=f8de1da313b8 (leaf)
        authorizedService=dot1x-eap-tls@borg.startrek.in:
         uid=rad-nostromo-test (leaf)
        authorizedService=mail@starfleet.startrek.in:
         uid=naf.nafus@starfleet.startrek.in (leaf)
        authorizedService=ovpn@borg.startrek.in:
         cn=dev-sk-notebook (leaf)
        authorizedService=ssh-acc@borg.startrek.in:
         uid=naf.nafus_borg.startrek.in (leaf)
        authorizedService=ssh-acc@ferengi.ears.com (leaf)
        authorizedService=web@borg.startrek.in:
         uid=naf.nafus6@borg.startrek.in (leaf)
         uid=qqqqqqqqq@borg.startrek.in (leaf)
        authorizedService=xmpp@borg.startrek.in:
         uid=naf.nafus1@starfleet.startrek.in (leaf)
         uid=naffafus@starfleet.startrek.in (leaf)
    ...'

=cut

sub as_string {
  my $self = shift;
  my $lev  = shift || 0;
  my $s    = '';
  if ($self->has_subnodes) {
    foreach my $k (sort $self->nodenames) {
      $s .= ' ' x $lev if $lev;
      $s .= $k;
      if ($self->{subnode}{$k}->has_subnodes) {
	$s .= ":\n";
	$s .= $self->{subnode}{$k}->as_string($lev + 1);
	chomp($s)
      } else {
	$s .= " (leaf)";
      }
      $s .= "\n";
    }
  }
  return $s
}

=head2 as_hash

method to print the object as hash

    dc=umidb {
    ou=DHCP {
      ou=borg-cube01 {
        'cn=borg-cube01 DHCP Config' {
          cn=GUEST {
            cn=192.168.253.0 {
              cn=host01 {},
                 cn=pool1    {},
                 cn=test24nafus1 {}
            }
          },
          cn=KINDERGARTEN {
            cn=192.168.254.0 {
              cn=pool1     {},
              cn=tst4-4-naf1 {}
            }
          },
        },
      },
    },
    }

=cut


sub as_hash {
  my $self  = shift;
  my $map   = shift // sub { shift; @_ };
  my $hroot = {};
  my @ar;

  push @ar, [ '', $self, $hroot ];
  while (my $elt = shift @ar) {
    if ($elt->[1]->has_subnodes) {
      my $hr0 = {};
      my ($name, $hr) = &{$map}('tree', $elt->[0], $hr0);
      $elt->[2]{$name} = $hr0;
      while (my ($kw, $val) = each %{$elt->[1]->{subnode}}) {
	push @ar, [ $kw, $val, $hr ];
      }
    } else {
      my ($name) = &{$map}('leaf', $elt->[0]);
      $elt->[2]{$name} = {};
    }
  }
  return %{$hroot->{''}};
}

=head2 as_hash_vue

returns hash of such structure:

    ...
    "key1": { "branch": {}, "dn": "dn1 string" },
    ou=workstations": {
      "branch": {
        "cn=chakotay": {
          "dn": "cn=chakotay,cn=chakotay,ou=workstations,dc=umidb"
        },
        "cn=tuvok": {
          "dn": "cn=tuvok,cn=tuvok,ou=workstations,dc=umidb"
        }
      },
      "dn": "ou=workstations,dc=umidb"
    },
    ...
    uid=taf.taffij" : {
       "branch" : {
          "authorizedService=mail@borg.startrek.in" : {
             "branch" : {
                "uid=taf.taffij@borg.startrek.in" : {
                   "dn" : "uid=taf.taffij@borg.startrek.in,authorizedService=mail@borg.startrek.in,uid=taf.taffij,ou=People,dc=umidb"
                }
             },
             "dn" : "authorizedService=mail@borg.startrek.in,uid=taf.taffij,ou=People,dc=umidb"
          },
          "authorizedService=xmpp@im.talax.startrek.in" : {
             "branch" : {
                "uid=taf.taffij@im.talax.startrek.in" : {
                   "dn" : "uid=taf.taffij@im.talax.startrek.in,authorizedService=xmpp@im.talax.startrek.in,uid=taf.taffij,ou=People,dc=umidb"
                }
             },
             "dn" : "authorizedService=xmpp@im.talax.startrek.in,uid=taf.taffij,ou=People,dc=umidb"
          }
       },
       "dn" : "uid=taf.taffij,ou=People,dc=umidb"
    },
    ...
    "key2": { "branch": {}, "dn": "dn2 string" },
    ...

=cut

sub as_hash_vue {
  my $self  = shift;
  my $map   = shift // sub { shift; @_ };
  my $hroot = {};
  my @ar;

  push @ar, [ '', $self, $hroot ];
  while (my $elt = shift @ar) {
    if ($elt->[1]->has_subnodes) {
      my $hr0 = {};
      my ($name, $hr) = &{$map}('tree', $elt->[0], $hr0);
      $elt->[2]{"$name"}{branch} = $hr0;
      $elt->[2]{"$name"}{dn} = "$elt->[1]->{dn}";
      while (my ($kw, $val) = each %{$elt->[1]->{subnode}}) {
	push @ar, [ $kw, $val, $hr ];
      }
    } else {
      my ($name) = &{$map}('leaf', $elt->[0]);
      $elt->[2]{"$name"} = { dn => $elt->[1]->{dn}, };
    }
  }
  #return %{$hroot->{''}{branch}};
  return $hroot->{''}{branch};
}

=head2 as_json

method to print the object as array, ready to be processed to JSON used
in oldstyle ldap tree 

=cut

sub as_json {
  my $self  = shift;
  my $map   = shift // sub { shift; @_ };
  my $hroot = {};
  my @vue;
  my @ar;

  push @ar, [ '', $self, $hroot ];
  while (my $elt = shift @ar) {
    if ($elt->[1]->has_subnodes) {
      my $hr0 = {};
      my ($name, $hr) = &{$map}('tree', $elt->[0], $hr0);
      push @vue, { id => $name, branch => 1, dn => $elt->[1]->dn };
      while (my ($kw, $val) = each %{$elt->[1]->{subnode}}) {
	push @ar, [ $kw, $val, $hr ];
      }
    } else {
      my ($name) = &{$map}('leaf', $elt->[0]);
      push @vue, { id => $name, branch => 0, dn => $elt->[1]->dn };

    }
  }
  return @vue;
}

=head2 as_json_vue

method to print the object as hash, ready to be processed to JSON used
in Vuejs tree example

=cut

sub as_json_vue {
  my $self  = shift;
  my $map   = shift // sub { shift; @_ };
  my $hroot = [];
  my @ar;

  push @ar, [ '', $self, $hroot ];
  while (my $e = shift @ar) {
    if ($e->[1]->has_subnodes) {
      my $ch = [];
      push @{$e->[2]}, { name     => $e->[0],
			 dn       => $e->[1]->dn,
			 isOpen   => \0,
			 children => $ch };
      while (my ($k, $v) = each %{$e->[1]->{subnode}}) {
	push @ar, [ $k, $v, $ch ];
      }
    } else {
      push @{$e->[2]}, { name => $e->[0], dn => $e->[1]->dn };
    }
  }
  # use Data::Printer;
  # p $hroot->[0]->{children}[0];
  # use Logger;
  # log_debug{ np( $hroot ) };
  # my @sorted = sort { $a->{name} cmp $b->{name} } @{$hroot->[0]{children}[0]{children}};
  # log_debug { np( @sorted ) };
  # my $return = { name     => $hroot->[0]->{children}->[0]->{name},
  # 		 children => \@sorted };
  # return $return;

  $hroot->[0]{children}[0]{isOpen} = \1;
  return $hroot->[0]{children}[0];
}

sub as_json_ipa {
  my $self   = shift;
  my $resolv = shift // 0;
  my $map    = shift // sub { shift; @_ };
  my $hroot  = [];
  my @ar;
  my $ip;
  my $ptr;
  my $host;

  push @ar, [ '', $self, $hroot ];
  while (my $e = shift @ar) {
    if ($e->[1]->has_subnodes) {
      my $ch = [];
      push @{$e->[2]}, { name     => $e->[0] // '',
			 dn       => join('.', reverse split(/,/, $e->[1]->dn // '')),
			 isOpen   => \0,
			 children => $ch };
      while (my ($k, $v) = each %{$e->[1]->{subnode}}) {
	push @ar, [ $k, $v, $ch ];
      }
    } else {
      $ip = join('.', reverse split(/,/, $e->[1]->dn));

      push @{$e->[2]}, { name => $e->[0],
			 free => \0,
			 host => '',
			 dn   => $ip };
    }
  }

  # use Data::Printer;
  # p $hroot;

  # return $hroot->[0]{children}[0];
  $hroot->[0]{dn}     = 'networks';
  $hroot->[0]{name}   = 'networks';
  $hroot->[0]{isOpen} = \1;
  
  return $hroot->[0];
}

use overload
  '""' => sub { shift->as_string },
  '<>' => sub {
    my $self = shift;
    return if $self->is_leaf;
    each %{$self->{subnode}}
  };

our $AUTOLOAD;

sub AUTOLOAD {
  my $self = shift;
  my $fn   = $AUTOLOAD;
  $fn =~ s/.*:://;
  if ($self->has_subnodes && @_ == 1) {
    my $key = "$fn=$_[0]";
    if (exists($self->{subnode}{$key})) {
      return $self->{subnode}{$key};
    }
  }
  confess "Can't locate method $AUTOLOAD";
}

1;
