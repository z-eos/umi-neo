# -*- mode: cperl; eval: (follow-mode 1); -*-

package Umi::Controller::Machines;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojolicious::Validator;
use Mojo::Util 'b64_decode';

use Net::LDAP::Constant qw(
			    LDAP_SUCCESS
			    LDAP_PROTOCOL_ERROR
			    LDAP_NO_SUCH_OBJECT
			    LDAP_INVALID_DN_SYNTAX
			    LDAP_INSUFFICIENT_ACCESS
			    LDAP_CONTROL_SORTRESULT
			 );

use Umi::Ldap;

=head1 create_or_update

EXAMPLE

curl -X POST -u uid=john,ou=People,dc=foo,dc=bar:*** http://10.0.0.1:3000/public/machines -H "Content-Type: application/json" -d @FILE.json -s | jq

foo-create.json

    {
      "hostname": "foo.norse.digital",
      "domain": [ "jobastre.norse.digital",
		  "cretin.norse.digital",
		  "lampiste.norse.co" ],
      "ipaddr": "192.0.2.1",
      "status": "up",
      "cpu_count": 24000001,
      "ram_size": 32731636,
      "devices": [ "/dev/sdd=vol-0e91bf61c401abe38 32G",
		   "/dev/sda1=vol-032c8367041821f3c 8G" ],
	    "os": {
		    "name": "Linux",
		    "version": "5.4.0-1088",
		    "arch": "x86_64",
		    "distro-name": "debian",
		    "distro-version": "12",
		    "distro-family": "debian"
	    },
	    "id": "i-deadbeef",
	    "type": "s3.verylarge",
	    "location": "moon-copernicus-1",
	    "account_id": "OUCH3158206",
	    "hosting_id": "CloudAssHole"
    }


foo-update.json

    {
      "hostname": "foo.norse.digital",
      "domain": [ "jobastre.norse.digital",
		  "cretin.norse.digital",
		  "lampiste.norse.co" ],
      "ipaddr": "10.173.95.111",
      "status": "up",
      "cpu_count": 2,
      "ram_size": 32731636,
      "devices": [ "/dev/sdz9=vol-0e938 32E",
		   "/dev/sda1=vol-0323c 8Z" ],
	    "os": {
		    "name": "Linux",
		    "version": "5.4.0-1088",
		    "arch": "x86_64",
		    "distro-name": "debian",
		    "distro-version": "17",
		    "distro-family": "debian"
	    },
	    "id": "i-deadpork",
	    "type": "s3.notverylarge",
	    "location": "moon-copernicus-1",
	    "account_id": "OUCH3158206",
	    "hosting_id": "CloudAssHole"
    }


=cut

sub create_or_update ($self) {
  my $ldap = $self->h_auth_basic;
  # my $auth = $self->req->headers->authorization || '';
  # # Expect "Basic <base64encoded>"
  # unless ( $auth && $auth =~ /^Basic\s+(.+)$/ ) {
  #   $self->res->headers->www_authenticate('Basic realm="Protected Area"');
  #   $self->render(text => 'Authentication required', status => 401);
  #   return;
  # }

  # my $encoded = $1;
  # my $decoded = b64_decode($encoded) || '';
  # # Expect decoded string to be "username:password"
  # my ($user, $pass) = split /:/, $decoded, 2;

  # my $ldap = Umi::Ldap->new( $self->{app}, $user, $pass, 1 );
  # # $self->h_log(ref($ldap->ldap));
  # unless ( ref($ldap->ldap) eq 'Net::LDAP' ) {
  #   $self->res->headers->www_authenticate('Basic realm="Protected Area"');
  #   $self->render(text => 'Authentication required', status => 401);
  #   return;
  # }

  my $data = $self->req->json;
  # $self->h_log($data);

  return $self->render(json => { error => "Invalid data" })
    unless defined $data && exists $data->{hostname};

  my $attrmap = {
		 hostname => 'grayHostName',
		 domain => 'associatedDomain',
		 ipaddr => 'ipHostNumber',
		 status => 'grayStatus',
		 cpu_count => 'ipHostNumber',
		 ram_size => 'grayRAMSize',
		 devices => 'grayDeviceMapping',
		 os => {
			name => 'grayOSName',
			version => 'grayOSVersion',
			arch => 'grayOSArchitecture',
			'distro-name' => 'grayOSDistribution',
			'distro-version' => 'grayOSDistributionVersion',
			'distro-family' => 'grayOSDistributionFamily',
		       },
		 id => 'grayInstanceID',
		 type => 'grayInstanceType',
		 location => 'grayInstanceRegion',
		 account_id => 'grayMasterAccount',
		 hosting_id => 'grayHostingID'
		};

  my $host_data;
  foreach (keys %{$data}) {
    if ( $_ eq 'os' ) {
      foreach my $a (keys %{$data->{os}}) {
	$host_data->{$attrmap->{os}->{$a}} = $data->{os}->{$a};
      }
    } elsif ( ref($data->{$_}) eq 'ARRAY' ) {
      $host_data->{$attrmap->{$_}} = $data->{$_};
    } elsif ( $_ eq 'ipaddr' ) {
      $host_data->{$attrmap->{$_}} = "$data->{$_}";
    } else {
      $host_data->{$attrmap->{$_}} = "$data->{$_}";
    }
  }

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{machines},
		     filter => sprintf("(cn=%s)", $data->{hostname}),
		     attrs => [qw(
				   associatedDomain
				   grayDeviceMapping
				   grayHostName
				   grayHostingID
				   grayInstanceID
				   grayInstanceRegion
				   grayInstanceType
				   grayMasterAccount
				   grayOSArchitecture
				   grayOSDistribution
				   grayOSDistributionFamily
				   grayOSDistributionVersion
				   grayOSName
				   grayOSVersion
				   grayRAMSize
				   grayStatus
				   ipHostNumber
				)]};
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;
  $self->h_log($search->error);

  my ($msg, $diff, $add, $delete, $replace, $changes, $e_orig, $e_tmp);
  my $dn = sprintf("cn=%s,%s", $data->{hostname}, $self->{app}->{cfg}->{ldap}->{base}->{machines});
  if ($search->count) {
    foreach ($search->entry->attributes) {
      next if $_ eq $self->h_get_rdn($dn);
      $e_tmp = $search->entry->get_value($_, asref => 1);
      if ( scalar @$e_tmp == 1 ) {
	$e_orig->{$_} = $e_tmp->[0];
      } else {
	$e_orig->{$_} = $e_tmp;
      }
    }

    $diff = $self->h_hash_diff( $e_orig, $host_data);
    # $self->h_log($diff);

    if ( %{$diff->{added}} ) {
      push @$add, $_ => $diff->{added}->{$_} foreach (keys(%{$diff->{added}}));
      push @$changes, add => $add;
    }
    if ( %{$diff->{removed}} ) {
      push @$delete, $_ => [] foreach (keys(%{$diff->{removed}}));
      push @$changes, delete => $delete;
    }
    if ( %{$diff->{changed}} ) {
      push @$replace, $_ => $diff->{changed}->{$_}->{new} foreach (keys(%{$diff->{changed}}));
      push @$changes, replace => $replace;
    }

    if ($changes) {
      $msg = $ldap->modify($dn, $changes);
    } else {
      $msg = { status => 'ok', message => 'Host data is intact. No changes made.' };
    }
  } else {

    $host_data->{objectClass} = $self->{app}->{cfg}->{ldap}->{objectClass}->{machines};
    $host_data->{cn} = $data->{hostname};
    $host_data->{uid} = $data->{hostname};
    $msg = $ldap->add($dn, $host_data);
    $self->h_log( $msg );

  }

  $self->render(json => { result => $msg });
}

1;
