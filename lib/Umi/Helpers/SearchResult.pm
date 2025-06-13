# -*- mode: cperl; eval(follow-mode); -*-

package Umi::Helpers::SearchResult;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util qw( b64_decode );

use Umi::Constants qw( DNS UMIAUTH );

use Encode qw(decode_utf8);
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

returns fa- class color to be used for the entry

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
		 } elsif ( $e->dn =~ /^pgpCertID=.*,$app->{cfg}->{ldap}->{base}->{pgp}/
			   && $e->exists('pgpKeyExpireTime')
			   && $time > generalizedTime_to_time($e->get_value('pgpKeyExpireTime')) ) {
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
				     strftime("%F %T UTC%z", gmtime($contextCSN)));
		    }
		  }
		  # $self->h_log( $res );
		  return $res;
	       });


  ### END OF REGISTER --------------------------------------------------------------------------------------------
}

1;
