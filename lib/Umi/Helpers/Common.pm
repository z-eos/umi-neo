# -*- mode: cperl; eval(follow-mode); -*-
#

package Umi::Helpers::Common;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util qw( b64_encode encode );

use Crypt::HSXKPasswd;
use File::Temp qw/ tempfile tempdir :POSIX /;
use File::Which qw(which);
use GD::Barcode::QRcode;
use GD;
use IPC::Run qw(run);
use List::Util qw(tail);
use MIME::Base64 qw(decode_base64 encode_base64);
use Net::CIDR::Set;
use Net::LDAP::Util qw(ldap_explode_dn);
use POSIX qw(strftime :sys_wait_h);
use Try::Tiny;
use Crypt::X509;
# use Crypt::X509::CRL;

sub register {

    ### BEGINNING OF REGISTER

    my ($self, $app) = @_;

    my $re = {
	      ip    => '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-5][0-9])',
	      net3b => '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}',
	      net2b => '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){1}',
	     };

    $app->helper(
		 header_form_subsearch_button => sub {
		     my ($c, $text) = @_;
		     return uc($text);
		 });

    $app->helper(
		 h_ldap_err => sub {
		     my ($c, $message, $search_arg) = @_;
		     return sprintf("
ERROR: %s
code: %s; text: %s
base: %s
filter: %s
attrs: %s\n", $message->error_name, $message->code // 'NO_MESSAGE_CODE',
				    $message->error_text // 'NO_MESSAGE_ERROR_TEXT',
				    $search_arg->{base} // 'NO_BASE',
				    $search_arg->{filter} // '(objectClass=*)',
				    exists $search_arg->{attrs} ? join(" ", @{$search_arg->{attrs}}) : 'NONE',
				   );
		   });

    $app->helper(
		 h_pad_base64 => sub {
		     my ( $self, $to_pad ) = @_;
		     while (length($to_pad) % 4) {
			 $to_pad .= '=';
		     }
		     return $to_pad;
		 });

=head2 h_is_ascii

checks whether the argument is ASCII

returns 0 if it is and 1 if not

=cut

    $app->helper(
		 h_is_ascii => sub {
		     my ($self, $arg) = @_;
		     return $arg // '' ne '' && $arg !~ /^[[:ascii:]]+$/ ? 1 : 0;
		 });

=head2 h_is_ip

checks whether the argument is ASCII

returns 0 if it is and 1 if not

=cut

    $app->helper(
		 h_is_ip => sub {
		     my ($self, $arg) = @_;
		     return $arg // '' ne '' && $arg =~ /^$re->{ip}$/ ? 1 : 0;
		 });

=head2 ipam_dec2ip

decimal IP to a dotted IP converter

stolen from http://ddiguru.com/blog/25-ip-address-conversions-in-perl

=cut

    $app->helper(
		 h_ipam_dec2ip => sub {
		   my ($self, $arg) = @_;
		   return join '.', unpack 'C4', pack 'N', $arg;
		 });

=head2 h_ipam_ip2dec

dotted IP to a decimal IP converter

stolen from http://ddiguru.com/blog/25-ip-address-conversions-in-perl

=cut

    $app->helper(
		 h_ipam_ip2dec => sub {
		   my ($self, $arg) = @_;
		   $arg //= '0.0.0.0';
		   return unpack N => pack 'C4' => split /\./ => $arg;
		 });

    $app->helper(
		 h_ipam_msk_ip2dec => sub {
		   my ($self, $arg) = @_;
		   $arg //= '0.0.0.0';
		   return (unpack 'B*' => pack 'N' => $self->h_ipam_ip2dec($arg)) =~ tr/1/1/;
		 });

    # most left attribute in dn
    $app->helper(
		 h_get_rdn => sub {
		   my ($self, $dn) = @_;
		   return (split(/=/, $dn))[0];
		 });



    # MAC address normalyzer
    $app->helper(
		 macnorm => sub {
		     my ( $c, $args ) = @_;
		     my $arg = {
				mac => $args->{mac},
				dlm => $args->{dlm} || '',
			       };
		     my $re1 = $self->{a}->{re}->{mac}->{mac48};
		     my $re2 = $self->{a}->{re}->{mac}->{cisco};
		     if ( ($arg->{mac} =~ /^$re1$/ || $arg->{mac} =~ /^$re2$/) &&
			  ($arg->{dlm} eq '' || $arg->{dlm} eq ':' || $arg->{dlm} eq '-') ) {
			 my $sep = $1 eq '.' ? '\.' : $1;
			 my @mac_arr = split(/$sep/, $arg->{mac});
			 @mac_arr = map { substr($_, 0, 2), substr($_, 2) } @mac_arr
			     if scalar(@mac_arr) == 3;
			 # log_debug { np(@mac_arr) };
			 return lc( join( $arg->{dlm}, @mac_arr ) );
		     } else {
			 return 0;
		     }
		 });

    # QR CODE
    $app->helper(
		 h_qrcode => sub {
		     my ($self, $args) = @_;
		     my $arg = {
				txt => $args->{toqr},
				ecc => $args->{ecc} || 'M',
				mod => $args->{mod} || 1,
			       };

		     $arg->{txt} = encode 'UTF-8', $arg->{txt}; # without it non latin in QR is broken

		     # log_debug { np($arg->{txt}) };
		     $arg->{ops} = {
				    Ecc        => $arg->{ecc},
				    ModuleSize => $arg->{mod},
				   };

		     $arg->{ver} = $arg->{ops}->{Version} = $args->{ver}
		       if defined $args->{ver};

		     try {
			 $arg->{gd} = GD::Barcode::QRcode->new( "$arg->{txt}", $arg->{ops} )->plot();
			 $arg->{white} = $arg->{gd}->colorClosest(255,255,255);
			 $arg->{gd}->transparent($arg->{white});
			 $arg->{gd}->interlaced('true');
			 $arg->{ret}->{qr} = b64_encode $arg->{gd}->png;
		     }
		     catch { $arg->{ret}->{error} = $_ . ' (in general max size is about 1660 characters of Latin1 codepage)'; };

		     return $arg->{ret};
		 });

=head2 keygen_ssh

ssh key generator

default key_type is RSA, default bits 2048

wrapper for ssh-keygen(1)

=cut

    $app->helper(
		 h_keygen_ssh => sub  {
		     my ( $self, $args ) = @_;

		     my $res;
		     if (!exists $app->{cfg}->{tool}->{ssh}) {
		       $res->{debug}->{error} = ['Configuration lacks SSH related section. Inform admins.'];
		       return $res;
		     }

		     my $arg = {
				type => $args->{key_type} // 'Ed25519',
				bits => $args->{bits} // 2048,
				name => $args->{name}
			       };

		     my (@ssh, $fh, $key_file, $kf);
		     my $to_which = 'ssh-keygen';
		     my $ssh_bin = which $to_which;
		     if ( defined $ssh_bin ) {
			 push @ssh, $ssh_bin;
		     } else {
			 push @{$res->{error}},  "command <code>$to_which</code> not found";
			 return $res;
		     }

		     # values of select element in form ssh-keygen
		     my %type_map = (
				     'RSA'      => ['rsa', $arg->{bits}],
				     'Ed25519'  => ['ed25519', undef],
				     'ECDSA256' => ['ecdsa', 256],
				     'ECDSA384' => ['ecdsa', 384],
				     'ECDSA521' => ['ecdsa', 521],
				    );

		     if (my $mapping = $type_map{$arg->{type}}) {
		       $arg->{type} = $mapping->[0];
		       push @ssh, '-b', $mapping->[1] if defined $mapping->[1];
		     }

		     (undef, $key_file) = tempfile('/tmp/.umi-ssh.XXXXXX', OPEN => 0, CLEANUP => 1);
		     # my $key_file = tmpnam();
		     my $date = strftime("%Y%m%d%H%M%S", localtime);

		     push @ssh, '-t', $arg->{type}, '-N', '', '-f', $key_file,
		       '-C', sprintf("%s %s (%s) on %s",
				     $app->{cfg}->{tool}->{ssh}->{comment} // 'Umi generated for',

				     $self->session->{user_obj}->{gecos}
				     // sprintf("%s %s",
						$self->session->{user_obj}->{givenname},
						$self->session->{user_obj}->{sn})
				     // 'noname',

				     $arg->{name}->{email}
				     // $self->session->{user_obj}->{mail}
				     // 'noemail',

				     $date);

		     $arg->{opt} = \@ssh;

		     my ($stdout, $stderr);
		     run \@ssh, '>', \$stdout, '2>', \$stderr || die "ERROR: ssh-keygen: $?";

		     # my $obj = new POSIX::Run::Capture(argv => [ @ssh ] );
		     # push @{$res->{error}},  $obj->errno if ! $obj->run;
		     # # log_debug { np($arg) };

		     push @{$res->{error}},
			 sprintf('<code>%s</code> exited with:
<dl class="row mt-4">
  <dt class="col-2 text-right">STDERR:</dt>
  <dd class="col-10 text-monospace"><small><pre>%s</pre></small></dd>
  <dt class="col-2 text-right">STDOUT:</dt>
  <dd class="col-10 text-monospace"><small><pre>%s</pre></small></dd>
</dl>',
				 join(' ', @{$arg->{opt}}),
				 $stderr,
				 $stdout)
			 if $stderr;

		     open($fh, '<', $key_file) or die "Cannot open file $key_file: $!";
		     {
			 local $/;
			 $arg->{key}->{pvt} = <$fh>;
		     }
		     close($fh) || die "Cannot close file $key_file: $!";
		     unlink $key_file || die "Could not unlink $key_file: $!";;

		     open($fh, '<', "$key_file.pub") or die "Cannot open file $key_file.pub: $!";
		     {
			 local $/;
			 $arg->{key}->{pub} = <$fh>;
		     }
		     close($fh) || die "Cannot close file $key_file.pub: $!";
		     unlink "$key_file.pub" || die "Could not unlink $key_file.pub: $!";;

		     $res->{private} = $arg->{key}->{pvt};
		     $res->{public}  = $arg->{key}->{pub};
		     $res->{public}  =~ s/[\n\r]//;
		     $res->{date}    = $date;

		     # log_debug { np($res) };
		     # log_debug { np($arg) };
		     return $res;
		 });

=head2 keygen_gpg

gpg key generator

default key_type is , default bits 2048

wrapper for gpg(1)

this method is supposed to work with the only one single key in keyring

=cut

    $app->helper(
		 h_keygen_gpg => sub {
		   my ( $self, $args ) = @_;

		   my $res;
		   if (!exists $app->{cfg}->{tool}->{gpg}) {
		     $res->{debug}->{error} = ['Configuration lacks GPG related section. Inform admins.'];
		     return $res;
		   }

		   my $arg = { bits     => $args->{bits}     // 4096,
			       key_type => $args->{key_type} // 'eddsa',
			       import   => $args->{import}   // '',
			       send_key => $args->{send_key} // 0,
			       name     => $args->{name} // { real  => "not signed in $$",
							      email => "not signed in $$" },
			     };

		   my $date = strftime('%Y%m%d%H%M%S', localtime);

		   $ENV{GNUPGHOME} = tempdir(TEMPLATE => '/var/tmp/.umi-gnupg.XXXXXX', CLEANUP => 1 );

 		   my ($key, @gpg, @run, $obj, $gpg_bin, $fh, $tf, $stdout, $stderr);
		   my $to_which = 'gpg';
		   $gpg_bin = which $to_which;
		   if ( defined $gpg_bin ) {
		     push @gpg, $gpg_bin, '--no-tty', '--yes', '--quiet';
		   } else {
		     push @{$res->{debug}->{error}},  "command <code>$to_which</code> not found";
		     $self->h_log($res);
		   }

		   if ( $arg->{import} ne '' ) {
		     ($fh, $tf) = tempfile( 'import.XXXXXX', DIR => $ENV{GNUPGHOME} );
		     if ( exists $arg->{import}->{key_file} && $arg->{import}->{key_file} ne '' ) {
		       print $fh $arg->{import}->{key_file};
		     } elsif ( exists $arg->{import}->{key_text} && $arg->{import}->{key_text} ne '' ) {
		       print $fh $arg->{import}->{key_text};
		     }
		     close $fh;
		     $stdout = $stderr = undef;
		     @run = (@gpg, '--import', $tf);
		     # $self->h_log(\@run);
		     run \@run, '>', \$stdout, '2>', \$stderr ||
		       push @{$res->{debug}->{error}},  $? >> 8, $stderr;

		   } else {
		     ### https://www.gnupg.org/documentation/manuals/gnupg-devel/Unattended-GPG-key-generation.html
		     ### https://lists.gnupg.org/pipermail/gnupg-users/2017-December/059622.html
		     ### Key-Type: default
		     ### Key-Length: $arg->{bits}
		     ### Subkey-Type: default

		     ($fh, $tf) = tempfile( 'batch.XXXXXX', DIR => $ENV{GNUPGHOME} );
		     if ($arg->{key_type} eq 'eddsa') {
		       print $fh <<"END_INPUT";
%echo Generating a GPG key
%no-protection
Key-Type: $arg->{key_type}
Key-Curve: Ed25519
Key-Usage: sign
Subkey-Type: ecdh
Subkey-Curve: Curve25519
Subkey-Usage: encrypt
Name-Real: $arg->{name}->{real}
Name-Email: $arg->{name}->{email}
Name-Comment: $app->{cfg}->{tool}->{gpg}->{comment} on $date
Expire-Date: $app->{cfg}->{tool}->{gpg}->{expire}
%commit
%echo Done
END_INPUT
		     } elsif ($arg->{key_type} eq 'RSA') {
		       print $fh <<"END_INPUT";
%echo Generating a GPG key
%no-protection
Key-Type: $arg->{key_type}
Key-Length: $arg->{bits}
Subkey-Type: $arg->{key_type}
Subkey-Length: $arg->{bits}
Name-Real: $arg->{name}->{real}
Name-Email: $arg->{name}->{email}
Name-Comment: $app->{cfg}->{tool}->{gpg}->{comment} on $date
Expire-Date: $app->{cfg}->{tool}->{gpg}->{expire}
%commit
%echo Done
END_INPUT
		     }

		     close $fh || die "Cannot close file $tf: $!";

		     @run = (@gpg, '--batch', '--gen-key', $tf);
		     # $self->h_log(\@run);
		     run \@run, '>', \$stdout, '2>', \$stderr ||
		       push @{$res->{debug}->{error}},
		       sprintf('<code>%s</code> exited with:
<dl class="row mt-4">
  <dt class="col-2 text-right">ERROR:</dt>
  <dd class="col-10 text-monospace"><small><pre>%s</pre></small></dd>
  <dt class="col-2 text-right">STDERR:</dt>
  <dd class="col-10 text-monospace"><small><pre>%s</pre></small></dd>
  <dt class="col-2 text-right">STDOUT:</dt>
  <dd class="col-10 text-monospace"><small><pre>%s</pre></small></dd>
</dl>',
			       join(' ', @run),
			       $? >> 8,
			       $stderr // '',
			       $stdout // '');

		   }
		   # $self->h_log($stdout);
		   # $self->h_log($stderr);

		   if ( !$? ) {
		     $stdout = $stderr = undef;
		     @run = (@gpg, '--list-keys', '--with-colons', '--fingerprint');
		     # $self->h_log(\@run);
		     run \@run, '>', \$stdout, '2>', \$stderr ||
		       push @{$res->{debug}->{error}},  $? >> 8, $stderr;
		     $stdout =~ /^fpr:{9}([A-F0-9]{40})/m;
		     $res->{fingerprint} = $1;
		     $arg->{fingerprint} = $1;
		     #$arg->{fingerprint} =~ tr/ \n//ds;
		     # log_debug { np($arg->{fingerprint}) };
		   }
		   # $self->h_log($stdout);
		   # $self->h_log($stderr);

		   if ( !$? ) {
		     $stdout = $stderr = undef;
		     @run = (@gpg, '--armor', '--export', $arg->{fingerprint});
		     # $self->h_log(\@run);
		     run \@run, '>', \$stdout, '2>', \$stderr ||
		       push @{$res->{debug}->{error}},  $? >> 8, $stderr;
		     # $self->h_log($res);
		     $arg->{key}->{pub} = $stdout;
		     $res->{public}   = $arg->{key}->{pub};
		   }
		   # $self->h_log($stdout);
		   # $self->h_log($stderr);

		   if ( !$? ) {
		     $stdout = $stderr = undef;
		     @run = (@gpg, '--fingerprint');
		     # $self->h_log(\@run);
		     run \@run, '>', \$stdout, '2>', \$stderr ||
		       push @{$res->{debug}->{error}}, $? >> 8, $stderr;
		     # $self->h_log($res);

		     if ( $arg->{import} eq '' ) {
		       $stdout = $stderr = undef;
		       @run = (@gpg, '--armor', '--export-secret-key', $arg->{fingerprint});
		       run \@run, '>', \$stdout, '2>', \$stderr ||
			 push @{$res->{debug}->{error}}, $? >> 8, $stderr;
		       # $self->h_log($res);
		       $arg->{key}->{pvt} = $stdout;
		       $res->{private} = $arg->{key}->{pvt};
		     }
		   }
		   # $self->h_log($stdout);
		   # $self->h_log($stderr);

		   if ( !$? ) {
		     $stdout = $stderr = undef;
		     @run = (@gpg, '--list-keys', $arg->{fingerprint});
		     # $self->h_log(\@run);
		     run \@run, '>', \$stdout, '2>', \$stderr ||
		       push @{$res->{debug}->{error}}, $? >> 8, $stderr;
		     # $self->h_log($res);
		     $arg->{key}->{lst}->{hr} = $stdout;
		     $res->{list_key} = $arg->{key}->{lst};
		   }
		   # $self->h_log($stdout);
		   # $self->h_log($stderr);

		   ### gpg2 --keyserver 'ldap://192.168.137.1/ou=Keys,ou=PGP,dc=umidb????bindname=uid=umi-admin%2Cou=People%2Cdc=umidb,password=testtest' --send-keys 79F6E0C65DF4EC16
		   if ( !$? && $arg->{send_key} ) {
		     $arg->{ldap}->{bindname} =~ s/,/%2C/g;
		     $stdout = $stderr = undef;
		     @run = (@gpg,
			     '--keyserver',
			     sprintf('ldap://%s:389/%s????bindname=%s,password=%s',
				     $arg->{ldap}->{server},
				     $arg->{ldap}->{base},
				     $arg->{ldap}->{bindname},
				     $arg->{ldap}->{password} ),
			     '--send-keys',
			     $arg->{fingerprint});
		     run \@run, '>', \$stdout, '2>', \$stderr ||
		       push @{$res->{debug}->{error}}, $? >> 8, $stderr;
		   } elsif ( !$stderr && ! $arg->{send_key} ) {
		     ## https://gnupg.org/documentation/manuals/gnupg/GPG-Input-and-Output.html#GPG-Input-and-Output
		     ## https://github.com/CSNW/gnupg/blob/master/doc/DETAILS
		     ## $arg->{key}->{lst}->{colons} indexes are -2 from described in DETAILS file
		     $stdout = $stderr = undef;
		     @run = (@gpg, '--with-colons', '--list-keys', $arg->{fingerprint});
		     run \@run, '>', \$stdout, '2>', \$stderr ||
		       push @{$res->{debug}->{error}}, $? >> 8, $stderr;
		     # $self->h_log($stdout);

		     %{$arg->{key}->{lst}->{colons}} =
		       map { (split(/:/, $_))[0] => [tail(-1, @{[split(/:/, $_)]})] }
		       split(/\n/, $stdout);

		     $arg->{key}->{snd} =
		       {
			objectClass => [ 'pgpKeyInfo' ],
			pgpSignerID => $arg->{key}->{lst}->{colons}->{pub}->[3],
			pgpCertID   => $arg->{key}->{lst}->{colons}->{pub}->[3],
			pgpKeyID    => substr($arg->{key}->{lst}->{colons}->{pub}->[3], 8),
			pgpKeySize  => sprintf("%05s", $arg->{key}->{lst}->{colons}->{pub}->[1]),
			pgpKeyType  => $arg->{key}->{lst}->{colons}->{pub}->[2],
			pgpRevoked  => 0,
			pgpDisabled => 0,
			pgpKey      => $arg->{key}->{pub},
			pgpUserID   => $arg->{key}->{lst}->{colons}->{uid}->[8],
			pgpSubKeyID => $arg->{key}->{lst}->{colons}->{sub}->[3],
			pgpKeyCreateTime => strftime('%Y%m%d%H%M%SZ', localtime($arg->{key}->{lst}->{colons}->{pub}->[4])),
			pgpKeyExpireTime => strftime('%Y%m%d%H%M%SZ', localtime($arg->{key}->{lst}->{colons}->{pub}->[5])),
		       };

		     $res->{send_key} = $arg->{key}->{snd};
		   }

		   #File::Temp::cleanup();

		   # $self->h_log($arg);
		   # $self->h_log($res);
		   return $res;
		 });

    # PWDGEN
    $app->helper(
		 h_pwdgen => sub {
		     my ( $self, $par ) = @_;
		     # return {} if ! %$par;
		     my $cf = $app->{cfg}->{tool}->{pwdgen} // undef;
		     my $p =
			 {
			  pwd => $par->{pwd_vrf} // undef,
			  xk => {
				 case_transform            => $par->{xk_case_transform} // 'RANDOM',
				 num_words                 => $par->{xk_num_words} // 5,
				 padding_characters_after  => $par->{xk_padding_characters_after} // 0,
				 padding_characters_before => $par->{xk_padding_characters_before} // 0,
				 padding_digits_after      => $par->{xk_padding_digits_after} // 0,
				 padding_digits_before     => $par->{xk_padding_digits_before} // 0,
				 padding_type              => $par->{xk_padding_type} // 'NONE',
				 separator_character       => $par->{xk_separator_character} // 'RANDOM',
				 separator_alphabet        => $par->{xk_separator_alphabet},
				 word_length_max           => $par->{xk_word_length_max} // 8,
				 word_length_min           => $par->{xk_word_length_min} // 4
				},
			  pnum => $par->{pwd_num} // $cf->{pnum} || 1,
			  palg => $par->{pwd_alg} // $cf->{palg} // $cf->{xk}->{preset_default} || 'XKCD',
			 };

		     if ($p->{xk}->{separator_character} eq 'CHAR') {
		       $p->{xk}->{separator_character} = $par->{xk_separator_character_char};
		     } elsif ($p->{xk}->{separator_character} eq 'RANDOM' && length($par->{xk_separator_character_random}) == 1) {
		       # !!! WARNING need to verify
		       $par->{xk_separator_character_random} .= $par->{xk_separator_character_random};
		     }

		     my @arr = split(//, $par->{xk_separator_character_random});
		     $p->{xk}->{separator_alphabet} = \@arr;

		     #p $p;
		     if (! defined $p->{pwd} || $p->{pwd} eq '') {
			 ### password generation (not verification)
			 if ( defined $p->{palg} ) {

			     Crypt::HSXKPasswd->module_config('LOG_ERRORS', 1);
			     Crypt::HSXKPasswd->module_config('DEBUG', 0);
			     ## ??? my $default_config = Crypt::HSXKPasswd->default_config();
			     ## all alg use same config structure, so here we fetch default
			     ## config for pwd_alg and overwrite options with form input
			     my $xk_cf = Crypt::HSXKPasswd->preset_config( $p->{palg} );
			     # p $xk_cf;
			     foreach (keys %{$xk_cf}) {
				 $xk_cf->{$_} = $p->{xk}->{$_} if exists $p->{xk}->{$_};
				 #$xk_cf->{$_} = $par->{'xk_'.$_} if exists $par->{'xk_'.$_};
			     }
			     $xk_cf->{separator_alphabet} = $p->{xk}->{separator_alphabet}
				 if $p->{xk}->{separator_character} eq 'RANDOM';
			     #p $xk_cf;
			     my $xk = Crypt::HSXKPasswd->new( config => $xk_cf );
			     $p->{pwd}->{clear}    = $xk->password( $p->{pnum} );
			     %{$p->{pwd}->{stats}} = $xk->stats();
			     $p->{pwd}->{status}   = $xk->status();

			 }
		     } elsif ( ref($p->{pwd}) ne 'HASH' ) {
			 ### password verification
			 $p->{tmp} = $p->{pwd};
			 delete $p->{pwd};
			 $p->{pwd}->{clear} = $p->{tmp};
		     }
		     # http://www.openldap.org/faq/data/cache/347.html
		     #
		     # RFC 2307 passwords (http://www.openldap.org/faq/data/cache/346.html)
		     # generation ( {SSHA} ) to be used as userPassword value.
		     #
		     # Prepares with Digest::SHA, password provided or autogenerated, to be
		     # used as userPassword attribute value
		     my $sha = Digest::SHA->new( $cf->{sha}->{alg} );
		     $sha->add($p->{pwd}->{clear});
		     $sha->add($cf->{sha}->{salt});
		     $p->{return} =
			 {
			  clear => $p->{pwd}->{clear},
			  # WARNING Mojo::Util->b64_encode produces wrong result
			  #ssha  => '{SSHA}' . $self->h_pad_base64($self->b64_encode( $sha->digest . $cf->{sha}->{salt}, ''))
			  ssha  => '{SSHA}' . $self->h_pad_base64(encode_base64( $sha->digest . $cf->{sha}->{salt}, ''))
			 };

		     $p->{return}->{stats}  = $p->{pwd}->{stats}  if $p->{pwd}->{stats};
		     $p->{return}->{status} = $p->{pwd}->{status} if $p->{pwd}->{status};

		     return $p->{return};
		 });

    ## HASH DIFF
    #
    # 1. It takes two hash references as input: the original hash and
    # the modified hash.
    #
    # 2. It iterates through the keys of the original hash to find
    # removed and changed keys.
    #
    # 3. It then iterates through the keys of the modified hash to
    # find added keys.
    #
    # 4. For changed keys, it stores both the old and new values.
    #
    # 5. It returns a hash reference containing four hashes: removed,
    # added, changed, and unchanged keys and their values.
    $app->helper(
		 h_hash_diff => sub {
		   my ($self, $original_ref, $modified_ref) = @_;
		   #$self->h_log($original_ref);
		   #$self->h_log($modified_ref);
		   my (%removed, %added, %changed, %unchanged);
		   # Find removed and changed keys
		   foreach my $key (keys %$original_ref) {
		     if (
			 !exists $modified_ref->{$key} ||
			 ( ref($modified_ref->{$key}) eq 'ARRAY' &&
			   (
			    @{$modified_ref->{$key}} == 0 ||
			    ( grep {$_ eq ''} @{$modified_ref->{$key}} ) == @{$modified_ref->{$key}}
			   )
			 )
			) {
		       $removed{$key} = $original_ref->{$key};
		     } elsif (ref($original_ref->{$key}) eq 'ARRAY' &&
			      ref($modified_ref->{$key}) eq 'ARRAY') {
		       my $arr_diff = $self->h_array_diff($original_ref->{$key},
							  $modified_ref->{$key});

		       if ( @{$arr_diff->{added}} != 0 || @{$arr_diff->{removed}} != 0 ) {
			 if (@{$arr_diff->{removed}} != 0) {
			   @{$modified_ref->{$key}} = grep {$_ ne ''} @{$modified_ref->{$key}};
			 }
			 $changed{$key} = {
					   old => $original_ref->{$key},
					   new => $modified_ref->{$key}
					  };
		       }
		     } elsif ($original_ref->{$key} ne $modified_ref->{$key}) {
		       $changed{$key} = {
					 old => $original_ref->{$key},
					 new => $modified_ref->{$key}
					};
		     } else {
		       $unchanged{$key} = $original_ref->{$key};
		     }
		   }
		   # Find added keys
		   foreach my $key (keys %$modified_ref) {
		     if (!exists $original_ref->{$key} &&
			 (
			  ( ref($modified_ref->{$key}) eq 'ARRAY' &&
			    @{$modified_ref->{$key}} != 0 &&
			    ( grep {$_ ne ''} @{$modified_ref->{$key}} ) > 0
			  ) ||
			  $modified_ref->{$key} ne ''
			 )
			) {
		       $added{$key} = $modified_ref->{$key};
		     }
		   }
		   return {
			   removed => \%removed,
			   added => \%added,
			   changed => \%changed,
			   unchanged => \%unchanged
			  };
		 });

    ## ARRAY DIFF
    #
    # 1. It takes two array references as input: the original array and
    # the modified array.
    #
    # 2. It creates hash maps of both arrays for efficient lookups.
    #
    # 3. It finds removed elements by checking which elements from the
    # original array don't exist in the modified array.
    #
    # 4. It finds added elements by checking which elements from the
    # modified array don't exist in the original array.
    #
    # 5. It finds unchanged elements by checking which elements from the
    # original array still exist in the modified array.
    #
    # 6. It returns a hash reference containing three arrays: removed,
    # added, and unchanged elements.
    $app->helper(
		 h_array_diff => sub {
		     my ($self, $original_ref, $modified_ref) = @_;

		     my %original = map { $_ => 1 } @$original_ref;
		     my %modified = map { $_ => 1 } @$modified_ref;

		     my @removed = grep { !exists $modified{$_} } @$original_ref;
		     my @added = grep { !exists $original{$_} } @$modified_ref;
		     my @unchanged = grep { exists $modified{$_} } @$original_ref;

		     return {
			     removed => \@removed,
			     added => \@added,
			     unchanged => \@unchanged
			    };
		 });

=head2 h_file2var

reading file to a string or array

TODO: error handling

=cut

    $app->helper(
		 h_file2var => sub {
		   my ( $self, $file, $final_message, $return_as_arr ) = @_;
		   my ( @file_in_arr,$file_in_str, $fh );

		   open($fh, '<', "$file") || die "Cannot open file $file: $!";
		   {
		     local $/;
		     if ( defined $return_as_arr && $return_as_arr == 1 ) {
		       while (<$fh>) {
			 chomp;
			 push @file_in_arr, $_;
		       }
		     } else {
		       local $/ = undef;
		       $file_in_str = <$fh>;
		     }
		   }
		   close($fh) || die "Cannot close file $file: $!";

		   return defined $return_as_arr && $return_as_arr == 1 ? \@file_in_arr : $file_in_str;
		 });

=head2 cert_info

data taken, generally, from

    openssl x509 -in target.crt -text -noout
    openssl crl  -inform der -in crl.der -text -noout

=cut

    $app->helper(
		 h_cert_info => sub {
		   my ( $self, $args ) = @_;
		   my $arg = {
			      attr => $args->{attr} || 'userCertificate;binary',
			      cert => $args->{cert},
			      ts => defined $args->{ts} && $args->{ts} ? $args->{ts} : "%a %b %e %H:%M:%S %Y",
			     };

		   my ( $cert, $key, $hex, $return );
		   if ( $arg->{attr} eq 'userCertificate;binary' ||
			$arg->{attr} eq 'cACertificate;binary' ) {
		     $cert = Crypt::X509->new( cert => join('', $arg->{cert}) );
		     if ( $cert->error ) {
		       return { 'error' => sprintf('Error on parsing Certificate: %s', $cert->error) };
		     } else {
		       return  {
				'Subject' => join(',',@{$cert->Subject}),
				'CN' => $cert->subject_cn,
				'Issuer' => join(',',@{$cert->Issuer}),
				'S/N' => $cert->serial,
				'Not Before' => strftime ($arg->{ts}, localtime($cert->not_before)),
				'Not  After' => strftime ($arg->{ts}, localtime( $cert->not_after)),
				'cert' => $arg->{cert},
				'error' => undef,
			       };
		     }
		   } elsif ( $arg->{attr} eq 'certificateRevocationList;binary' ) {
		     # $cert = Crypt::X509::CRL->new( crl => $arg->{cert} );
		     # if ( $cert->error ) {
		     #   return { 'error' => sprintf('Error on parsing CertificateRevocationList: %s', $cert->error) };
		     # } else {
		     #   $arg->{sn} = $cert->revocation_list;
		     #   foreach $key (sort (keys %{$arg->{sn}} )) {
		     # 	 $hex = sprintf("%X", $key);
		     # 	 $hex = length($hex) % 2 ? '0' . $hex : $hex;
		     # 	 $arg->{sn}->{$key}->{sn_hex} = $hex;
		     # 	 $arg->{sn}->{$key}->{revocationDate} =
		     # 	   strftime ($arg->{ts}, localtime($arg->{sn}->{$key}->{revocationDate}));
		     #   }
		     #   return {
		     # 	       'Issuer' => join(',',@{$cert->Issuer}),
		     # 	       'AuthIssuer' => join(',',@{$cert->authorityCertIssuer}),
		     # 	       'RevokedCertificates' => $arg->{sn},
		     # 	       'Update This' => strftime ($arg->{ts}, localtime($cert->this_update)),
		     # 	       'Update Next' => strftime ($arg->{ts}, localtime( $cert->next_update)),
		     # 	       'error' => undef,
		     # 	       'cert' => $arg->{cert},
		     # 	      };
		     # }
		   } else {
		     return { 'error' => sprintf('Unknown certificate type'), };
		   }
		 });

    ### END OF REGISTER
  }


1;
