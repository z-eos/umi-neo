package Umi::Helpers::Common;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util;

use MIME::Base64 qw(decode_base64 encode_base64);
use Crypt::HSXKPasswd;
use File::Temp qw/ tempfile tempdir :POSIX /;
use File::Which qw(which);
use GD;
use GD::Barcode::QRcode;
use Try::Tiny;
use POSIX qw(strftime :sys_wait_h);
use IPC::Run qw(run);

use Data::Printer caller_info => 1;

sub register {
    my ($self, $app) = @_;

    $app->helper(
		 header_form_subsearch_button => sub {
		     my ($c, $text) = @_;
		     return uc($text);
		 });

    $app->helper(
		 h_pad_base64 => sub {
		     my ( $self, $to_pad ) = @_;
		     while (length($to_pad) % 4) {
			 $to_pad .= '=';
		     }
		     return $to_pad;
		 });

    $app->helper(
		 is_ascii => sub {
		     my ($self, $arg) = @_;
		     return defined $arg && $arg ne '' && $arg !~ /^[[:ascii:]]+$/ ? 1 : 0;
		 });

    $app->helper(
		 is_ip => sub {
		     my ($self, $arg) = @_;
		     return defined $arg && $arg ne '' && $arg =~ /^$self->{a}->{re}->{ip}$/ ? 1 : 0;
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

		     utf8::encode($arg->{txt}); # without it non latin in QR is broken

		     # log_debug { np($arg->{txt}) };
		     $arg->{ops} = {
				    Ecc        => $arg->{ecc},
				    ModuleSize => $arg->{mod},
				   };
		     if ( defined $args->{ver} ) {
			 $arg->{ver}            = $args->{ver};
			 $arg->{ops}->{Version} = $arg->{ver};
		     }
		     p $arg;
		     try {
			 $arg->{gd} = GD::Barcode::QRcode->new( "$arg->{txt}", $arg->{ops} )->plot();
			 $arg->{white} = $arg->{gd}->colorClosest(255,255,255);
			 $arg->{gd}->transparent($arg->{white});
			 $arg->{gd}->interlaced('true');
			 $arg->{ret}->{qr} = encode_base64($arg->{gd}->png);
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
		     my $arg = { type => $args->{key_type} || 'RSA',
				 bits => $args->{bits} || 2048,
				 name => $args->{name} };

		     my (@ssh, $res, $fh, $key_file, $kf);
		     my $to_which = 'ssh-keygen';
		     my $ssh_bin = which $to_which;
		     if ( defined $ssh_bin ) {
			 push @ssh, $ssh_bin;
		     } else {
			 push @{$res->{error}},  "command <code>$to_which</code> not found";
			 return $res;
		     }

		     if ( $arg->{type} eq 'RSA' ) {
			 $arg->{type} = 'rsa';
			 push @ssh, '-b', $arg->{bits};
		     } elsif ( $arg->{type} eq 'Ed25519' ) {
			 $arg->{type} = 'ed25519';
		     } elsif ( $arg->{type} eq 'ECDSA256' ) {
			 $arg->{type} = 'ecdsa';
			 push @ssh, '-b', 256;
		     } elsif ( $arg->{type} eq 'ECDSA384' ) {
			 $arg->{type} = 'ecdsa';
			 push @ssh, '-b', 384;
		     } elsif ( $arg->{type} eq 'ECDSA521' ) {
			 $arg->{type} = 'ecdsa';
			 push @ssh, '-b', 521;
		     }

		     (undef, $key_file) = tempfile('/tmp/.umi-ssh.XXXXXX', OPEN => 0, CLEANUP => 1);
		     # my $key_file = tmpnam();
		     my $date = strftime("%Y%m%d%H%M%S", localtime);

		     push @ssh, '-t', $arg->{type}, '-N', '', '-f', $key_file,
			 '-C', qq/$self->{a}->{re}->{sshpubkey}->{comment} $arg->{name}->{real} ( $arg->{name}->{email} ) on $date/;
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

# PWDGEN
$app->helper(
	     h_pwdgen => sub {
		 my ( $self, $par ) = @_;
		 # return {} if ! %$par;
		 my $cf = $app->{cfg}->{tool}->{pwdgen} // undef;
		 my $p =
		     {
		      pwd => $par->{pwd} // undef,
		      xk => {
			     case_transform            => $par->{xk_case_transform} // "RANDOM",
			     num_words                 => $par->{xk_num_words} // 5,
			     padding_characters_after  => $par->{xk_padding_characters_after} // 0,
			     padding_characters_before => $par->{xk_padding_characters_before} // 0,
			     padding_digits_after      => $par->{xk_padding_digits_after} // 0,
			     padding_digits_before     => $par->{xk_padding_digits_before} // 0,
			     padding_type              => $par->{xk_padding_type} // "NONE",
			     separator_character       => $par->{xk_separator_character_char} // "RANDOM",
			     word_length_max           => $par->{xk_word_length_max} // 8,
			     word_length_min           => $par->{xk_word_length_min} // 4
			    },
		      pnum => $par->{pwd_num} // $cf->{pnum} || 1,
		      palg => $par->{pwd_alg} // $cf->{palg} // $cf->{xk}->{preset_default} || 'XKCD',
		     };
		     
		 @{$p->{xk}->{separator_alphabet}} = split(//, $par->{xk_separator_alphabet})
		     if exists $par->{xk_separator_alphabet};
		 p $p;
		 if (! defined $p->{pwd} || $p->{pwd} eq '') {
		     ### password generation (not verification)
		     if ( defined $p->{palg} ) {

			 Crypt::HSXKPasswd->module_config('LOG_ERRORS', 1);
			 Crypt::HSXKPasswd->module_config('DEBUG', 0);
			 #??? my $default_config = Crypt::HSXKPasswd->default_config();
			 # all alg use same config structure, so here we fetch default
			 # config for pwd_alg and overwrite options with form input
			 my $xk_cf = Crypt::HSXKPasswd->preset_config( $p->{palg} );
			 p $xk_cf;
			 foreach (keys %{$xk_cf}) {
			     #$xk_cf->{$_} = $p->{xk}->{$_} if exists $p->{xk}->{$_};
			     $xk_cf->{$_} = $par->{'xk_'.$_} if exists $par->{'xk_'.$_};
			 }
			 $xk_cf->{separator_alphabet} = $p->{xk}->{separator_alphabet}
			     if $p->{xk}->{separator_character} eq 'RANDOM';
			 p $xk_cf;
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

}

1;
