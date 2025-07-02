# -*- mode: cperl; eval: (follow-mode 1); -*-

package Umi::Helpers::Common;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util qw( b64_encode b64_decode encode decode url_escape );

use Umi::Constants qw(RE TRANSLIT);

use Crypt::HSXKPasswd;
use Crypt::X509;
# use Crypt::X509::CRL;
use File::Temp qw/ tempfile tempdir :POSIX /;
use File::Which qw(which);
use GD::Barcode::QRcode;
use GD;
use IPC::Run qw(run);
use List::Util qw(tail);
use MIME::Base64 qw(decode_base64 encode_base64);
use Net::CIDR::Set;
use Net::LDAP::Util qw(ldap_explode_dn time_to_generalizedTime generalizedTime_to_time);
use POSIX qw(strftime :sys_wait_h);
use Text::Unidecode;
use Time::Piece;
use Try::Tiny;
use URI::Escape;


use Text::vCard::Addressbook;
use vCard::AddressBook;


sub register {

  my ($self, $app) = @_;

  my $re = RE; # defined in Umi::Constants;
  my $translit_subs = TRANSLIT; # defined in Umi::Constants;

  ### BEGINNING OF REGISTER

=head2 h_auth_basic

  my $ldap = $c->h_auth_basic;

Performs HTTP Basic Authentication and returns an authenticated C<Umi::Ldap>
object on success.

This helper inspects the C<Authorization> header in the incoming request,
expecting it to contain HTTP Basic credentials. If the credentials are
missing or invalid, it sets a C<WWW-Authenticate> response header and halts
the request with a 401 Unauthorized status.

On success, it constructs and returns an instance of L<Umi::Ldap>,
initialized with the provided username and password. The LDAP connection
must succeed (i.e., be a L<Net::LDAP> object) or authentication is
considered to have failed.

B<Returns>: C<Umi::Ldap> object on success, or halts request with a 401
response on failure.

B<Example>:

  sub some_action {
    my $self = shift;
    my $ldap = $self->h_auth_basic or return;
    ...
  }

=cut

  $app->helper( h_auth_basic => sub {
		  my  ($self) = @_;

		  my $auth = $self->req->headers->authorization || '';
		  # Expect "Basic <base64encoded>"
		  unless ( $auth && $auth =~ /^Basic\s+(.+)$/ ) {
		    $self->res->headers->www_authenticate('Basic realm="Protected Area"');
		    $self->render(text => 'Authentication required', status => 401);
		    $self->log->info(sprintf("=== connect from %s, unauthorized", $self->tx->remote_address));
		    return;
		  }

		  my $encoded = $1;
		  my $decoded = b64_decode($encoded) || '';
		  # Expect decoded string to be "username:password"
		  my ($user, $pass) = split /:/, $decoded, 2;

		  my $ldap = Umi::Ldap->new( $self->{app}, $user, $pass, 1 );
		  # $self->h_log(ref($ldap->ldap));
		  unless ( ref($ldap->ldap) eq 'Net::LDAP' ) {
		    $self->res->headers->www_authenticate('Basic realm="Protected Area"');
		    $self->render(text => 'Authentication required', status => 401);
		    $self->log->info(sprintf("=== connect from %s, user %s login failed", $self->tx->remote_address, $user));
		    return;
		  }
		  $self->log->info(sprintf("=== connect from %s, user %s authenticated", $self->tx->remote_address, $user));

		  return $ldap;
		});

  $app->helper(		 header_form_subsearch_button => sub {
			   my ($self, $text) = @_;
			   return uc($text);
			 });

  $app->helper( h_ldap_err => sub {
		  my ($self, $message, $search_arg) = @_;
		  return sprintf("
ERROR: %s
code: %s; text: %s
base: %s
filter: %s
attrs: %s\n",
				 $message->error_name,
				 $message->code // 'NO_MESSAGE_CODE',
				 $message->error_text // 'NO_MESSAGE_ERROR_TEXT',
				 $search_arg->{base} // 'NO_BASE',
				 $search_arg->{filter} // '(objectClass=*)',
				 exists $search_arg->{attrs} ? join(' ', @{$search_arg->{attrs}}) : 'NONE',
				);
		});

=head2 h_pad_base64

ensures a given Base64-encoded string is correctly padded by appending the
necessary C<=> characters.

  say $c->h_pad_base64('YWJjZA');   # Outputs 'YWJjZA=='
  say $c->h_pad_base64('dGVzdA');   # Outputs 'dGVzdA=='

=cut

  $app->helper( h_pad_base64 => sub {
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

  $app->helper( h_is_ascii => sub {
		  my ($self, $arg) = @_;
		  return $arg // '' ne '' && $arg !~ /^[[:ascii:]]+$/ ? 1 : 0;
		});

=head2 h_lrtrim

remove white space/s from both ends of each string

if string is "delim" delimited, then white space/s could be removed
before and after the delimiter (in most cases str is DN or RDN)

=head3 EXAMPLE

    in: `  uid=abc ,  ou=ABC  ,dc=DDD '
    ou: `uid=abc,ou=ABC,dc=DDD'

    in: `  abcABCDDD '
    ou: `abcABCDDD'

=cut

  $app->helper( h_lrtrim => sub {
		  my ($self, $args) = @_;
		  my $arg = { str => $args->{str},
			      delim => $args->{delim} || ',',
			      tosplit => $args->{tosplit} || 0, };
		  if ( $arg->{tosplit} ) {
		    my @ar = split(/$arg->{delim}/, $arg->{str});
		    $_ =~ s/^\s+|\s+$//g foreach @ar;
		    $arg->{res} = join( $arg->{delim}, @ar);
		  } else {
		    $arg->{str} =~ s/^\s+|\s+$//g;
		    $arg->{res} = $arg->{str};
		  }
		  return $arg->{res};
		});



=head2 h_csv_to_arr

  my $arr_ref = $c->h_csv_to_arr($csv_string);

Splits a comma-separated string into an array reference, trimming leading and trailing whitespace from each resulting element.

If the string does not contain a comma, a single-element array reference is returned with the trimmed input string.

Returns: array reference

=cut

$app->helper(h_csv_to_arr => sub {
  my ($self, $csv) = @_;
  return [ map { s/^\s+|\s+$//gr } split /,/, $csv ];
});


=head2 h_trim_leading_newlines

Removes all leading newline characters (`\n`, optionally preceded by `\r`) from the beginning of the input string.

=cut

  $app->helper(h_trim_leading_newlines => sub {
		 my ($self, $text) = @_;
		 return unless defined $text;
		 $text =~ s/^\R+//; # \R matches any newline sequence (\n, \r, \r\n, etc.)
		 return $text;
	       });

=head2 h_compact

removes empty string values from an array or a hash by modifying the data
structure in place

returns compacted array or hash

=cut

  $app->helper( h_compact => sub {
		  my ($self, $target) = @_;
		  if (ref $target eq 'ARRAY') {
		    # Filter out any undefined or empty string elements.
		    @$target = grep { defined($_) && $_ ne '' } @$target;
		  } elsif (ref $target eq 'HASH') {
		    # Remove hash keys with undefined or empty string values.
		    foreach my $key (keys %$target) {
		      delete $target->{$key}
			if ! defined($target->{$key}) || $target->{$key} eq '';
		    }
		  }
		  return $target;
		});

=head2 h_is_meaningful_arrayref

returns true if its single argument is:

    a reference to an array,
    not an empty array, and
    not an array containing just the empty string

    EXAMPLES:
    Case	Returns
    -------------------
    undef	false
    []		false
    [""]	false
    ["foo"]	true
    ["", "bar"]	true

=cut

  $app->helper( h_is_meaningful_arrayref => sub {
		  my ($self, $aref) = @_;
		  return 0 unless ref($aref) eq 'ARRAY';
		  return 0 if @$aref == 0;
		  return 0 if @$aref == 1 && $aref->[0] eq '';
		  return 1;
		});

=head2 h_is_ip_pair

checks whether the argument is a space delimited pair of ip addresses

returns 1 if it is and 0 if not

=cut

  $app->helper( h_is_ip_pair => sub {
		  my ($self, $arg) = @_;
		  return (($arg // '') ne '' && $arg =~ /^$re->{ip}\s+$re->{ip}$/) ? 1 : 0;
		});

=head2 h_telephonenumber

checks whether the argument is a comma delimited telephone numbers in
international notation

returns hash of two elements: a ref to an array of numbers parsed (empty on success)
and string of errors (empty on success)

=cut

  $app->helper( h_telephonenumber => sub {
		  my ($self, $str) = @_;
		  my (@num, $err, %t);
		  if ( $str =~ /[^\d\+\(\)\s,]/ ) {
		    return { num => \@num, err => 'Invalid characters. Only digits, plus sign, parentheses, spaces, and commas are allowed.' };
		  } else {
		    @num = split /\s*,\s*/, $str;  # Split the input by commas
		    @num = grep { $_ ne '' } @num; # Remove any empty elements

		    # Check the length of each phone number
		    foreach my $number (@num) {
		      my $digits_only = $number; # Count only digits in the phone number
		      $digits_only =~ s/[^\d]//g;
		      # Most phone numbers worldwide have between 7 and 15 digits
		      my $digit_count = length($digits_only);
		      if ($digit_count < 7 || $digit_count > 15) {
			$err .= "Number $number has $digit_count digits. Must be between 7 and 15. ";
		      }
		    }
		    # Normalize numbers: keep only digits and leading +
		    @num = map { s/[^\d\+]+//gr } @num;
		    $t{$_} = 1 foreach (@num);
		    @num = keys %t;
		    return { num => \@num, err => $err };
		  }
		});


=head2 h_is_ip

checks whether the argument is ip address

returns 1 if it is and 0 if not

=cut

  $app->helper( h_is_ip => sub {
		  my ($self, $arg) = @_;
		  return (($arg // '') ne '' && $arg =~ /^$re->{ip}$/) ? 1 : 0;
		});

=head2 ipam_dec2ip

decimal IP to a dotted IP converter

stolen from http://ddiguru.com/blog/25-ip-address-conversions-in-perl

=cut

  $app->helper( h_ipam_dec2ip => sub {
		  my ($self, $arg) = @_;
		  return join '.', unpack 'C4', pack 'N', $arg;
		});

=head2 h_ipam_ip2dec

dotted IP to a decimal IP converter

stolen from http://ddiguru.com/blog/25-ip-address-conversions-in-perl

=cut

  $app->helper( h_ipam_ip2dec => sub {
		  my ($self, $arg) = @_;
		  $arg //= '0.0.0.0';
		  return unpack N => pack 'C4' => split /\./ => $arg;
		});

  $app->helper( h_ipam_msk_ip2dec => sub {
		  my ($self, $arg) = @_;
		  $arg //= '0.0.0.0';
		  return (unpack 'B*' => pack 'N' => $self->h_ipam_ip2dec($arg)) =~ tr/1/1/;
		});

=head2 h_get_rdn

get RDN (name of the outmost left attribute) of the given DN

=cut

  $app->helper( h_get_rdn => sub {
		  my ($self, $dn) = @_;
		  return (split(/=/, $dn))[0];
		});

=head2 h_get_rdn_val

get RDN (outmost left attribute) value of the given DN

=cut

  $app->helper( h_get_rdn_val => sub {
		  my ($self, $dn) = @_;
		  return (split(/=/, (split(/,/, $dn))[0]))[1];
		});

=head2 h_macnorm

MAC address field value normalizator.

The standard (IEEE 802) format for printing MAC-48 addresses in
human-friendly form is six groups of two hexadecimal digits, separated by
hyphens (-) or colons (:), in transmission order (e.g. 01-23-45-67-89-ab or
01:23:45:67:89:ab ) is casted to the twelve hexadecimal digits without
delimiter.

For the examples above it will look: 0123456789ab

=over

=item mac

MAC address to process

=item dlm

I<delimiter>, if defined (allowed characters: `-` and `:`), then returned
mac is normalyzed to human-friendly form as six groups of two hexadecimal
digits, separated by this I<delimiter>

=back

=cut

  $app->helper( h_macnorm => sub {
		  my ( $self, $args ) = @_;
		  my $mac = $args->{mac};
		  my $dlm = $args->{dlm} // '';
		  my $re1 = $re->{mac}->{mac48};
		  my $re2 = $re->{mac}->{cisco};

		  # $self->h_log($args);
		  if ( $mac =~ /^$re1$/ || $mac =~ /^$re2$/ ) {
		    my $normalized = lc($mac);
		    $normalized =~ s/[-:\.]//g;
		    if ($dlm ne '') {
		      $normalized = join($dlm, $normalized =~ /(..)/g);
		    }
		    # $self->h_log($normalized);
		    return $normalized;
		  } else {
		    return 0;
		  }
		});

=head2 h_gen_id

get random id of length N passed as input, default is 8

=cut

  $app->helper( h_gen_id => sub {
		  my ($self, $len) = @_;
		  $len = $len // 8;
		  my @chars = ('A'..'Z', 'a'..'z', 0..9);
		  return join '', map { $chars[rand @chars] } 1 .. $len;
		});

=head2 h_decode_text

Attempt to decode the given C<$text> from UTF-8.

If decoding succeeds, the decoded string is returned.

If decoding fails or C<$text> is undefined, the optional C<$alt> is returned instead.

EXAMPLE:

  $decoded = $c->h_decode_text($text);
  $decoded = $c->h_decode_text($text, $alt);

=cut

  $app->helper(h_decode_text => sub {
		 my ($self, $text, $alt) = @_;
		 # $self->h_log($text);
		 return $alt unless defined $text;
		 my $decoded = decode 'UTF-8', $text;
		 # $self->h_log($decoded);
		 return $decoded ? $decoded : $alt;
	       });

=head2 h_translit

simple transliteration to ASCII with normalization to [a-zA-Z0-9.-_]

constant TRANSLATE includes comprehensive character mappings for major
European languages

=cut

  $app->helper( h_translit => sub {
		  my ($self, $in) = @_;
		  # $self->h_log($in);

		  # Ensure proper UTF-8 handling
		  $in = decode('UTF-8', $in) unless utf8::is_utf8($in);

		  # Sort by length (longest first) to handle multi-character mappings correctly
		  my @sorted_keys = sort { length($b) <=> length($a) } keys %$translit_subs;
		  # $self->h_log(\@sorted_keys);

		  for my $cyrillic (@sorted_keys) {
		    my $latin = $translit_subs->{$cyrillic};
		    $in =~ s/\Q$cyrillic\E/$latin/g;
		  }
		  # $self->h_log($in);

		  # Clean up: remove non-ASCII and normalize
		  $in =~ s/[^\x00-\x7F]//g; # Remove non-ASCII
		  $in =~ s/[^[:alnum:]._-]//g; # Keep only allowed characters
		  # $self->h_log($in);

		  return $in;
		});

=head2 h_maybe_percent_decode_utf8

Detects whether a string contains percent-encoded UTF-8 byte sequences
(e.g., "Bj%C3%B8rn"), and if so, decodes it into a proper UTF-8 Perl string.

Returns a scalar string, decoded as UTF-8 if appropriate.

=head3 Example

  my $s = "Bj%C3%B8rn";
  say maybe_percent_decode_utf8($s);  # prints "Bjørn"

=cut

  $app->helper( h_maybe_percent_decode_utf8 => sub {
		  my ($self, $s) = @_;

		  # Step 1: Check for percent-encoded patterns
		  if ( $s =~ /%[0-9A-Fa-f]{2}/ ) {
		    # Step 2: URI-decode
		    my $decoded = uri_unescape($s);

		    # Step 3: Decode only if not already flagged as UTF-8
		    # deprecated return is_utf8($decoded) ? $decoded : decode('UTF-8', $decoded);
		    return $self->h_decode_text($decoded);
		  }

		  return $s;

		});


=head1 h_as_struct_decode

decode attribute value if it is bytes and not characters

$obj_hash is ldap search->as_struct hash

=cut

  $app->helper( h_as_struct_decode => sub {
		  my  ($self, $obj_hash, $attr, $na) = @_;
		  $na = '<i class="text-muted text-opacity-50">unavailable</i>' if ! defined $na;
		  my $res = '';

		  if ( defined $obj_hash && ref($obj_hash) eq 'HASH' && exists $obj_hash->{$attr} ) {
		    $res = $self->h_decode_text($obj_hash->{$attr}->[0]);
		  } else {
		    $res = $na;
		  }
		  # $self->h_log( $res );
		  return $res;
	       });


=head2 h_qrcode

QR CODE generator

    toqr: text to generate QR code against
    ecc:  Ecc mode. M, L, H or Q (Default = M)
    mod:  size of modules (barcode unit) (Default = 1).
    html: 1 to genegate HTML do display QR code image

=cut

  $app->helper( h_qrcode => sub {
		  my ($self, $args) = @_;
		  my $arg = {
			     txt =>  $args->{toqr},
			     ecc =>  $args->{ecc}  || 'M',
			     mod =>  $args->{mod}  || 1,
			     html => $args->{html} || 1,
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
		    $arg->{ret}->{html} = sprintf('<div id="pwd-qr" class="mt-3"><img src="data:image/png;base64,%s" class="img-thumbnail bg-light align-top"></div>',
						  $arg->{ret}->{qr})
		      if $arg->{html} == 1;
		  }
		  catch { $arg->{ret}->{error} = $_ . ' (in general max size is about 1660 characters of Latin1 codepage)'; };
		  # $self->h_log($arg->{ret});
		  return $arg->{ret};
		});

=head2 h_img_info

returns hash ref `{ width => XX, height => YY }` of the image on input

=cut

  $app->helper( h_img_info => sub {
		  my ($self, $image) = @_;
		  my $i = GD::Image->new($image);
		  return { width  => $i->width,
			   height => $i->height };
		});

=head2 h_img_resize

resize image by default limits in config file: ldap->defaults->attr->jpegPhoto

return either image resized or an original

=cut

  $app->helper( h_img_resize => sub {
		  my ($self, $img, $size) = @_;

		  # Load the image
		  my $image = GD::Image->new($img) or die "ERROR: h_img_resize(): Cannot load image: $!";

		  # Get original dimensions
		  my ($width, $height) = $image->getBounds();

		  # Define max constraints
		  my $max_size = $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{jpegPhoto}->{max_size};
		  my $max_side = $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{jpegPhoto}->{max_side};

		  # Determine if resizing is needed
		  if ($width > $max_side || $height > $max_side || $size > $max_size) {

		    # Calculate new dimensions while maintaining aspect ratio
		    my ($new_width, $new_height) = ($width, $height);

		    if ($width > $max_side || $height > $max_side) {
		      if ($width > $height) {
			$new_width  = $max_side;
			$new_height = int(($height / $width) * $max_side);
		      } else {
			$new_height = $max_side;
			$new_width  = int(($width / $height) * $max_side);
		      }
		    }
		    my $resized = GD::Image->newTrueColor($new_width, $new_height);
		    $resized->copyResampled($image, 0, 0, 0, 0, $new_width, $new_height, $width, $height);

		    return $resized->jpeg($self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{jpegPhoto}->{quality});
		  } else {
		    return $img;
		  }

		});

=head2 keygen_ssh

ssh key generator

default key_type is RSA, default bits 2048

wrapper for ssh-keygen(1)

=cut

  $app->helper( h_keygen_ssh => sub  {
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
					     $self->session->{user_obj}->{givenname} // 'noname',
					     $self->session->{user_obj}->{sn} // 'noname'),

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

		  # $self->h_log($res);
		  # log_debug { np($arg) };
		  return $res;
		});

=head2 keygen_gpg

gpg key generator

default key_type is , default bits 2048

wrapper for gpg(1)

this method is supposed to work with the only one single key in keyring

=cut

  $app->helper( h_keygen_gpg => sub {
		  my ( $self, $args ) = @_;

		  my $res;
		  # Check if GPG configuration section exists in app config
		  if (!exists $app->{cfg}->{tool}->{gpg}) {
		    $res->{debug}->{error} = ['Configuration lacks GPG related section. Inform admins.'];
		    return $res;
		  }

		  # Set default parameters for key generation with fallback values
		  my $arg = { bits     => $args->{bits}     // 4096,    # Key size in bits (default 4096)
			      key_type => $args->{key_type} // 'eddsa',	# Crypto algorithm (default EdDSA)
			      import   => $args->{import}   // '',      # Import existing key data
			      send_key => $args->{send_key} // 0,       # Send to LDAP keyserver flag
			      name     => $args->{name} // { real  => "not signed in $$",   # Default user real name
							     email => "not signed in $$" }, # Default email
			      to_enc   => $args->{to_enc} // {} # text to encrypt with newly generated key
			    };

		  # Generate timestamp for key comment
		  my $date = strftime('%Y%m%d%H%M%S', localtime);

		  # Create temporary GPG home directory (auto-cleanup on exit)
		  $ENV{GNUPGHOME} = tempdir(TEMPLATE => '/var/tmp/.umi-gnupg.XXXXXX', CLEANUP => 1 );

		  my ($key, @gpg, @run, $obj, $gpg_bin, $fh, $tf, $stdout, $stderr, $exitcode);
		  # Locate GPG binary in system PATH
		  my $to_which = 'gpg';
		  $gpg_bin = which $to_which;
		  if ( defined $gpg_bin ) {
		    # Build base GPG command with standard options
		    push @gpg, $gpg_bin, '--no-tty', '--yes', '--quiet', '--status-fd=2';
		  } else {
		    # GPG binary not found - log error
		    push @{$res->{debug}->{error}},  "command <code>$to_which</code> not found";
		    $self->h_log($res);
		  }

		  $ENV{LANG} = 'C'; # for predictable (English) GPG output

		  # IMPORT MODE: Import existing GPG key from file or text
		  if ( $arg->{import} ne '' ) {
		    # Create temporary file for key import
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
		    $exitcode = run \@run, '>', \$stdout, '2>', \$stderr;
		    push @{$res->{debug}->{error}},  $? >> 8, $stderr unless $exitcode;

		  } else {
		    ###################################################################################################
		    # GENERATION MODE: Create new GPG key pair using batch file					      #
		    #												      #
		    #    References for unattended GPG key generation:						      #
		    #    https://www.gnupg.org/documentation/manuals/gnupg-devel/Unattended-GPG-key-generation.html   #
		    #    https://lists.gnupg.org/pipermail/gnupg-users/2017-December/059622.html		      #
		    #    Key-Type: default									      #
		    #    Key-Length: $arg->{bits}								      #
		    #    Subkey-Type: default									      #
		    ###################################################################################################

		    # Create batch file for unattended key generation
		    ($fh, $tf) = tempfile( 'batch.XXXXXX', DIR => $ENV{GNUPGHOME} );
		    if ($arg->{key_type} eq 'eddsa') {
		      # EdDSA key generation template (modern elliptic curve crypto)
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
		      # RSA key generation template (traditional crypto)
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

		    #############################
		    # GPG key generation        #
		    #############################
		    @run = (@gpg, '--batch', '--gen-key', $tf);
		    # $self->h_log(\@run);
		    $exitcode = run \@run, '>', \$stdout, '2>', \$stderr;
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
			      $stdout // '') unless $exitcode;
		  }

		  # $self->h_log($res->{debug});
		  # $self->h_log($stdout);
		  # $self->h_log($stderr);

		  #######################################################################
		  # Extract key fingerprint (unique 40-character hex identifier)        #
		  #######################################################################
		  if ( !$? ) {
		    $stdout = $stderr = undef;
		    @run = (@gpg, '--list-keys', '--with-colons', '--fingerprint');
		    # $self->h_log(\@run);
		    $exitcode = run \@run, '>', \$stdout, '2>', \$stderr;
		    push @{$res->{debug}->{error}},  $? >> 8, $stderr unless $exitcode;
		    # Parse fingerprint from colon-separated output
		    $stdout =~ /^fpr:{9}([A-F0-9]{40})/m;
		    $res->{fingerprint} = $1;
		    $arg->{fingerprint} = $1;
		    #$arg->{fingerprint} =~ tr/ \n//ds;
		    # log_debug { np($arg->{fingerprint}) };
		  }
		  # $self->h_log($stdout);
		  # $self->h_log($stderr);

		  ##################################################
		  # Export public key in ASCII armor format	   #
		  ##################################################
		  if ( !$? ) {
		    $stdout = $stderr = undef;
		    @run = (@gpg, '--armor', '--export', $arg->{fingerprint});
		    # $self->h_log(\@run);
		    $exitcode = run \@run, '>', \$stdout, '2>', \$stderr;
		    push @{$res->{debug}->{error}},  $? >> 8, $stderr unless $exitcode;
		    # $self->h_log($res);
		    $arg->{key}->{pub} = $stdout;
		    $res->{public}   = $arg->{key}->{pub};
		  }
		  # $self->h_log($stdout);
		  # $self->h_log($stderr);

		  #########################################################
		  # Encrypt $arg->{to_enc} if it is not an empty hash: {} #
		  #########################################################
		  if ( !$? && ref($arg->{to_enc}) eq 'HASH' && %{$arg->{to_enc}} ) {
		    foreach (keys %{$arg->{to_enc}}) {
		      $stdout = $stderr = undef;
		      @run = (@gpg, '--armor', '--encrypt', '--recipient', $arg->{fingerprint});
		      # $self->h_log(\@run);
		      $exitcode = run \@run, \$arg->{to_enc}->{$_}, \$stdout, '2>', \$stderr;
		      push @{$res->{debug}->{error}},  $? >> 8, $stderr unless $exitcode;
		      $res->{enc}->{$_} = $stdout;
		      # $self->h_log($stdout);
		      # $self->h_log($stderr);
		    }
		    # $self->h_log($res->{enc});
		  }

		  #############################
		  # Export private key	      #
		  #############################
		  if ( !$? ) {
		    $stdout = $stderr = undef;
		    @run = (@gpg, '--fingerprint');
		    # $self->h_log(\@run);
		    $exitcode = run \@run, '>', \$stdout, '2>', \$stderr;
		    push @{$res->{debug}->{error}}, $? >> 8, $stderr unless $exitcode;
		    # $self->h_log($res);

		    if ( $arg->{import} eq '' ) {
		      $stdout = $stderr = undef;
		      @run = (@gpg, '--armor', '--export-secret-key', $arg->{fingerprint});
		      $exitcode = run \@run, '>', \$stdout, '2>', \$stderr;
		      push @{$res->{debug}->{error}}, $? >> 8, $stderr unless $exitcode;
		      # $self->h_log($res);
		      $arg->{key}->{pvt} = $stdout;
		      $res->{private} = $arg->{key}->{pvt};
		    }
		  }
		  # $self->h_log($stdout);
		  # $self->h_log($stderr);

		  #########################################
		  # Get human-readable key listing	  #
		  #########################################
		  if ( !$? ) {
		    $stdout = $stderr = undef;
		    @run = (@gpg, '--list-keys', $arg->{fingerprint});
		    # $self->h_log(\@run);
		    $exitcode = run \@run, '>', \$stdout, '2>', \$stderr;
		    push @{$res->{debug}->{error}}, $? >> 8, $stderr unless $exitcode;
		    # $self->h_log($res);
		    $arg->{key}->{lst}->{hr} = $stdout;
		    $res->{list_key} = $arg->{key}->{lst};
		  }
		  # $self->h_log($stdout);
		  # $self->h_log($stderr);

		  ############################################################
		  # Send key to LDAP keyserver if requested or store in LDAP #
		  ############################################################
		  ### gpg2 --keyserver 'ldap://192.168.137.1/ou=Keys,ou=PGP,dc=umidb????bindname=uid=umi-admin%2Cou=People%2Cdc=umidb,password=testtest' --send-keys 79F6E0C65DF4EC16
		  if ( !$? && $arg->{send_key} ) {
		    # URL-encode commas in LDAP bind DN
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
		    $exitcode = run \@run, '>', \$stdout, '2>', \$stderr;
		    push @{$res->{debug}->{error}}, $? >> 8, $stderr unless $exitcode;
		    #} elsif ( !$stderr && ! $arg->{send_key} ) {
		  } else {

		    #########################################################################################################
		    # Prepare LDAP entry data for PGP key storage							    #
		    # References for GPG output parsing:								    #
		    #   https://gnupg.org/documentation/manuals/gnupg/GPG-Input-and-Output.html#GPG-Input-and-Output	    #
		    #   https://github.com/CSNW/gnupg/blob/master/doc/DETAILS						    #
		    #   $arg->{key}->{lst}->{colons} indexes are -2 from described in DETAILS file			    #
		    #########################################################################################################

		    $stdout = $stderr = undef;
		    @run = (@gpg, '--with-colons', '--list-keys', $arg->{fingerprint});
		    $exitcode = run \@run, '>', \$stdout, '2>', \$stderr;
		    push @{$res->{debug}->{error}}, $? >> 8, $stderr unless $exitcode;
		    # $self->h_log($stdout);

		    # Parse colon-separated GPG output into hash structure
		    %{$arg->{key}->{lst}->{colons}} =
		      map { (split(/:/, $_))[0] => [tail(-1, @{[split(/:/, $_)]})] }
		      split(/\n/, $stdout);

		    # Build LDAP entry attributes for pgpKeyInfo object class
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

		   $self->h_log($res->{debug});
		  # $self->h_log($res);
		  return $res;
		});

# noAI #   $app->helper( h_keygen_gpg => sub {
# noAI #		  my ( $self, $args ) = @_;
# noAI #
# noAI #		  my $res;
# noAI #		  if (!exists $app->{cfg}->{tool}->{gpg}) {
# noAI #		    $res->{debug}->{error} = ['Configuration lacks GPG related section. Inform admins.'];
# noAI #		    return $res;
# noAI #		  }
# noAI #
# noAI #		  my $arg = { bits     => $args->{bits}     // 4096,
# noAI #			      key_type => $args->{key_type} // 'eddsa',
# noAI #			      import   => $args->{import}   // '',
# noAI #			      send_key => $args->{send_key} // 0,
# noAI #			      name     => $args->{name} // { real  => "not signed in $$",
# noAI #							     email => "not signed in $$" },
# noAI #			    };
# noAI #
# noAI #		  my $date = strftime('%Y%m%d%H%M%S', localtime);
# noAI #
# noAI #		  $ENV{GNUPGHOME} = tempdir(TEMPLATE => '/var/tmp/.umi-gnupg.XXXXXX', CLEANUP => 1 );
# noAI #
# noAI #		  my ($key, @gpg, @run, $obj, $gpg_bin, $fh, $tf, $stdout, $stderr);
# noAI #		  my $to_which = 'gpg';
# noAI #		  $gpg_bin = which $to_which;
# noAI #		  if ( defined $gpg_bin ) {
# noAI #		    push @gpg, $gpg_bin, '--no-tty', '--yes', '--quiet';
# noAI #		  } else {
# noAI #		    push @{$res->{debug}->{error}},  "command <code>$to_which</code> not found";
# noAI #		    $self->h_log($res);
# noAI #		  }
# noAI #
# noAI #		  if ( $arg->{import} ne '' ) {
# noAI #		    ($fh, $tf) = tempfile( 'import.XXXXXX', DIR => $ENV{GNUPGHOME} );
# noAI #		    if ( exists $arg->{import}->{key_file} && $arg->{import}->{key_file} ne '' ) {
# noAI #		      print $fh $arg->{import}->{key_file};
# noAI #		    } elsif ( exists $arg->{import}->{key_text} && $arg->{import}->{key_text} ne '' ) {
# noAI #		      print $fh $arg->{import}->{key_text};
# noAI #		    }
# noAI #		    close $fh;
# noAI #		    $stdout = $stderr = undef;
# noAI #		    @run = (@gpg, '--import', $tf);
# noAI #		    # $self->h_log(\@run);
# noAI #		    run \@run, '>', \$stdout, '2>', \$stderr ||
# noAI #		      push @{$res->{debug}->{error}},  $? >> 8, $stderr;
# noAI #
# noAI #		  } else {
# noAI #		    ### https://www.gnupg.org/documentation/manuals/gnupg-devel/Unattended-GPG-key-generation.html
# noAI #		    ### https://lists.gnupg.org/pipermail/gnupg-users/2017-December/059622.html
# noAI #		    ### Key-Type: default
# noAI #		    ### Key-Length: $arg->{bits}
# noAI #		    ### Subkey-Type: default
# noAI #
# noAI #		    ($fh, $tf) = tempfile( 'batch.XXXXXX', DIR => $ENV{GNUPGHOME} );
# noAI #		    if ($arg->{key_type} eq 'eddsa') {
# noAI #		      print $fh <<"END_INPUT";
# noAI # %echo Generating a GPG key
# noAI # %no-protection
# noAI # Key-Type: $arg->{key_type}
# noAI # Key-Curve: Ed25519
# noAI # Key-Usage: sign
# noAI # Subkey-Type: ecdh
# noAI # Subkey-Curve: Curve25519
# noAI # Subkey-Usage: encrypt
# noAI # Name-Real: $arg->{name}->{real}
# noAI # Name-Email: $arg->{name}->{email}
# noAI # Name-Comment: $app->{cfg}->{tool}->{gpg}->{comment} on $date
# noAI # Expire-Date: $app->{cfg}->{tool}->{gpg}->{expire}
# noAI # %commit
# noAI # %echo Done
# noAI # END_INPUT
# noAI #		    } elsif ($arg->{key_type} eq 'RSA') {
# noAI #		      print $fh <<"END_INPUT";
# noAI # %echo Generating a GPG key
# noAI # %no-protection
# noAI # Key-Type: $arg->{key_type}
# noAI # Key-Length: $arg->{bits}
# noAI # Subkey-Type: $arg->{key_type}
# noAI # Subkey-Length: $arg->{bits}
# noAI # Name-Real: $arg->{name}->{real}
# noAI # Name-Email: $arg->{name}->{email}
# noAI # Name-Comment: $app->{cfg}->{tool}->{gpg}->{comment} on $date
# noAI # Expire-Date: $app->{cfg}->{tool}->{gpg}->{expire}
# noAI # %commit
# noAI # %echo Done
# noAI # END_INPUT
# noAI #		    }
# noAI #
# noAI #		    close $fh || die "Cannot close file $tf: $!";
# noAI #
# noAI #		    @run = (@gpg, '--batch', '--gen-key', $tf);
# noAI #		    # $self->h_log(\@run);
# noAI #		    run \@run, '>', \$stdout, '2>', \$stderr ||
# noAI #		      push @{$res->{debug}->{error}},
# noAI #		      sprintf('<code>%s</code> exited with:
# noAI # <dl class="row mt-4">
# noAI #   <dt class="col-2 text-right">ERROR:</dt>
# noAI #   <dd class="col-10 text-monospace"><small><pre>%s</pre></small></dd>
# noAI #   <dt class="col-2 text-right">STDERR:</dt>
# noAI #   <dd class="col-10 text-monospace"><small><pre>%s</pre></small></dd>
# noAI #   <dt class="col-2 text-right">STDOUT:</dt>
# noAI #   <dd class="col-10 text-monospace"><small><pre>%s</pre></small></dd>
# noAI # </dl>',
# noAI #			      join(' ', @run),
# noAI #			      $? >> 8,
# noAI #			      $stderr // '',
# noAI #			      $stdout // '');
# noAI #
# noAI #		  }
# noAI #		  # $self->h_log($stdout);
# noAI #		  # $self->h_log($stderr);
# noAI #
# noAI #		  if ( !$? ) {
# noAI #		    $stdout = $stderr = undef;
# noAI #		    @run = (@gpg, '--list-keys', '--with-colons', '--fingerprint');
# noAI #		    # $self->h_log(\@run);
# noAI #		    run \@run, '>', \$stdout, '2>', \$stderr ||
# noAI #		      push @{$res->{debug}->{error}},  $? >> 8, $stderr;
# noAI #		    $stdout =~ /^fpr:{9}([A-F0-9]{40})/m;
# noAI #		    $res->{fingerprint} = $1;
# noAI #		    $arg->{fingerprint} = $1;
# noAI #		    #$arg->{fingerprint} =~ tr/ \n//ds;
# noAI #		    # log_debug { np($arg->{fingerprint}) };
# noAI #		  }
# noAI #		  # $self->h_log($stdout);
# noAI #		  # $self->h_log($stderr);
# noAI #
# noAI #		  if ( !$? ) {
# noAI #		    $stdout = $stderr = undef;
# noAI #		    @run = (@gpg, '--armor', '--export', $arg->{fingerprint});
# noAI #		    # $self->h_log(\@run);
# noAI #		    run \@run, '>', \$stdout, '2>', \$stderr ||
# noAI #		      push @{$res->{debug}->{error}},  $? >> 8, $stderr;
# noAI #		    # $self->h_log($res);
# noAI #		    $arg->{key}->{pub} = $stdout;
# noAI #		    $res->{public}   = $arg->{key}->{pub};
# noAI #		  }
# noAI #		  # $self->h_log($stdout);
# noAI #		  # $self->h_log($stderr);
# noAI #
# noAI #		  if ( !$? ) {
# noAI #		    $stdout = $stderr = undef;
# noAI #		    @run = (@gpg, '--fingerprint');
# noAI #		    # $self->h_log(\@run);
# noAI #		    run \@run, '>', \$stdout, '2>', \$stderr ||
# noAI #		      push @{$res->{debug}->{error}}, $? >> 8, $stderr;
# noAI #		    # $self->h_log($res);
# noAI #
# noAI #		    if ( $arg->{import} eq '' ) {
# noAI #		      $stdout = $stderr = undef;
# noAI #		      @run = (@gpg, '--armor', '--export-secret-key', $arg->{fingerprint});
# noAI #		      run \@run, '>', \$stdout, '2>', \$stderr ||
# noAI #			push @{$res->{debug}->{error}}, $? >> 8, $stderr;
# noAI #		      # $self->h_log($res);
# noAI #		      $arg->{key}->{pvt} = $stdout;
# noAI #		      $res->{private} = $arg->{key}->{pvt};
# noAI #		    }
# noAI #		  }
# noAI #		  # $self->h_log($stdout);
# noAI #		  # $self->h_log($stderr);
# noAI #
# noAI #		  if ( !$? ) {
# noAI #		    $stdout = $stderr = undef;
# noAI #		    @run = (@gpg, '--list-keys', $arg->{fingerprint});
# noAI #		    # $self->h_log(\@run);
# noAI #		    run \@run, '>', \$stdout, '2>', \$stderr ||
# noAI #		      push @{$res->{debug}->{error}}, $? >> 8, $stderr;
# noAI #		    # $self->h_log($res);
# noAI #		    $arg->{key}->{lst}->{hr} = $stdout;
# noAI #		    $res->{list_key} = $arg->{key}->{lst};
# noAI #		  }
# noAI #		  # $self->h_log($stdout);
# noAI #		  # $self->h_log($stderr);
# noAI #
# noAI #		  ### gpg2 --keyserver 'ldap://192.168.137.1/ou=Keys,ou=PGP,dc=umidb????bindname=uid=umi-admin%2Cou=People%2Cdc=umidb,password=testtest' --send-keys 79F6E0C65DF4EC16
# noAI #		  if ( !$? && $arg->{send_key} ) {
# noAI #		    $arg->{ldap}->{bindname} =~ s/,/%2C/g;
# noAI #		    $stdout = $stderr = undef;
# noAI #		    @run = (@gpg,
# noAI #			    '--keyserver',
# noAI #			    sprintf('ldap://%s:389/%s????bindname=%s,password=%s',
# noAI #				    $arg->{ldap}->{server},
# noAI #				    $arg->{ldap}->{base},
# noAI #				    $arg->{ldap}->{bindname},
# noAI #				    $arg->{ldap}->{password} ),
# noAI #			    '--send-keys',
# noAI #			    $arg->{fingerprint});
# noAI #		    run \@run, '>', \$stdout, '2>', \$stderr ||
# noAI #		      push @{$res->{debug}->{error}}, $? >> 8, $stderr;
# noAI #		  } elsif ( !$stderr && ! $arg->{send_key} ) {
# noAI #		    ## https://gnupg.org/documentation/manuals/gnupg/GPG-Input-and-Output.html#GPG-Input-and-Output
# noAI #		    ## https://github.com/CSNW/gnupg/blob/master/doc/DETAILS
# noAI #		    ## $arg->{key}->{lst}->{colons} indexes are -2 from described in DETAILS file
# noAI #		    $stdout = $stderr = undef;
# noAI #		    @run = (@gpg, '--with-colons', '--list-keys', $arg->{fingerprint});
# noAI #		    run \@run, '>', \$stdout, '2>', \$stderr ||
# noAI #		      push @{$res->{debug}->{error}}, $? >> 8, $stderr;
# noAI #		    # $self->h_log($stdout);
# noAI #
# noAI #		    %{$arg->{key}->{lst}->{colons}} =
# noAI #		      map { (split(/:/, $_))[0] => [tail(-1, @{[split(/:/, $_)]})] }
# noAI #		      split(/\n/, $stdout);
# noAI #
# noAI #		    $arg->{key}->{snd} =
# noAI #		      {
# noAI #		       objectClass => [ 'pgpKeyInfo' ],
# noAI #		       pgpSignerID => $arg->{key}->{lst}->{colons}->{pub}->[3],
# noAI #		       pgpCertID   => $arg->{key}->{lst}->{colons}->{pub}->[3],
# noAI #		       pgpKeyID    => substr($arg->{key}->{lst}->{colons}->{pub}->[3], 8),
# noAI #		       pgpKeySize  => sprintf("%05s", $arg->{key}->{lst}->{colons}->{pub}->[1]),
# noAI #		       pgpKeyType  => $arg->{key}->{lst}->{colons}->{pub}->[2],
# noAI #		       pgpRevoked  => 0,
# noAI #		       pgpDisabled => 0,
# noAI #		       pgpKey      => $arg->{key}->{pub},
# noAI #		       pgpUserID   => $arg->{key}->{lst}->{colons}->{uid}->[8],
# noAI #		       pgpSubKeyID => $arg->{key}->{lst}->{colons}->{sub}->[3],
# noAI #		       pgpKeyCreateTime => strftime('%Y%m%d%H%M%SZ', localtime($arg->{key}->{lst}->{colons}->{pub}->[4])),
# noAI #		       pgpKeyExpireTime => strftime('%Y%m%d%H%M%SZ', localtime($arg->{key}->{lst}->{colons}->{pub}->[5])),
# noAI #		      };
# noAI #
# noAI #		    $res->{send_key} = $arg->{key}->{snd};
# noAI #		  }
# noAI #
# noAI #		  #File::Temp::cleanup();
# noAI #
# noAI #		  # $self->h_log($arg);
# noAI #		  # $self->h_log($res);
# noAI #		  return $res;
# noAI #		});

  # PWDGEN
  $app->helper( h_pwdgen => sub {
		  my ( $self, $par ) = @_;
		  # $self->h_log($par);
		  my ($xk, $error);
		  my $cf = $app->{cfg}->{tool}->{pwdgen} // undef;
		  my $p;
		  # as pwd_alg value, form returns preset name as class name defined in templates/protected/tool/pwdgen-create.html.ep
		  $p->{palg} = exists $par->{pwd_alg} ? uc substr($par->{pwd_alg}, 4) : $cf->{xk}->{preset_default};
		  $p->{pnum} = exists $par->{pwd_num} ? $par->{pwd_num} : $cf->{pnum};
		  if ( exists $par->{pwd_vrf} && $par->{pwd_vrf} ne '' ) {
		    $p->{pwd}->{clear} = $par->{pwd_vrf};
		  } elsif ( exists $par->{pwd_alg} && $par->{pwd_alg} eq 'alg-userdefined' ) {
		    $p->{pwd}->{clear} = $par->{pwd_userdefined};
		  } else {
		    $p->{pwd}->{clear} = undef;
		  }
		  # $self->h_log($p);

		  if (! defined $p->{pwd}->{clear} ) { #}|| $p->{pwd}->{clear} eq '') {
		    ##########################################
		    # PASSWORD GENERATION (not verification) #
		    ##########################################

		    Crypt::HSXKPasswd->module_config('DEBUG', $cf->{xk}->{cfg}->{DEBUG});
		    Crypt::HSXKPasswd->module_config('ENTROPY_WARNINGS', $cf->{xk}->{cfg}->{ENTROPY_WARNINGS});
		    Crypt::HSXKPasswd->module_config('LOG_ERRORS', $cf->{xk}->{cfg}->{LOG_ERRORS});
		    my $xk_cf = Crypt::HSXKPasswd->preset_config( $p->{palg} );
		    # $self->h_log($xk_cf);

		    if ( defined $par && ref($par) eq 'HASH' && exists $par->{xk_num_words} ) {
		      ###########################################################################################
		      # Crypt::HSXKPasswd(3) -> CONFIGURATION                                                   #
		      # sep-*, pad-* pch-* are defined in templates/protected/tool/pwdgen-create.html.ep        #
		      ###########################################################################################

		      if ( exists $par->{xk_separator_character} && $par->{xk_separator_character} eq 'sep-none' ) {
			$par->{xk_separator_character} = 'NONE';
			delete $par->{xk_separator_character_char};
			delete $par->{xk_separator_alphabet};
		      } elsif ( exists $par->{xk_separator_character} && $par->{xk_separator_character} eq 'sep-char' ) {
			$par->{xk_separator_character} = $par->{xk_separator_character_char};
			delete $par->{xk_separator_character_char};
			delete $par->{xk_separator_alphabet};
		      } elsif ( exists $par->{xk_separator_character} && $par->{xk_separator_character} eq 'sep-random' ) {
			$par->{xk_separator_character} = 'RANDOM';
			$par->{xk_separator_alphabet} = [ split //, $self->h_lrtrim({str => $par->{'xk_separator_alphabet'}}) ];
			delete $par->{xk_separator_character_char};
		      }

		      if ( exists $par->{xk_padding_type} && $par->{xk_padding_type} eq 'pad-none' ) {
			$par->{xk_padding_type} = 'NONE';
			delete $par->{xk_pad_to_length};
			delete $par->{xk_padding_alphabet};
			delete $par->{xk_padding_character};
			delete $par->{xk_padding_character_random};
			delete $par->{xk_padding_character_after};
			delete $par->{xk_padding_character_before};
			delete $par->{xk_padding_character_separator};
		      } elsif ( exists $par->{xk_padding_type} && $par->{xk_padding_type} eq 'pad-fixed' ) {
			$par->{xk_padding_type} = 'FIXED';
		      } elsif ( exists $par->{xk_padding_type} && $par->{xk_padding_type} eq 'pad-adaptive' ) {
			$par->{xk_padding_type} = 'ADAPTIVE';
		      }

		      if ( exists $par->{xk_padding_character} && $par->{xk_padding_character} eq 'pch-separator' ) {
			$par->{xk_padding_character} = 'SEPARATOR';
			delete $par->{xk_padding_alphabet};
		      } elsif ( exists $par->{xk_padding_character} && $par->{xk_padding_character} eq 'pch-random' ) {
			$par->{xk_padding_character} = 'RANDOM';
			$par->{xk_padding_alphabet} = [ split //, $self->h_lrtrim({str => $par->{'xk_padding_alphabet'}}) ];
		      } elsif ( exists $par->{xk_padding_character} && $par->{xk_padding_character} eq 'pch-character' ) {
			$par->{xk_padding_character} = $par->{xk_padding_character_char};
			delete $par->{xk_padding_character_char};
			delete $par->{xk_padding_alphabet};
		      }

		      # $self->h_log($par);

		      if (keys %{$par}) {
			my $j;
			foreach my $i (keys %{$par}) {
			  next if $i !~ /^xk_/;
			  $j = substr $i, 3;

			  if ( ! defined $par->{$i} ||
			       $par->{$i} eq '' ||
			       (exists $par->{$i} && exists $xk_cf->{$j} && $xk_cf->{$j} eq $par->{$i}) ) {
			    next;
			  } else {
			    $xk_cf->{$j} = $par->{$i};
			  }

			}
		      }
		      # $self->h_log($xk_cf);

		      try {
			$xk = Crypt::HSXKPasswd->new( config => $xk_cf );
		      }
		      catch { $error = $_; };
		      if ( ! defined $error ) {
			$p->{pwd}->{clear}    = $xk->password( $p->{pnum} );
			%{$p->{pwd}->{stats}} = $xk->stats();
			$p->{pwd}->{status}   = $xk->status();
		      } else {
			$self->h_log($error);
		      }
		    }
		  }
		  # elsif ( ref($p->{pwd}) ne 'HASH' ) {
		  #   #########################
		  #   # PASSWORD VERIFICATION #
		  #   #########################
		  #   $p->{return}->{clear} = $p->{pwd};
		  # }

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

		  $p->{return}->{error}  = $error  if $error;
		  $p->{return}->{stats}  = $p->{pwd}->{stats}  if exists $p->{pwd} && exists $p->{pwd}->{stats};
		  $p->{return}->{status} = $p->{pwd}->{status} if exists $p->{pwd} && exists $p->{pwd}->{status};

		  # $self->h_log($p);

		  return $p->{return};
		});

=head2 h_hash_diff

    1. It takes two hash references as input: the original hash and
    the modified hash.

    2. It iterates through the keys of the original hash to find
    removed and changed keys.

    3. It then iterates through the keys of the modified hash to
    find added keys.

    4. For changed keys, it stores both the old and new values.

    5. It returns a hash reference containing four hashes: removed,
    added, changed, and unchanged keys and their values.

    [
	[0] "add",
	[1] [
		[0] "roomNumber",
		[1] 2
	    ]
    ]

=cut

  $app->helper( h_hash_diff => sub {
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

=head2 h_array_diff

    1. It takes two array references as input: the original array and
    the modified array.

    2. It creates hash maps of both arrays for efficient lookups.

    3. It finds removed elements by checking which elements from the
    original array don't exist in the modified array.

    4. It finds added elements by checking which elements from the
    modified array don't exist in the original array.

    5. It finds unchanged elements by checking which elements from the
    original array still exist in the modified array.

    6. It returns a hash reference containing three arrays: removed,
    added, and unchanged elements.

=cut

  $app->helper( h_array_diff => sub {
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

  $app->helper( h_file2var => sub {
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

=head2 h_cert_info

data taken, generally, from

    openssl x509 -text -noout -in target.crt
    openssl crl  -text -noout -in crl.der -inform der

=cut

  $app->helper( h_cert_info => sub {
		  my ( $self, $args ) = @_;

		  # Validate input arguments
		  return { error => 'No certificate data provided' } unless $args->{cert};

		  my $attr = $args->{attr} // 'userCertificate;binary';
		  my $ts   = defined $args->{ts} && $args->{ts} ? $args->{ts} : "%a %b %e %H:%M:%S %Y";
		  my $cert;

		  if ( $attr eq 'userCertificate;binary' || $attr eq 'cACertificate;binary' ) {
		    # Parse X.509 certificate
		    $cert = Crypt::X509->new( cert => join('', $args->{cert}) );

		    return { error => sprintf('Error parsing certificate: %s', $cert->error) } if $cert->error;

		    return {
			    Subject      => join(',', @{ $cert->Subject }),
			    CN           => $cert->subject_cn,
			    Issuer       => join(',', @{ $cert->Issuer }),
			    'S/N'        => $cert->serial,
			    'Not Before' => strftime($ts, localtime($cert->not_before)),
			    'Not After'  => strftime($ts, localtime($cert->not_after)),
			    cert         => $args->{cert},
			    error        => undef,
			   };

		  } elsif ( $attr eq 'certificateRevocationList;binary' ) {
		    # !! TODO ¡¡
		    # Uncomment and implement CRL parsing when needed
		    # $cert = Crypt::X509::CRL->new( crl => $args->{cert} );
		    # return { error => sprintf('Error parsing CRL: %s', $cert->error) } if $cert->error;
		    # my %revoked;
		    # foreach my $key (sort keys %{ $cert->revocation_list }) {
		    #   my $hex = sprintf("%X", $key);
		    #   $hex = length($hex) % 2 ? '0' . $hex : $hex;
		    #   $revoked{$key} = {
		    #     sn_hex         => $hex,
		    #     revocationDate => strftime($ts, localtime($cert->revocation_list->{$key}->{revocationDate})),
		    #   };
		    # }
		    # return {
		    #   Issuer            => join(',', @{ $cert->Issuer }),
		    #   AuthIssuer        => join(',', @{ $cert->authorityCertIssuer }),
		    #   RevokedCertificates => \%revoked,
		    #   'Update This'     => strftime($ts, localtime($cert->this_update)),
		    #   'Update Next'     => strftime($ts, localtime($cert->next_update)),
		    #   cert             => $args->{cert},
		    #   error            => undef,
		    # };
		  }

		  return { error => 'Unknown certificate type' };
		}
	      );


=head2 h_btns_cp_save_from_element

helper to place two buttons to copy to clipboard and download as file a
content of an element with id passed to helper

on input expects:

    target_id:    mandatory
    file_name:    optional
    button_class: optional
    wrapper_class:optional
    mimetype:     optional
    qrcode:       optional

=cut

  $app->helper( h_btns_cp_save_from_element => sub {
		  my ($c, $target_id, $file_name, $button_class, $wrapper_class, $mimetype, $qrcode) = @_;

		  # Set default values if parameters are not provided
		  $target_id     ||= 'targetId';
		  $file_name     ||= 'element-' . $target_id . '-value.txt';
		  $button_class  ||= 'btn btn-secondary btn-sm';
		  $wrapper_class ||= '';
		  $mimetype      ||= 'text/plain';
		  $qrcode        ||= '';

		  my $qr_button = '';
		  $qr_button = '<a href="/tool/qrcode?toqr='
		    . url_escape($qrcode)
		    . '&mod=5" class="btn btn-secondary btn-sm"><i class="fa-solid fa-qrcode"></i></a>'
		    if length($qrcode);

		  my $html = qq{
<div class="btn-group $wrapper_class" id="h_btns_cp_save_from_element">
    <button type="button" class="$button_class" title="Copy to clipboard"
	    onclick="copyToClipboard('#$target_id')">
	<i class="fa-solid fa-copy"></i>
    </button>
    <button type="button" class="$button_class"  title="Download as text/plain"
	    onclick="downloadString(document.querySelector('#$target_id').innerText, '$mimetype', '$file_name')">
	<i class="fa-solid fa-download"></i>
    </button>
    $qr_button
</div>
	};

		  return $html;
		});

=head2 h_btn_cp_from_url

  %== h_btn_cp_from_url id => 'copy-ldif', title => 'Copy LDIF', text => '<i class="fa-solid fa-copy"></i>', js_func => sub { return "fetchLdif(params)" };

Renders a button which, when clicked, copies text returned by the provided JS expression (stringified) into the clipboard.

Options:
- id:        HTML id of the button.
- title:     Tooltip text.
- text:      Visible button label or HTML.
- js_func:   Subroutine reference that returns the JS expression which evaluates to a string to be copied.
	     something like this:
	     <script>
	       const params = {
		 base: <%= b($search_arg->{base})->quote %>,
		 filter: <%= b($search_arg->{filter})->quote %>,
		 scope: "<%= exists $search_arg->{scope} ? $search_arg->{scope} : 'sub' %>"
	       };

	       async function fetchLdif(params = {}) {
		 const query = new URLSearchParams({
		 base_dn: params.base,
		 search_filter: params.filter,
		 search_scope: params.scope
		 }).toString();
		 const baseUrl = '<%= url_for("get_searchresult_ldif")->to_abs %>';
		 const url = baseUrl + '?' + query;
		 // console.log(url);
		 const res = await fetch(url);
		 if (!res.ok) throw new Error("Network error");
		 return await res.text();
	       }
	     </script

=cut

  $app->helper( h_btn_cp_from_url => sub {
		  my ($self, %args) = @_;

		  my $id     = $args{id}     || 'btn-copy';
		  my $class  = $args{class}  || 'btn btn-sm btn-secondary';
		  my $title  = $args{title}  || 'Copy to clipboard';
		  my $text   = $args{text}   || '<i class="fa-solid fa-copy"></i>';
		  my $js     = $args{js_func} ? $args{js_func}->() : '""';

		  return qq{
<button id="$id" class="$class" title="$title">
  $text
</button>
<script>
  document.addEventListener('DOMContentLoaded', function () {
    const btn = document.getElementById('$id');
    if (!btn) return;
    btn.addEventListener('click', function () {
      (async () => {
	try {
	  const text = await ($js);
	  const temp = document.createElement("textarea");
	  temp.value = text;
	  document.body.appendChild(temp);
	  temp.select();
	  document.execCommand("copy");
	  document.body.removeChild(temp);
	  alert("Copied to clipboard");
	} catch (e) {
	  alert("Copy failed: " + e);
	}
      })();
    });
  });
</script>
};
		});

=head2 h_btn_save_from_url

  %== h_btn_save_from_url id => 'download-ldif', title => 'Download LDIF of this search result into text file', filename => 'searchresult.ldif', js_func => sub { return 'fetchLdif(params)' }

Helper that renders a HTML button element with the given C<id> and C<title>,
which, upon being clicked, fetches text data using the supplied JavaScript
function expression (provided by C<js_func>) and triggers download of that data
as a plain text file with name given in C<filename>.

=head3 Parameters

=over 4

=item * C<id>

String. Required. Will be used as the HTML C<id> of the button.

=item * C<title>

String. Optional. Will be used as the C<title> attribute (tooltip text).

=item * C<filename>

String. Optional. Default is C<data.txt>. Filename for the downloaded file.

=item * C<js_func>

CodeRef. Required. Must return a valid JavaScript expression that evaluates
into a Promise resolving to text content to be downloaded.

=back

=head3 Example Output

  <button id="download-ldif" class="btn btn-sm btn-secondary" title="Download LDIF">
    <i class="fa-solid fa-file-arrow-down"></i>
  </button>
  <script>
    document.addEventListener('DOMContentLoaded', () => {
      document.getElementById('download-ldif').addEventListener('click', async () => {
	const text = await fetchLdif(params);
	const blob = new Blob([text], { type: 'text/plain' });
	const link = document.createElement('a');
	link.href = URL.createObjectURL(blob);
	link.download = "searchresult.ldif";
	document.body.appendChild(link);
	link.click();
	document.body.removeChild(link);
      });
    });
  </script>

=cut

  $app->helper( h_btn_save_from_url => sub {
		  my ($self, %args) = @_;
		  my $t = localtime;

		  my $id       = $args{id}      || 'btn-download';
		  my $class    = $args{class}   || 'btn btn-sm btn-secondary';
		  my $title    = $args{title}   || 'Download as text file';
		  my $text     = $args{text}    || '<i class="fa-solid fa-file-arrow-down"></i>';
		  my $filename = $args{filename}|| 'searchresult-' . $t->datetime . '.ldif';
		  my $js       = $args{js_func} ? $args{js_func}->() : '""';

		  return qq{
<button id="$id" class="$class" title="$title">
  $text
</button>
<script>
document.addEventListener('DOMContentLoaded', function () {
  const btn = document.getElementById('$id');
  if (!btn) return;
  btn.addEventListener('click', function () {
    (async () => {
      try {
	const text = await ($js);
	const blob = new Blob([text], { type: 'text/plain' });
	const link = document.createElement('a');
	link.href = URL.createObjectURL(blob);
	link.download = '$filename';
	document.body.appendChild(link);
	link.click();
	document.body.removeChild(link);
      } catch (e) {
	alert("Download failed: " + e);
      }
    })();
  });
});
</script>
};
		});

=head2 h_nested_params

helper to convert parameters with names like `hosts[0]` into a nested array structure

empty parameters are ignored

=cut

  $app->helper( h_nested_params => sub {
		  my $c = shift;
		  my $params = $c->req->params->to_hash;
		  my %nested;

		  for my $key (keys %$params) {
		    if ($key =~ /^(\w+)\[(\d+)\]$/) {
		      if ( ref($params->{$key}) eq 'ARRAY' ) {
			# For keys like hosts[0], memberUid[1], etc.
			$nested{$1}[$2] = $params->{$key};
		      } else {
			push @{$nested{$1}[$2]}, $params->{$key};
		      }
		    } else {
		      $nested{$key} = $params->{$key} if $params->{$key} ne '';
		    }
		  }
		  return \%nested;
		});

=head2 h_is_empty_nested_arr

verify that an array reference is equal to `[ [] ]`

=cut

  $app->helper( h_is_empty_nested_arr => sub {
		  my ($self, $arr) = @_;
		  # $self->h_log(ref($arr) eq 'ARRAY'
		  #   && scalar(@$arr) == 1
		  #   && ref($arr->[0]) eq 'ARRAY'
		  #   && scalar(@{ $arr->[0] }) == 0);
		  return ref($arr) eq 'ARRAY'
		    && scalar(@$arr) == 1
		    && ref($arr->[0]) eq 'ARRAY'
		    && scalar(@{ $arr->[0] }) == 0;
		});

=head2 h_ts_to_generalizedTime

convert timestamp like YYYY-mm-dd to YYYYmmdd000000Z

=cut

  $app->helper( h_ts_to_generalizedTime => sub {
		  my ($self, $date, $format) = @_;
		  $format = '%Y-%m-%d' if ! defined $format;
		  my $t = Time::Piece->strptime($date, $format);
		  my $res = time_to_generalizedTime($t->epoch) if defined $t;
		  return $res;
		});

=head2 h_years_since

calculates number of full years since date

=cut

  $app->helper( h_years_since => sub {
		  my ($self, $date) = @_;
		  my $then = localtime( generalizedTime_to_time($date) );
		  my $now  = localtime();
		  my $years = $now->year - $then->year;

		  # Adjust if current date is before anniversary in the current year
		  $years--
		    if $now->mon < $then->mon || ($now->mon == $then->mon && $now->mday < $then->mday);

		  return $years;
		});

=head2 h_get_value_safe

  my $val = $self->h_get_attr_safe($entry, 'attr');

Return the first value of attribute C<attr> from a L<Net::LDAP::Entry> object C<$entry>,
or undef if the attribute is absent or empty.

Silent on missing attributes. Suitable for use with C<get_value()> on entries returned
by C<Net::LDAP::Search>.

=cut

  $app->helper( h_get_value_safe => sub {
		  my ($self, $entry, $attr) = @_;
		  return undef unless $entry && $attr && $entry->exists($attr);
		  my $val = $entry->get_value($attr);
		  return defined($val) && length($val) ? $val : undef;
		});


  # =head2 h_domains_to_hash

  # convert an array of domain names into a hash where the keys are the
  # second-level domain names (SLDs) and the values are arrays of
  # top-level domain names (TLDs) for each SLD

  # =cut

  #     $app->helper( h_domains_to_hash => sub {
  #		   my ($self, $domains) = @_;
  #		   #$self->h_log($domains);
  #		   # Hash to group domains by their SLD
  #		   my %grouped_domains;
  #		   foreach my $domain (@$domains) {
  #		     if ($domain =~ /^(?:.*\.)?([^.]+)\.([^.]+)$/) {
  #		       my ($tld, $sld) = ($1, $2);
  #		       push @{ $grouped_domains{$sld} }, $tld;
  #		     }
  #		   }
  #		   $self->h_log(%grouped_domains);

  #		   # Sort TLDs within each SLD group
  #		   foreach my $sld (keys %grouped_domains) {
  #		     my @sorted_tlds = sort @{ $grouped_domains{$sld} };
  #		     $grouped_domains{$sld} = \@sorted_tlds;
  #		   }

  #		   return \%grouped_domains;
  #		 });


=head2 h_branch_add_if_not_exists

the subroutine accepts several arguments (the object itself as $self,
a hashref of parameters $p, the LDAP connection object $ldap, a root
entry $root and a debug hashref $debug).

It builds the branch DN, checks if it already exists, and if not,
constructs the branch attributes and adds the entry via LDAP.

Finally, it pushes any messages into the debug hash and returns the
result of the LDAP add operation (or nothing if the entry already
exists).

EXAMPLE

    my $result = $self->add_branch_if_not_exists($p, $ldap, $root, $debug, $dry_run);

=cut

  $app->helper( h_branch_add_if_not_exists => sub {
		  my ($self, $p, $ldap, $root, $debug, $dry_run) = @_;

		  $dry_run = 0 if ! defined $dry_run;

		  # Build the branch DN from the provided parameters.
		  my $br_dn = sprintf('authorizedService=%s@%s,%s',
				      $p->{authorizedService},
				      $p->{associatedDomain},
				      $root->dn
				     );

		  # Search for an existing entry with that DN.
		  my $if_exist = $ldap->search({
						base  => $br_dn,
						scope => 'base',
						attrs => [ 'authorizedService' ],
					       });

		  # If an entry exists, do nothing.
		  if ($if_exist->count) {
		    return { br_dn => $br_dn };
		  } else {
		    # Build a UID. If $p->{login} exists, use it; otherwise use lowercased "givenName.sn" from $root.
		    my $uid = sprintf('%s@%s_%s',
				      $p->{authorizedService},
				      $p->{associatedDomain},
				      exists $p->{login}
				      ? $p->{login}
				      : lc(sprintf("%s.%s", $root->get_value('givenName'), $root->get_value('sn')))
				     );

		    # Construct the branch attributes.
		    my $br_attrs = {
				    uid               => $uid,
				    objectClass       => [ @{$self->{app}->{cfg}->{ldap}->{objectClass}->{acc_svc_branch}} ],
				    associatedDomain  => $p->{associatedDomain},
				    authorizedService => sprintf('%s@%s',
								 $p->{authorizedService},
								 $p->{associatedDomain}),
				   };

		    # Add branch entry to LDAP.
		    my $msg;
		    if ( $dry_run == 0 ) {
		      $msg = $ldap->add($br_dn, $br_attrs);
		    } else {
		      $msg = { status => 'ok',
			       message => sprintf('DRYRUN: h_branch_add_if_not_exists() ldap->add dn: %s', $br_dn) }
		    }
		    if ($msg) {
		      push @{$debug->{$msg->{status}}}, $msg->{message};
		    }
		    return { br_dn => $br_dn, msg => $msg };
		  }
		});

=head2 h_service_add_if_not_exists

the subroutine accepts

    $self  the current object (so you can use its helpers and configuration)
    $p     a hash reference of parameters
    $ldap  an LDAP connection object
    $root  an LDAP entry object (used to retrieve attribute values like givenName and sn)
    $br    a hash reference containing the branch DN (i.e. $br->{br_dn})
    $debug a hash reference for collecting debug messages
    $dry_run if set to 1 then LDAP add not done

The subroutine constructs the service DN, determines the required
attributes (using schema information and placeholder substitution),
and finally calls $ldap->add(...). It also pushes status messages into
the debug structure. (You may adjust the return value as needed; here
it returns an empty hashref in the success case.)

EXAMPLE

    my $result = $self->add_branch_if_not_exists($p, $ldap, $root, $br, $debug);

=cut

  $app->helper( h_service_add_if_not_exists => sub {
		  my ($self, $p, $ldap, $root, $br, $debug, $dry_run) = @_;

		  $dry_run = 0 if ! defined $dry_run;

		  $self->h_log($p) if $dry_run == 1;

		  $p->{login} = $self->h_macnorm({mac => $p->{login}}) if $p->{authorizedService} eq 'dot1x-eap-md5';

		  ## TODO: IN SLAPD CONFIG TO INDEX ALL WHAT IS SEARCHED

		  # Construct the service DN using parameters from $p and configuration.
		  my ($ci, $rdn_val);
		  if ( exists $p->{'userCertificate;binary'} ) {
		    $ci = $self->h_cert_info({ cert => $p->{'userCertificate;binary'}, ts => "%Y%m%d%H%M%S" });
		    $rdn_val = $ci->{CN};
		  } elsif (exists $p->{login}) {
		    $rdn_val = $p->{login};
		  } else {
		    $rdn_val = $self->h_get_root_uid_val( $p->{dn_to_new_svc} );
		  }
		  my $svc_dn = sprintf(
				       '%s=%s,%s',
				       (exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{rdn}
					? $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{rdn}
					: $self->{app}->{cfg}->{ldap}->{defaults}->{rdn}),
				       $rdn_val,
				       $br->{br_dn}
				      );
		  # Search for an existing entry with that DN.
		  my $if_exist = $ldap->search({
						base  => $svc_dn,
						scope => 'base',
						attrs => [qw(uid authorizedService)],
					       });

		  # If an entry exists, do nothing.
		  return { svc_dn => $svc_dn } if $if_exist->count;

		  # Build a hash of all object classes from the LDAP schema.
		  my %objectclasses = map { $_->{name} => $_ } $ldap->schema->all_objectclasses;
		  my $schema = $ldap->schema;
		  my ($all_sup, $svc_attrs_must, $svc_attrs_may);
		  $all_sup = {}; $svc_attrs_must = {}; $svc_attrs_may = {};

		  # For each objectClass configured for the authorized service,
		  # mark it and all its superior classes.
		  foreach my $oc_name (@{$self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{objectClass}}) {
		    $all_sup->{$oc_name} = 1;
		    my @sup = $ldap->get_all_superior_classes($schema, $oc_name);
		    $all_sup->{$_} = 1 for @sup;
		  }

		  # Log the current (empty) must/may attributes (for debugging)
		  # $self->h_log($svc_attrs_must);
		  # $self->h_log($svc_attrs_may);

		  # Build counters for required (must) and optional (may) attributes.
		  foreach my $oc (keys %$all_sup) {
		    if (exists $objectclasses{$oc}->{must}) {
		      foreach my $attr (@{$objectclasses{$oc}->{must}}) {
			if ($attr eq 'userid') {
			  $svc_attrs_must->{uid}++;
			} elsif ($attr eq 'userCertificate') {
			  $svc_attrs_must->{'userCertificate;binary'}++;
			} else {
			  $svc_attrs_must->{$attr}++;
			}
		      }
		    }
		    if (exists $objectclasses{$oc}->{may}) {
		      foreach my $attr (@{$objectclasses{$oc}->{may}}) {
			next unless exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$attr};
			if ($attr eq 'userid') {
			  $svc_attrs_may->{uid}++;
			} elsif ($attr eq 'userCertificate') {
			  $svc_attrs_may->{'userCertificate;binary'}++;
			} else {
			  $svc_attrs_may->{$attr}++;
			}
		      }
		    }
		  }
		  # $self->h_log($svc_attrs_must);
		  # $self->h_log($svc_attrs_may);

		  # Determine the last uidNumber. Use a filter if defined in config.
		  my $uidNumber_last;
		  if (exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{last_num_filter}) {
		    $uidNumber_last =
		      $ldap->last_num(
				      undef,
				      $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{last_num_filter},
				      undef,
				      'sub'
				     );
		  } else {
		    $uidNumber_last = $ldap->last_num;
		  }

		  # Generate a password (and other related values) for the service entry.
		  my $pwd = $self->h_pwdgen;
		  my $svc_attrs = {};
		  my %svc_details;

		  # Set the objectClass attribute from configuration.
		  $svc_attrs->{objectClass} = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{objectClass};

		  # Process each data field defined in the configuration.
		  foreach my $df (@{$self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{data_fields}}) {
		    if ($df eq 'login') {
		      $svc_attrs->{uid} = $rdn_val;
		      $self->h_log($svc_attrs->{uid});
		      $svc_details{uid} = $svc_attrs->{uid};
		    } elsif ($df eq 'userPassword') {
		      $svc_attrs->{userPassword} = exists $p->{password2}
			? $p->{password2}
			: $pwd->{ssha};
		      $svc_details{userPassword} = $pwd->{clear};
		    } elsif ($df eq 'sshKeyText' || $df eq 'sshKeyFile') {
		      push @{$svc_attrs->{sshPublicKey}}, $p->{$df} if exists $p->{$df} && $p->{$df} ne '';
		    } elsif (!exists $p->{$df}) {
		      if (exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$df . '_prefix'}) {
			$svc_attrs->{$df} = sprintf(
						    "%s/%s.%s",
						    $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$df . '_prefix'},
						    lc $root->get_value('givenName'),
						    lc $root->get_value('sn')
						   );
		      } elsif (exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$df}) {
			$svc_attrs->{$df} = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$df};
		      }
		    } else {
		      $svc_attrs->{$df} = $p->{$df};
		    }
		  }


		  ############################################################################
		  # Substitute placeholders like: `%uid%`, `%associatedDomain%`, etc.	     #
		  ############################################################################
		  my %replace;
		  $replace{'%associatedDomain%'} = $svc_attrs->{associatedDomain} if exists $svc_attrs->{associatedDomain};
		  $replace{'%givenName%'} = $root->get_value('givenName') if $root->exists('givenName');
		  $replace{'%sn%'} = $root->get_value('sn') if $root->exists('sn');
		  $replace{'%sshPublicKey%'} = $p->{sshPublicKey} // [];
		  $replace{'%mailLocalAddress%'} = $root->get_value('mail') if $root->exists('mail');
		  $replace{'%gecos%'} = $self->h_get_value_safe( $root, 'gecos' )
		    // join(' ', grep defined,
			    $self->h_get_value_safe( $root, 'givenName' ),
			    $self->h_get_value_safe( $root, 'sn' ))
		    // undef;

		  if ( exists $p->{'userCertificate;binary'} ) {
		    $replace{'%umiUserCertificateSn%'} = '' . $ci->{'S/N'};
		    $replace{'%umiUserCertificateNotBefore%'} = $ci->{'Not Before'};
		    $replace{'%umiUserCertificateNotAfter%'} = $ci->{'Not After'};
		    $replace{'%umiUserCertificateSubject%'} = $ci->{'Subject'};
		    $replace{'%umiUserCertificateIssuer%'} = $ci->{'Issuer'};
		    $replace{'%cn%'} = $ci->{CN};
		    push @{$debug->{error}}, $ci->{error} if defined $ci->{error};
		    $pwd->{clear} = $ci->{CN};
		    delete $svc_attrs->{uid};
		    delete $svc_attrs->{userPassword};
		  } else {
		    $replace{'%uid%'} = $svc_attrs->{uid};

		    ###########################################################################
		    # // [] ensures safe array dereference even if undef		      #
		    # join(' ', grep defined, ...) ensures you don’t join undef values	      #
		    ###########################################################################
		    $replace{'%cn%'} = $self->h_get_value_safe( $root, 'cn' ) // $replace{'%gecos%'};
		  }

		  foreach my $attr (keys %$svc_attrs_must) {
		    next if exists $svc_attrs->{$attr};
		    if ($attr eq 'uidNumber') {
		      $svc_attrs->{$attr} = $uidNumber_last->[0] + 1;
		    } elsif (exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$attr}) {
		      $svc_attrs->{$attr} = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$attr};
		      if ( $attr eq 'userCertificate;binary' ) { # binary data shouldn't be substituted
			$svc_attrs->{$attr} = $p->{'userCertificate;binary'};
		      } else {
			$svc_attrs->{$attr} =~ s/%([[:alpha:]]+(?:;[[:alpha:]]+)*)%/exists $replace{"%$1%"} ? $replace{"%$1%"} : $&/ge;
		      }
		    } else {
		      $svc_attrs->{$attr} = undef;
		      $self->h_log('ERROR: must attribute is absent: ' . $attr);
		    }
		  }
		  foreach my $attr (keys %$svc_attrs_may) {
		    next if exists $svc_attrs->{$attr} || !exists $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$attr};
		    $svc_attrs->{$attr} = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}}->{attr}->{$attr};
		    if ( $attr eq 'userCertificate;binary' ) { # binary data shouldn't be substituted
		      $svc_attrs->{$attr} = $p->{'userCertificate;binary'};
		    } else {
		      $svc_attrs->{$attr} =~ s/%([[:alpha:]]+(?:;[[:alpha:]]+)*)%/exists $replace{"%$1%"} ? $replace{"%$1%"} : $&/ge;
		    }
		  }

		  $svc_attrs->{authorizedService} = sprintf('%s@%s', $p->{authorizedService},
							    $p->{associatedDomain});
		  # $dry_run=1;
		  # $self->h_log($svc_dn);
		  $self->h_log($svc_attrs) if $dry_run == 1;

		  # Add the service entry to LDAP.
		  my $msg;
		  if ( $dry_run == 0 ) {
		    $msg = $ldap->add($svc_dn, $svc_attrs);
		  } else {
		    $msg = { status => 'ok',
			     message => sprintf('DRYRUN: h_service_add_if_not_exists() ldap->add dn: %s', $svc_dn) }
		  }
		  if ($msg) {
		    push @{$debug->{$msg->{status}}}, $msg->{message};
		    if ($msg->{status} eq 'ok') {
		      push @{$debug->{$msg->{status}}},
			sprintf('password: <span class="badge text-bg-secondary user-select-all">%s</span>', $pwd->{clear});
		    }
		  }
		  # $self->h_log($debug);

		  my %r = ( svc_dn => $svc_dn, msg => $msg, svc_details => \%svc_details );
		  # $self->h_log(\%r);
		  return \%r;

		});

=head2 h_vcard

receives Net::LDAP::Search->as_struct for root object/s

returns all the vCards as a single string

=cut

  $app->helper( h_vcard => sub {
		  my ($self, $entries) = @_;
		  # $self->h_log( $entries );

		  my $abook = vCard::AddressBook->new();

		  foreach my $dn (sort keys %$entries) {
		    my %h;
		    my $e = $entries->{$dn};

		    $h{full_name}    = $e->{gecos}->[0] if ref($e->{gecos}) eq 'ARRAY' && $e->{gecos}->[0] ne '';
		    $h{given_names}  = $e->{givenname}  if ref($e->{givenname}) eq 'ARRAY' && $e->{givenname}->[0] ne '';
		    $h{family_names} = $e->{sn}         if ref($e->{sn}) eq 'ARRAY' && $e->{sn}->[0] ne '';
		    $h{title}        = $e->{title}->[0] if ref($e->{title}) eq 'ARRAY' && $e->{title}->[0] ne '';
		    # otherwise warning '... uninitialized value ... vCard.pm line 112' occures
		    $h{photo} = '';

		    if (exists $e->{mail}) {
		      for (@{$e->{mail}}) {
			next if $_ eq '';
			push @{$h{email_addresses}}, { type => ['work'], address => $_ };
		      }
		    }

		    if (exists $e->{telephonenumber}) {
		      for (@{$e->{telephonenumber}}) {
			next if $_ eq '';
			push @{$h{phones}}, { type => ['work'], number => $_ };
		      }
		    }

		    my $vcard = $abook->add_vcard();
		    $vcard->load_hashref(\%h);
		    # $self->h_log( $vcard->as_string );
		    # $self->h_log( \%h );
		  }

		  return $abook->as_string;
		});

  ### END OF REGISTER --------------------------------------------------------------------------------------------
}

1;
