# -*- mode: cperl; eval: (follow-mode 1); -*-

package Umi::Helpers::Common;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util qw( b64_encode b64_decode encode decode url_escape xml_escape );

use Umi::Constants qw(RE TRANSLIT);

use Crypt::HSXKPasswd;
use Crypt::X509;
use Crypt::X509::CRL;
use File::Temp qw/ tempfile tempdir :POSIX /;
use File::Which qw(which);
use GD::Barcode::QRcode;
use GD;
use IPC::Run qw(run);
use List::Util qw(tail);
use Math::BigInt;
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

Performs HTTP Basic Authentication using credentials from the request's C<Authorization> header.

=over 4

=item B<Inputs>: None directly passed; inspects C<$c-E<gt>req-E<gt>headers-E<gt>authorization>.

=item B<Returns>: L<Umi::Ldap> object on successful authentication; otherwise sets status 401, issues a C<WWW-Authenticate> header, and returns C<undef>.

=back

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

=head2 header_form_subsearch_button

  my $label = $c->header_form_subsearch_button($text);

Formats subsearch button text.

=over 4

=item B<Inputs>: C<$text> (String) - Button text label.

=item B<Returns>: String - Uppercased text string.

=back

=cut

  $app->helper(		 header_form_subsearch_button => sub {
			   my ($self, $text) = @_;
			   return uc($text);
			 });

=head2 h_ldap_err

  my $err_str = $c->h_ldap_err($message, $search_arg);

Formats LDAP search error responses into a human-readable diagnostic string.

=over 4

=item B<Inputs>:

=over 4

=item * C<$message> (L<Net::LDAP::Message>) - LDAP response message object.

=item * C<$search_arg> (HashRef) - LDAP search options containing C<base>, C<filter>, and optional C<attrs>.

=back

=item B<Returns>: String - Formatted diagnostic error block.

=back

=cut

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

  my $padded = $c->h_pad_base64($str);

Ensures a Base64-encoded string is properly padded with trailing C<=> characters.

=over 4

=item B<Inputs>: C<$to_pad> (String) - Base64 string.

=item B<Returns>: String - Valid padded Base64 string.

=back

=cut

  $app->helper( h_pad_base64 => sub {
		  my ( $self, $to_pad ) = @_;
		  while (length($to_pad) % 4) {
		    $to_pad .= '=';
		  }
		  return $to_pad;
		});

=head2 h_is_ascii

  my $bool = $c->h_is_ascii($string);

Determines whether a given string contains non-ASCII characters.

=over 4

=item B<Inputs>: C<$arg> (String) - Input text.

=item B<Returns>: Integer - C<1> if non-ASCII characters are present; C<0> if completely ASCII or empty.

=back

=cut

  $app->helper( h_is_ascii => sub {
		  my ($self, $arg) = @_;
		  return $arg // '' ne '' && $arg !~ /^[[:ascii:]]+$/ ? 1 : 0;
		});

=head2 h_lrtrim

  my $trimmed = $c->h_lrtrim({ str => $dn_str, delim => ',', tosplit => 1 });

Trims leading and trailing whitespace from a string or from each element of a delimited string (such as a DN or RDN).

=over 4

=item B<Inputs>: C<$args> (HashRef)

=over 4

=item * C<str> (String, Required) - Target string.

=item * C<delim> (String, Optional) - Delimiter character (Default: C<,>).

=item * C<tosplit> (Boolean, Optional) - If true, splits string by C<delim> and trims each segment individually.

=back

=item B<Returns>: String - Trimmed output string.

=back

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

  my $array_ref = $c->h_csv_to_arr($csv_string);

Splits a comma-separated string into an array reference of trimmed strings.

=over 4

=item B<Inputs>: C<$csv> (String) - Comma-separated value string.

=item B<Returns>: ArrayRef[String] - Array reference of whitespace-trimmed values.

=back

=cut

$app->helper(h_csv_to_arr => sub {
  my ($self, $csv) = @_;
  return [ map { s/^\s+|\s+$//gr } split /,/, $csv ];
});

=head2 h_trim_leading_newlines

  my $clean = $c->h_trim_leading_newlines($text);

Strips leading newline sequences (C<\n>, C<\r\n>) from the input string.

=over 4

=item B<Inputs>: C<$text> (String) - Input text string.

=item B<Returns>: String (or C<undef> if input is undefined).

=back

=cut

  $app->helper(h_trim_leading_newlines => sub {
		 my ($self, $text) = @_;
		 return unless defined $text;
		 $text =~ s/^\R+//; # \R matches any newline sequence (\n, \r, \r\n, etc.)
		 return $text;
	       });

=head2 h_compact

  $c->h_compact(\@array_or_hash);

Removes empty string or C<undef> values from an array or hash in-place.

=over 4

=item B<Inputs>: C<$target> (ArrayRef|HashRef) - Target data structure.

=item B<Returns>: ArrayRef|HashRef - The modified reference.

=back

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

  my $bool = $c->h_is_meaningful_arrayref($aref);

Checks if the given reference is an array reference containing non-empty data.

=over 4

=item B<Inputs>: C<$aref> (Any) - Variable to test.

=item B<Returns>: Integer - C<1> if valid array reference with non-empty contents; C<0> otherwise.

=back

=cut

  $app->helper( h_is_meaningful_arrayref => sub {
		  my ($self, $aref) = @_;
		  return 0 unless ref($aref) eq 'ARRAY';
		  return 0 if @$aref == 0;
		  return 0 if @$aref == 1 && $aref->[0] eq '';
		  return 1;
		});

=head2 h_is_ip_pair

  my $bool = $c->h_is_ip_pair($str);

Validates whether the argument is a space-separated pair of IPv4 addresses.

=over 4

=item B<Inputs>: C<$arg> (String) - String to validate.

=item B<Returns>: Integer - C<1> if matching IP pair pattern; C<0> otherwise.

=back

=cut

  $app->helper( h_is_ip_pair => sub {
		  my ($self, $arg) = @_;
		  return (($arg // '') ne '' && $arg =~ /^$re->{ip}\s+$re->{ip}$/) ? 1 : 0;
		});

=head2 h_telephonenumber

  my $res = $c->h_telephonenumber($phone_csv_str);

Parses, validates, and normalizes international telephone numbers provided as a comma-separated list.

=over 4

=item B<Inputs>: C<$str> (String) - Comma-separated list of phone numbers.

=item B<Returns>: HashRef - C<{ num =E<gt> \@normalized_numbers, err =E<gt> $error_string }>

=back

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

  my $bool = $c->h_is_ip($ip_str);

Validates whether a string is a valid IPv4 address.

=over 4

=item B<Inputs>: C<$arg> (String) - IP address string.

=item B<Returns>: Integer - C<1> if valid IPv4; C<0> otherwise.

=back

=cut

  $app->helper( h_is_ip => sub {
		  my ($self, $arg) = @_;
		  return (($arg // '') ne '' && $arg =~ /^$re->{ip}$/) ? 1 : 0;
		});

=head2 h_ipam_dec2ip

  my $dotted_ip = $c->h_ipam_dec2ip($integer_ip);

Converts a 32-bit unsigned integer IP address into standard dotted-quad format.

=over 4

=item B<Inputs>: C<$arg> (Integer) - Integer representation of an IP address.

=item B<Returns>: String - Dotted-quad IPv4 address string (e.g., C<"192.168.1.1">).

=back

=cut

  $app->helper( h_ipam_dec2ip => sub {
		  my ($self, $arg) = @_;
		  return join '.', unpack 'C4', pack 'N', $arg;
		});

=head2 h_ipam_ip2dec

  my $integer_ip = $c->h_ipam_ip2dec($dotted_ip);

Converts a dotted-quad IPv4 address string into a 32-bit unsigned integer.

=over 4

=item B<Inputs>: C<$arg> (String, Optional) - Dotted-quad IPv4 string (Default: C<"0.0.0.0">).

=item B<Returns>: Integer - 32-bit unsigned integer value.

=back

=cut

  $app->helper( h_ipam_ip2dec => sub {
		  my ($self, $arg) = @_;
		  $arg //= '0.0.0.0';
		  return unpack N => pack 'C4' => split /\./ => $arg;
		});

=head2 h_ipam_msk_ip2dec

  my $prefix_len = $c->h_ipam_msk_ip2dec($subnet_mask_str);

Calculates the CIDR prefix length (number of set bits) from a dotted-quad subnet mask string.

=over 4

=item B<Inputs>: C<$arg> (String, Optional) - Dotted-quad subnet mask (Default: C<"0.0.0.0">).

=item B<Returns>: Integer - Count of set bits (e.g., C for C<"255.255.255.0">).

=back

=cut

  $app->helper( h_ipam_msk_ip2dec => sub {
		  my ($self, $arg) = @_;
		  $arg //= '0.0.0.0';
		  return (unpack 'B*' => pack 'N' => $self->h_ipam_ip2dec($arg)) =~ tr/1/1/;
		});

=head2 h_get_rdn

  my $rdn_attr = $c->h_get_rdn($dn);

Extracts the attribute name of the outermost left RDN from a Distinguished Name (DN).

=over 4

=item B<Inputs>: C<$dn> (String) - LDAP DN string (e.g., C<"uid=jdoe,ou=People,dc=example,dc=com">).

=item B<Returns>: String - Leftmost attribute name (e.g., C<"uid">).

=back

=cut

  $app->helper( h_get_rdn => sub {
		  my ($self, $dn) = @_;
		  return (split(/=/, $dn))[0];
		});

=head2 h_get_rdn_val

  my $rdn_val = $c->h_get_rdn_val($dn);

Extracts the attribute value of the outermost left RDN from a Distinguished Name (DN).

=over 4

=item B<Inputs>: C<$dn> (String) - LDAP DN string (e.g., C<"uid=jdoe,ou=People,dc=example,dc=com">).

=item B<Returns>: String - Leftmost RDN value (e.g., C<"jdoe">).

=back

=cut

  $app->helper( h_get_rdn_val => sub {
		  my ($self, $dn) = @_;
		  return (split(/=/, (split(/,/, $dn))[0]))[1];
		});

=head2 h_macnorm

  my $res = $c->h_macnorm({ mac => '01:23:45:67:89:AB', dlm => '-' });

Normalizes various MAC address formats (MAC-48, Cisco, bare hex) into bare hex or delimited form.

=over 4

=item B<Inputs>: C<$args> (HashRef)

=over 4

=item * C<mac> (String) - Input MAC address string.

=item * C<dlm> (String, Optional) - Delimiter character (C<:> or C<->) for formatted output.

=back

=item B<Returns>: HashRef - C<{ mac =E<gt> $normalized_mac, error =E<gt> $err_msg_or_undef }>

=back

=cut

  $app->helper( h_macnorm => sub {
		  my ( $self, $args ) = @_;
		  my $mac = $args->{mac};
		  my $dlm = $args->{dlm} // '';
		  my $re1 = $re->{mac}->{mac48};
		  my $re2 = $re->{mac}->{cisco};
		  my $re3 = $re->{mac}->{plain};

		  # $self->h_log($args);
		  if ( $mac =~ /^$re1$/ || $mac =~ /^$re2$/ ) {
		    my $normalized = lc($mac);
		    $normalized =~ s/[-:\.]//g;
		    if ($dlm ne '') {
		      $normalized = join($dlm, $normalized =~ /(..)/g);
		    }
		    # $self->h_log($normalized);
		    return { mac => $normalized, error => undef };
		  } elsif ( $mac =~ /^$re3$/ ) {
		    return { mac => lc($mac), error => undef };
		  } else {
		    return { mac => undef,
			     error => 'incorrect MAC address format, expected MAC-48 (IEEE canonical), EUI-48 (hyphen form), Cisco or Bare/Plain hexadecimal' };
		    return 0;
		  }
		});

=head2 h_gen_id

  my $id = $c->h_gen_id($length);

Generates a random alphanumeric identifier string.

=over 4

=item B<Inputs>: C<$len> (Integer, Optional) - Desired length (Default: C<8>).

=item B<Returns>: String - Random alphanumeric string.

=back

=cut

  $app->helper( h_gen_id => sub {
		  my ($self, $len) = @_;
		  $len = $len // 8;
		  my @chars = ('A'..'Z', 'a'..'z', 0..9);
		  return join '', map { $chars[rand @chars] } 1 .. $len;
		});

=head2 h_decode_text

  my $decoded = $c->h_decode_text($text, $alt);

Decodes byte text to UTF-8 Perl characters.

=over 4

=item B<Inputs>:

=over 4

=item * C<$text> (String) - Encoded byte string.

=item * C<$alt> (String, Optional) - Fallback value if C<$text> is undefined.

=back

=item B<Returns>: String - UTF-8 character string or C<$alt>.

=back

=cut

  # $app->helper(h_decode_text => sub {
  #		 my ($self, $text, $alt) = @_;
  #		  $self->h_log($text);
  #		 return $alt unless defined $text;
  #		 my $decoded = decode 'UTF-8', $text;
  #		  $self->h_log($decoded);
  #		 return $decoded ? $decoded : $alt;
  #	       });

  # $app->helper(h_decode_text => sub {
  #		 my ($self, $text, $alt) = @_;
  #		 return $alt unless defined $text;

  #		 # Check if text is already decoded (contains wide characters)
  #		 return $text if utf8::valid($text);

  #		 # Only decode if it's still bytes
  #		 my $decoded = eval { utf8::decode 'UTF-8', $text };
  #		 $self->h_log($decoded);
  #		 return $decoded // $alt;
  #	       });

  $app->helper(h_decode_text => sub {
		 my ($self, $text, $alt) = @_;
		 return $alt unless defined $text;

		 # If already UTF-8 string, return as-is
		 return $text if utf8::is_utf8($text);

		 # Decode and ensure UTF-8 flag is set
		 my $decoded = Encode::decode('UTF-8', $text);
		 Encode::_utf8_on($decoded);  # Ensure UTF-8 flag is set

		 return $decoded;
	       });

=head2 h_translit

  my $ascii_clean = $c->h_translit($text);

Transliterates non-ASCII European and Cyrillic characters into Latin equivalents and normalizes string to ASCII allowed set.

=over 4

=item B<Inputs>: C<$in> (String) - UTF-8 text string.

=item B<Returns>: String - Sanitized ASCII string matching C<[a-zA-Z0-9.-_ ]>.

=back

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
		  $in =~ s/[^[:alnum:]._ -]//g; # Keep only allowed characters
		  # $self->h_log($in);

		  return $in;
		});

=head2 h_maybe_percent_decode_utf8

  my $decoded = $c->h_maybe_percent_decode_utf8($url_encoded_str);

Detects and decodes percent-encoded UTF-8 URL sequences if present.

=over 4

=item B<Inputs>: C<$s> (String) - Input string.

=item B<Returns>: String - URI-decoded UTF-8 string, or original string if no percent encoding detected.

=back

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

=head2 h_as_struct_decode

  my $val = $c->h_as_struct_decode($obj_hash, $attr, $na);

Safely extracts and UTF-8 decodes the first scalar value of an LDAP attribute from an C<as_struct> result hash.

=over 4

=item B<Inputs>:

=over 4

=item * C<$obj_hash> (HashRef) - Single entry hash reference from LDAP C<as_struct>.

=item * C<$attr> (String) - Target LDAP attribute name.

=item * C<$na> (String, Optional) - Fallback string if attribute is missing (Default: HTML C<"unavailable"> tag).

=back

=item B<Returns>: String - Decoded value string or fallback HTML.

=back

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

  my $qr_res = $c->h_qrcode({ toqr => 'text', ecc => 'M', mod => 2, html => 1 });

Generates a Base64-encoded PNG QR code image.

=over 4

=item B<Inputs>: C<$args> (HashRef)

=over 4

=item * C<toqr> (String, Required) - Text content to encode into QR code.

=item * C<ecc> (String, Optional) - Error correction level: C<L>, C<M>, C<Q>, C<H> (Default: C<M>).

=item * C<mod> (Integer, Optional) - Module size in pixels (Default: C<1>).

=item * C<html> (Integer, Optional) - If C<1>, includes formatted C<E<lt>imgE<gt>> tag markup (Default: C<1>).

=back

=item B<Returns>: HashRef - C<{ qr =E<gt> $base64_png, html =E<gt> $html_snippet, error =E<gt> $err_msg }>.

=back

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

  my $dim = $c->h_img_info($image_blob);

Inspects raw image binary data and returns image dimensions.

=over 4

=item B<Inputs>: C<$image> (Scalar/Blob) - Binary image content.

=item B<Returns>: HashRef - C<{ width =E<gt> $w, height =E<gt> $h }>

=back

=cut

  $app->helper( h_img_info => sub {
		  my ($self, $image) = @_;
		  my $i = GD::Image->new($image);
		  return { width  => $i->width,
			   height => $i->height };
		});

=head2 h_img_resize

  my $resized_blob = $c->h_img_resize($img_blob, $byte_size);

Resizes an image maintaining aspect ratio according to app config limits (C<jpegPhoto> max size and side).

=over 4

=item B<Inputs>:

=over 4

=item * C<$img> (Scalar/Blob) - Original binary image data.

=item * C<$size> (Integer) - Original file size in bytes.

=back

=item B<Returns>: Scalar/Blob - Resized JPEG binary data or original image if no resizing required.

=back

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

=head2 h_keygen_ssh

  my $res = $c->h_keygen_ssh({ key_type => 'Ed25519', bits => 2048, name => { email => 'user@domain' } });

Generates an SSH keypair using standard C<ssh-keygen(1)>.

=over 4

=item B<Inputs>: C<$args> (HashRef)

=over 4

=item * C<key_type> (String, Optional) - C<RSA>, C<Ed25519>, C<ECDSA256>, etc. (Default: C<Ed25519>).

=item * C<bits> (Integer, Optional) - Bit size for RSA key types (Default: C<2048>).

=item * C<name> (HashRef, Optional) - Comment options including C<email>.

=back

=item B<Returns>: HashRef - C<{ private =E<gt> $pvt_key, public =E<gt> $pub_key, date =E<gt> $timestamp, error =E<gt> \@errors }>

=back

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

=head2 h_keygen_gpg

  my $res = $c->h_keygen_gpg({ key_type => 'eddsa', bits => 4096, send_key => 0 });

Generates or imports a GPG keypair using system C<gpg(1)>.

=over 4

=item B<Inputs>: C<$args> (HashRef)

=over 4

=item * C<key_type> (String, Optional) - C<eddsa> or C<RSA> (Default: C<eddsa>).

=item * C<bits> (Integer, Optional) - Bit length for RSA (Default: C<4096>).

=item * C<import> (HashRef|String, Optional) - Key text or file structure to import existing key instead of generating.

=item * C<send_key> (Boolean, Optional) - Send generated key to LDAP keyserver (Default: C<0>).

=item * C<name> (HashRef, Optional) - C<{ real =E<gt> $name, email =E<gt> $email }>.

=item * C<to_enc> (HashRef, Optional) - Key/value pairs of strings to encrypt with the new key.

=back

=item B<Returns>: HashRef - C<{ fingerprint =E<gt> $hex, public =E<gt> $armored, private =E<gt> $armored, send_key =E<gt> \%ldap_pgp_attr_hash, enc =E<gt> \%enc_results, debug =E<gt> \%debug_msgs }>

=back

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

		    # $self->h_log($arg->{key}->{lst});
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
		       pgpKeyExpireTime => defined $arg->{key}->{lst}->{colons}->{pub}->[5]
		       && length($arg->{key}->{lst}->{colons}->{pub}->[5]) > 0
		       ? strftime('%Y%m%d%H%M%SZ', localtime($arg->{key}->{lst}->{colons}->{pub}->[5]))
		       : '99991231235959Z',
		      };


		    $res->{send_key} = $arg->{key}->{snd};
		  }

		  #File::Temp::cleanup();
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

=head2 h_pwdgen

  my $pwd_res = $c->h_pwdgen(\%params);

Generates or validates passwords using C<Crypt::HSXKPasswd> and produces C<{SSHA}> hashes for OpenLDAP C<userPassword> fields.

=over 4

=item B<Inputs>: C<$par> (HashRef)

=over 4

=item * C<pwd_alg> (String, Optional) - Preset class name (e.g. C<alg-web32>).

=item * C<pwd_num> (Integer, Optional) - Number of passwords.

=item * C<pwd_vrf> / C<pwd_userdefined> (String, Optional) - Plaintext password for direct hashing instead of random generation.

=item * C<xk_*> (Various, Optional) - C<Crypt::HSXKPasswd> overrides (e.g. C<xk_num_words>).

=back

=item B<Returns>: HashRef - C<{ clear =E<gt> $plain, ssha =E<gt> '{SSHA}...', error =E<gt> $err, stats =E<gt> \%stats, status =E<gt> $status }>

=back

=cut

  # PWDGEN
  # expected at least xk_num_words
  $app->helper( h_pwdgen => sub {
		  my ( $self, $par ) = @_;
		  # $self->h_log($par);
		  my ($xk, $error);
		  my $cf = $app->{cfg}->{tool}->{pwdgen} // undef;
		  my $p;
		  # we need at least this for "default generating"
		  $p->{xk_num_words} = $cf->{xk}->{num_words}->{val} if ! defined $p;
		  $par->{xk_num_words} //= $cf->{xk}->{num_words}->{val};
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

# Claude fix bellow#		      if ( exists $par->{xk_padding_type} && $par->{xk_padding_type} eq 'pad-none' ) {
# Claude fix bellow#			$par->{xk_padding_type} = 'NONE';
# Claude fix bellow#			delete $par->{xk_pad_to_length};
# Claude fix bellow#			delete $par->{xk_padding_alphabet};
# Claude fix bellow#			delete $par->{xk_padding_character};
# Claude fix bellow#			delete $par->{xk_padding_character_random};
# Claude fix bellow#			delete $par->{xk_padding_character_after};
# Claude fix bellow#			delete $par->{xk_padding_character_before};
# Claude fix bellow#			delete $par->{xk_padding_character_separator};
# Claude fix bellow#		      } elsif ( exists $par->{xk_padding_type} && $par->{xk_padding_type} eq 'pad-fixed' ) {
# Claude fix bellow#			$par->{xk_padding_type} = 'FIXED';
# Claude fix bellow#		      } elsif ( exists $par->{xk_padding_type} && $par->{xk_padding_type} eq 'pad-adaptive' ) {
# Claude fix bellow#			$par->{xk_padding_type} = 'ADAPTIVE';
# Claude fix bellow#		      }
# Claude fix bellow#
# Claude fix bellow#		      if ( exists $par->{xk_padding_character} && $par->{xk_padding_character} eq 'pch-separator' ) {
# Claude fix bellow#			$par->{xk_padding_character} = 'SEPARATOR';
# Claude fix bellow#			delete $par->{xk_padding_alphabet};
# Claude fix bellow#		      } elsif ( exists $par->{xk_padding_character} && $par->{xk_padding_character} eq 'pch-random' ) {
# Claude fix bellow#			$par->{xk_padding_character} = 'RANDOM';
# Claude fix bellow#			$par->{xk_padding_alphabet} = [ split //, $self->h_lrtrim({str => $par->{'xk_padding_alphabet'}}) ];
# Claude fix bellow#		      } elsif ( exists $par->{xk_padding_character} && $par->{xk_padding_character} eq 'pch-character' ) {
# Claude fix bellow#			$par->{xk_padding_character} = $par->{xk_padding_character_char};
# Claude fix bellow#			delete $par->{xk_padding_character_char};
# Claude fix bellow#			delete $par->{xk_padding_alphabet};
# Claude fix bellow#		      }

		      # --- padding type -------------------------------------------------
		      if ( ($par->{xk_padding_type} // '') eq 'pad-none' ) {
			$par->{xk_padding_type} = 'NONE';
			delete @{$par}{qw(xk_pad_to_length xk_padding_alphabet xk_padding_character
					  xk_padding_character_char
					  xk_padding_characters_before xk_padding_characters_after)};
		      } elsif ( ($par->{xk_padding_type} // '') eq 'pad-fixed' ) {
			$par->{xk_padding_type} = 'FIXED';
			delete $par->{xk_pad_to_length};
			# FIXED needs both counts; empty means 0
			for my $k (qw(xk_padding_characters_before xk_padding_characters_after)) {
			  $par->{$k} = 0 if ($par->{$k} // '') eq '';
			}
		      } elsif ( ($par->{xk_padding_type} // '') eq 'pad-adaptive' ) {
			$par->{xk_padding_type} = 'ADAPTIVE';
			delete @{$par}{qw(xk_padding_characters_before xk_padding_characters_after)};
		      }

		      # --- padding character --------------------------------------------
		      if ( ($par->{xk_padding_character} // '') eq 'pch-separator' ) {
			$par->{xk_padding_character} = 'SEPARATOR';
			delete @{$par}{qw(xk_padding_alphabet xk_padding_character_char)};
		      } elsif ( ($par->{xk_padding_character} // '') eq 'pch-random' ) {
			$par->{xk_padding_character} = 'RANDOM';
			$par->{xk_padding_alphabet}  = [ split //, $self->h_lrtrim({str => $par->{xk_padding_alphabet} // ''}) ];
			delete $par->{xk_padding_character_char};
		      } elsif ( ($par->{xk_padding_character} // '') eq 'pch-character' ) {
			$par->{xk_padding_character} = $par->{xk_padding_character_char};
			delete @{$par}{qw(xk_padding_character_char xk_padding_alphabet)};
		      }

		      # --- empty alphabets: let the module fall back to symbol_alphabet --
		      for my $k (qw(xk_separator_alphabet xk_padding_alphabet)) {
			delete $par->{$k} if ref $par->{$k} eq 'ARRAY' && !@{ $par->{$k} };
		      }

		      # $self->h_log($par);

		      if (keys %{$par}) {
			my $j;
# Claude fix bellow #			foreach my $i (keys %{$par}) {
# Claude fix bellow #			  next if $i !~ /^xk_/;
# Claude fix bellow #			  $j = substr $i, 3;
# Claude fix bellow #
# Claude fix bellow #			  if ( ! defined $par->{$i} ||
# Claude fix bellow #			       $par->{$i} eq '' ||
# Claude fix bellow #			       (exists $par->{$i} && exists $xk_cf->{$j} && $xk_cf->{$j} eq $par->{$i}) ) {
# Claude fix bellow #			    next;
# Claude fix bellow #			  } else {
# Claude fix bellow #			    $xk_cf->{$j} = $par->{$i};
# Claude fix bellow #			  }
# Claude fix bellow #
# Claude fix bellow #			}

			my $xk_cf = Crypt::HSXKPasswd->preset_config( $p->{palg} );
			# all possible presets keys list
			my %valid = map { $_ => 1 } qw(
							allow_accents
							case_transform
							num_words
							pad_to_length
							padding_alphabet
							padding_character
							padding_characters_after
							padding_characters_before
							padding_digits_after
							padding_digits_before
							padding_type
							separator_alphabet
							separator_character
							symbol_alphabet
							word_length_max
							word_length_min
						     );

			foreach my $i (keys %{$par}) {
			  next if $i !~ /^xk_/;
			  my $j = substr $i, 3;
			  next unless $valid{$j}; # ignore UI-only fields
			  next if ! defined $par->{$i} || $par->{$i} eq '';
			  $xk_cf->{$j} = $par->{$i};
			}

		      }

		      # $self->h_log($xk_cf);

		      try {
			$xk = Crypt::HSXKPasswd->new( config => $xk_cf );
		      }
		      catch { $error = $_; };

		      if ( ! defined $error ) {
			$p->{pwd}->{clear}    = $xk->password( $p->{pnum} );
			$error = 'Password generation failure.' if ! defined $p->{pwd}->{clear};
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
		  # Digest::SHA->add expects octets (bytes), not Perl’s internal character strings.
		  $sha->add(encode 'UTF-8', $p->{pwd}->{clear});
		  $sha->add(encode 'UTF-8', $cf->{sha}->{salt});
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

  my $diff = $c->h_hash_diff($orig_hashref, $mod_hashref);

Compares two hash references to find added, removed, changed, and unchanged key-value pairs.

=over 4

=item B<Inputs>:

=over 4

=item * C<$original_ref> (HashRef) - Original base hash.

=item * C<$modified_ref> (HashRef) - Modified target hash.

=back

=item B<Returns>: HashRef - C<{ removed =E<gt> \%removed, added =E<gt> \%added, changed =E<gt> \%changed, unchanged =E<gt> \%unchanged }>

=back

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

  my $diff = $c->h_array_diff($orig_aref, $mod_aref);

Compares two array references to find added, removed, and unchanged elements.

=over 4

=item B<Inputs>:

=over 4

=item * C<$original_ref> (ArrayRef) - Original base array.

=item * C<$modified_ref> (ArrayRef) - Modified target array.

=back

=item B<Returns>: HashRef - C<{ removed =E<gt> \@removed, added =E<gt> \@added, unchanged =E<gt> \@unchanged }>

=back

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

  my $content = $c->h_file2var($file_path, $msg, $return_as_arr);

Reads a file's entire content into a scalar string or an array of chomp'd lines.

=over 4

=item B<Inputs>:

=over 4

=item * C<$file> (String) - Path to file.

=item * C<$final_message> (Any, Unused) - Reserved parameter.

=item * C<$return_as_arr> (Boolean, Optional) - If C<1>, returns array reference of lines instead of scalar.

=back

=item B<Returns>: String|ArrayRef[String] - File content scalar or array reference of lines.

=back

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

  my $info = $c->h_cert_info({ cert => $cert_binary, attr => 'userCertificate;binary', ts => "%Y-%m-%d" });

Parses X.509 certificates or CRLs and returns a hash of certificate fields.

=over 4

=item B<Inputs>: C<$args> (HashRef)

=over 4

=item * C<cert> / C<crl> (Binary, Required) - Certificate or CRL raw data.

=item * C<attr> (String, Optional) - Attribute type: C<userCertificate;binary>, C<cACertificate;binary>, or C<certificateRevocationList;binary> (Default: C<userCertificate;binary>).

=item * C<ts> (String, Optional) - C<strftime> date format string (Default: C<"%a %b %e %H:%M:%S %Y">).

=back

=item B<Returns>: HashRef - Parsed subject, issuer, serial numbers, dates, or error structure C<{ error =E<gt> $msg }>.

=back

=cut

  $app->helper( h_cert_info => sub {
		  my ( $self, $args ) = @_;

		  # Validate input arguments
		  return { error => 'No certificate data provided' } unless $args->{cert} || $args->{crl};

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
			    'AKI serial' => $self->h_cert_serial($cert->key_identifier),
			    'AKI keyid'  => $self->h_cert_serial($cert->authority_serial),
			    'S/N'        => $self->h_cert_serial($cert->serial),
			    'Not Before' => strftime($ts, localtime($cert->not_before)),
			    'Not After'  => strftime($ts, localtime($cert->not_after)),
			    cert         => $args->{cert},
			    error        => undef,
			   };

		  } elsif ( $attr eq 'certificateRevocationList;binary' ) {
		    $cert = Crypt::X509::CRL->new( crl => $args->{crl} );
		    # $self->h_log($cert->revocation_list);
		    return { error => sprintf('Error parsing CRL: %s', $cert->error) } if $cert->error;

		    my %revoked;
		    foreach my $key (sort keys %{ $cert->revocation_list }) {
		      $revoked{$self->h_cert_serial($key)} = {
			key_dec         => $key,
			revocationDate => strftime($ts, localtime($cert->revocation_list->{$key}->{revocationDate})),
		      };
		    }

		    return {
			    'AKI serial'        => $self->h_cert_serial($cert->key_identifier),
			    'AKI keyid'         => $self->h_cert_serial($cert->authority_serial),
			    Issuer              => join(',', @{ $cert->Issuer }),
			    AuthIssuer          => join(',', @{ $cert->authorityCertIssuer }),
			    RevokedCertificates => \%revoked,
			    'Update This'       => strftime($ts, localtime($cert->this_update)),
			    'Update Next'       => strftime($ts, localtime($cert->next_update)),
			    cert                => $args->{cert},
			    error               => undef,
			   };
		  }

		  return { error => 'Unknown certificate type' };
		}
	      );

=head2 h_cert_serial

  my $colon_hex = $c->h_cert_serial($serial_val);

Normalizes certificate serial numbers into OpenSSL-style colon-separated uppercase hexadecimal octets.

=over 4

=item B<Inputs>: C<$cert> (String/Integer) - Decimal integer string or raw binary serial number.

=item B<Returns>: String|HashRef - Colon-separated hex string (e.g. C<"01:23:45:67:89:AB">) or error hash reference if missing.

=back

=cut

  $app->helper(h_cert_serial => sub {
		 my ($self, $cert) = @_;
		 return { error => 'Error: certificate value not provided' }
		   unless defined $cert;
		 my $bin;
		 if ($cert =~ /^[0-9]+$/) {
		   # Looks like decimal digits: interpret as big integer
		   my $big = Math::BigInt->new($cert);
		   $bin = $big->to_bytes;
		 } else {
		   $bin = $cert; # Otherwise assume it's already binary
		 }
		 return uc join(":", unpack("(H2)*", $bin));
	       });

=head2 h_btns_cp_save_from_element

  my $html = $c->h_btns_cp_save_from_element($target_id, $file_name, $button_class, $wrapper_class, $mimetype, $qrcode);

Renders HTML action buttons to copy an element's text to the clipboard, download it as a file, and optionally show a QR code.

=over 4

=item B<Inputs>:

=over 4

=item * C<$target_id> (String, Mandatory) - DOM element ID containing content.

=item * C<$file_name> (String, Optional) - Default download filename.

=item * C<$button_class> (String, Optional) - CSS class for buttons.

=item * C<$wrapper_class> (String, Optional) - CSS class for button container.

=item * C<$mimetype> (String, Optional) - MIME type for download file.

=item * C<$qrcode> (String, Optional) - Text to encode in a QR code button.

=back

=item B<Returns>: String - Rendered HTML button group string.

=back

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

###=head2 h_btn_cp_from_url
###
###  my $html = $c->h_btn_cp_from_url(id => 'copy-btn', js_func => sub { return "fetchText()" });
###
###Renders a button and inline JavaScript to copy text returned asynchronously by a JavaScript expression to the clipboard.
###
###=over 4
###
###=item B<Inputs>: Named parameters C<%args>
###
###=over 4
###
###=item * C<id> (String) - HTML element ID.
###
###=item * C<title> (String) - Tooltip title text.
###
###=item * C<text> (String) - Visible button HTML label.
###
###=item * C<js_func> (CodeRef) - Subroutine returning the JS expression string to evaluate.
###
###=back
###
###=item B<Returns>: String - HTML and inline C<E<lt>scriptE<gt>> tags.
###
###=back
###
###=cut
###
###  $app->helper( h_btn_cp_from_url => sub {
###		  my ($self, %args) = @_;
###
###		  my $id     = $args{id}     || 'btn-copy';
###		  my $class  = $args{class}  || 'btn btn-sm btn-secondary';
###		  my $title  = $args{title}  || 'Copy to clipboard';
###		  my $text   = $args{text}   || '<i class="fa-solid fa-copy"></i>';
###		  my $js     = $args{js_func} ? $args{js_func}->() : '""';
###
###		  return qq{
###<button id="$id" class="$class" title="$title">
###  $text
###</button>
###<script>
###  (function () {
###    const btn = document.getElementById('$id');
###    if (!btn) return;
###    btn.addEventListener('click', function () {
###      (async () => {
###	try {
###	  const text = await ($js);
###	  const temp = document.createElement("textarea");
###	  temp.value = text;
###	  document.body.appendChild(temp);
###	  temp.select();
###	  document.execCommand("copy");
###	  document.body.removeChild(temp);
###	  alert("Copied to clipboard");
###	} catch (e) {
###	  alert("Copy failed: " + e);
###	}
###      })();
###    });
###  })();
###</script>
###};
###
###		});
###
###=head2 h_btn_save_from_url
###
###  my $html = $c->h_btn_save_from_url(id => 'save-btn', filename => 'out.txt', js_func => sub { return "fetchData()" });
###
###Renders a button and inline JavaScript that fetches text data via JavaScript and triggers a browser file download.
###
###=over 4
###
###=item B<Inputs>: Named parameters C<%args>
###
###=over 4
###
###=item * C<id> (String) - HTML element ID.
###
###=item * C<title> (String) - Tooltip title text.
###
###=item * C<filename> (String) - Target download filename.
###
###=item * C<js_func> (CodeRef) - Subroutine returning the JS expression evaluating to text content.
###
###=back
###
###=item B<Returns>: String - HTML and inline C<E<lt>scriptE<gt>> tags.
###
###=back
###
###=cut
###
###  $app->helper( h_btn_save_from_url => sub {
###		  my ($self, %args) = @_;
###		  my $t = localtime;
###
###		  my $id       = $args{id}      || 'btn-download';
###		  my $class    = $args{class}   || 'btn btn-sm btn-secondary';
###		  my $title    = $args{title}   || 'Download as text file';
###		  my $text     = $args{text}    || '<i class="fa-solid fa-file-arrow-down"></i>';
###		  my $filename = $args{filename}|| 'searchresult-' . $t->datetime . '.ldif';
###		  my $js       = $args{js_func} ? $args{js_func}->() : '""';
###
###		  return qq{
###<button id="$id" class="$class" title="$title">
###  $text
###</button>
###<script>
###document.addEventListener('DOMContentLoaded', function () {
###  const btn = document.getElementById('$id');
###  if (!btn) return;
###  btn.addEventListener('click', function () {
###    (async () => {
###      try {
###	const text = await ($js);
###	const blob = new Blob([text], { type: 'text/plain' });
###	const link = document.createElement('a');
###	link.href = URL.createObjectURL(blob);
###	link.download = '$filename';
###	document.body.appendChild(link);
###	link.click();
###	document.body.removeChild(link);
###      } catch (e) {
###	alert("Download failed: " + e);
###      }
###    })();
###  });
###});
###</script>
###};
###		});


=head2 h_btn_cp_from_url

    my $html = $c->h_btn_cp_from_url(
      url   => $url,
      title => 'Copy LDIF',
      text  => '<i class="fa-solid fa-copy"></i>'
    );

Generates the HTML markup for a button that fetches text content from a specified URL and copies it to the client clipboard.

=over 4

=item * C<$url> - Target endpoint URL providing the text payload.

=item * C<%options> - Optional configuration hash (e.g., C<label>, C<class>, C<id>, C<title>).

=back

B<JavaScript Dependency:>

Depends from the delegated click event listener for async URL actions in umi-common.js

Returns raw HTML string.

=cut

$app->helper( h_btn_cp_from_url => sub {
    my ($self, %args) = @_;

    my $url   = $args{url}   || '';
    my $class = $args{class} || 'btn btn-sm btn-secondary js-btn-copy-url';
    my $title = $args{title} || 'Copy to clipboard';
    my $text  = $args{text}  || '<i class="fa-solid fa-copy"></i>';

    return qq{<button type="button" class="$class" title="$title" data-fetch-url="$url">$text</button>};
});


=head2 h_btn_save_from_url

    my $html = $c->h_btn_save_from_url(
      url      => $url,
      filename => 'searchresult.ldif',
      title    => 'Save LDIF'
    );

Generates the HTML markup for a button that fetches data from a specified URL and triggers a client-side file download in the browser.

=over 4

=item * C<$url> - Source URL to fetch the file content from.

=item * C<$filename> - Default base filename presented in the browser save prompt (e.g., C<searchresult.ldif>).

=item * C<%options> - Optional configuration hash (e.g., C<type>, C<class>, C<label>, C<id>).

=back

B<JavaScript Dependency:>

Depends from the delegated click event listener for async URL actions in umi-common.js

Returns raw HTML string.

=cut

$app->helper( h_btn_save_from_url => sub {
    my ($self, %args) = @_;

    my $url      = $args{url}      || '';
    my $filename = $args{filename} || 'searchresults-'  . strftime("%Y%m%d%H%M%S", localtime) . '.ldif';
    my $class    = $args{class}    || 'btn btn-sm btn-secondary js-btn-save-url';
    my $title    = $args{title}    || 'Download as text file';
    my $text     = $args{text}     || '<i class="fa-solid fa-file-arrow-down"></i>';

    return qq{<button type="button" class="$class" title="$title" data-fetch-url="$url" data-filename="$filename">$text</button>};
});

=head2 h_req_mark

  my $icon_html = $c->h_req_mark(icon => 'fa-bookmark', color => 'text-danger');

Renders a small indicator icon mark for required form fields.

=over 4

=item B<Inputs>: Named parameters C<%args> (C<icon>, C<color>, C<title>, C<class>).

=item B<Returns>: String - HTML superscript icon tag.

=back

=cut

  $app->helper( h_req_mark => sub {
		  my ($self, %args) = @_;
		  my $icon = $args{icon} // 'fa-bookmark';
		  my $color = $args{color} // 'text-danger-emphasis';
		  my $title = $args{title} // '!! REQUIRED !!';
		  my $class = $args{class} // '';
		  return qq{<sup><i class="fa-solid $icon fa-2xs $color $class" title="$title"></i></sup>};
		});

=head2 h_rest_mark

  my $has_rest = $c->h_rest_mark(text => 'REST', color => 'text-danger');

Renders a small indicator icon mark for required form fields.

=over 4

=item B<Inputs>: Named parameters C<%args> (C<icon>, C<color>, C<title>, C<class>).

=item B<Returns>: String - HTML superscript icon tag.

=back

=cut

  $app->helper( h_rest_mark => sub {
		  my ($self, %args) = @_;
		  my $text  = $args{text}  // '&#9900'; # '&#9675'; # 'R'; #'&#127276;'; # '&#127297;'; #'&#9415;';
		  my $icon  = $args{icon}  // 'fa-registered';
		  my $color = $args{color} // 'text-success-emphasis';
		  my $title = $args{title} // 'some REST endpoint/s available';
		  my $class = $args{class} // '';
		  my $tag   = $args{tag}   // 'sub';
		  # $self->h_log(keys %args);
		  if ( keys %args ) {
		    return qq{<$tag><i class="fa-solid $icon umi-text-tiny $color $class" title="$title"></i></$tag>};
		  } else {
		    return qq{<$tag class="umi-text-tiny $color $class text-uppercase" title="$title">$text</$tag>};
		  }
		});

=head2 h_nested_params

  my $nested_hash = $c->h_nested_params;

Parses request parameters with bracket notation (e.g. C<hosts[0]>) into structured nested arrays.

=over 4

=item B<Inputs>: None directly passed; inspects C<$c-E<gt>req-E<gt>params>.

=item B<Returns>: HashRef - Parameter hash reference with expanded nested arrays.

=back

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

  my $bool = $c->h_is_empty_nested_arr($arr);

Verifies if an array reference matches the specific nested structure C<[ [] ]>.

=over 4

=item B<Inputs>: C<$arr> (ArrayRef) - Array reference to test.

=item B<Returns>: Boolean - True if C<$arr> is C<[ [] ]>; false otherwise.

=back

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

  my $gen_time = $c->h_ts_to_generalizedTime($date_str, $format);

Converts a date string into LDAP GeneralizedTime format (e.g. C<YYYYMMDDHHMMSSZ>).

=over 4

=item B<Inputs>:

=over 4

=item * C<$date> (String) - Date string.

=item * C<$format> (String, Optional) - C<strptime> input format string (Default: C<'%Y-%m-%d'>).

=back

=item B<Returns>: String - LDAP GeneralizedTime string.

=back

=cut

  $app->helper( h_ts_to_generalizedTime => sub {
		  my ($self, $date, $format) = @_;
		  $format = '%Y-%m-%d' if ! defined $format;
		  my $t = Time::Piece->strptime($date, $format);
		  my $res = time_to_generalizedTime($t->epoch) if defined $t;
		  return $res;
		});

=head2 h_years_since

  my $years = $c->h_years_since($generalized_time_str);

Calculates the number of full elapsed years between an LDAP GeneralizedTime string and the current time.

=over 4

=item B<Inputs>: C<$date> (String) - LDAP GeneralizedTime string.

=item B<Returns>: Integer - Number of full elapsed years.

=back

=cut

  $app->helper( h_years_since => sub {
		  my ($self, $date) = @_;
		  my $then = localtime( generalizedTime_to_time($date) );
		  my $now  = localtime();
		  my $years = $now->year - $then->year;
		  # $self->h_log($now->year . ' - ' . $then->year . ' = ' . $years);
		  # Adjust if current date is before anniversary in the current year
		  $years--
		    if $now->mon < $then->mon || ($now->mon == $then->mon && $now->mday < $then->mday);

		  return $years;
		});

=head2 h_get_value_safe

  my $val = $c->h_get_value_safe($entry, $attr);

Safely retrieves the first scalar value of an attribute from a L<Net::LDAP::Entry> object.

=over 4

=item B<Inputs>:

=over 4

=item * C<$entry> (L<Net::LDAP::Entry>) - LDAP entry object.

=item * C<$attr> (String) - Target attribute name.

=back

=item B<Returns>: String|undef - Attribute value string or C<undef> if absent or empty.

=back

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

  my $res = $c->h_branch_add_if_not_exists($p, $ldap, $root, $debug, $dry_run);

Checks if an LDAP service branch DN exists, creating it if it does not.

=over 4

=item B<Inputs>:

=over 4

=item * C<$p> (HashRef) - Parameters containing C<authorizedService>, C<associatedDomain>, and optional C<login>.

=item * C<$ldap> (L<Umi::Ldap>|L<Net::LDAP>) - Active LDAP connection object.

=item * C<$root> (L<Net::LDAP::Entry>) - Root entry object.

=item * C<$debug> (HashRef) - Hash reference collecting status/debug messages.

=item * C<$dry_run> (Boolean, Optional) - If C<1>, skips writing to LDAP (Default: C<0>).

=back

=item B<Returns>: HashRef - C<{ br_dn =E<gt> $branch_dn, msg =E<gt> $ldap_result_or_hash }>

=back

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

  my $res = $c->h_service_add_if_not_exists($p, $ldap, $root, $br, $debug, $dry_run);

Constructs and provisions a new LDAP authorized service entry with schema validation, placeholder substitutions, and password generation.

=over 4

=item B<Inputs>:

=over 4

=item * C<$p> (HashRef) - Request form parameters.

=item * C<$ldap> (L<Umi::Ldap>|L<Net::LDAP>) - LDAP connection object.

=item * C<$root> (L<Net::LDAP::Entry>) - User root entry object.

=item * C<$br> (HashRef) - Branch info containing C<br_dn>.

=item * C<$debug> (HashRef) - Hash reference to accumulate status/error log messages.

=item * C<$dry_run> (Boolean, Optional) - If C<1>, performs simulation without adding to LDAP (Default: C<0>).

=back

=item B<Returns>: HashRef - C<{ svc_dn =E<gt> $service_dn, msg =E<gt> $ldap_msg, svc_details =E<gt> \%details }>

=back

=cut

  $app->helper( h_service_add_if_not_exists => sub {
		  my ($self, $p, $ldap, $root, $br, $debug, $dry_run) = @_;
		  # $self->h_log($p);

		  ## TODO: IN SLAPD CONFIG TO INDEX ALL WHAT IS SEARCHED

		  $dry_run = 0 if ! defined $dry_run;
		  $self->h_log($p) if $dry_run == 1;

		  my $sc = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$p->{authorizedService}};


		  # different services expect different format of logins
		  if ( $p->{authorizedService} eq 'dot1x-eap-md5' ) {
		    my $mac = $self->h_macnorm({mac => $p->{login}});
		    $p->{login} = $mac->{mac};
		    push @{$debug->{error}}, $mac->{error} if defined $mac->{error};
		  } elsif ( $sc->{delim_mandatory} && exists $p->{login} && $p->{login} !~ /.+@.+/ ) {
		    $p->{login} = sprintf("%s@%s", $p->{login}, $p->{associatedDomain});
		  } elsif ( $sc->{delim_mandatory} && ! exists $p->{login} ) {
		    $p->{login} = sprintf("%s@%s", $self->h_get_root_uid_val( $p->{dn_to_new_svc} ), $p->{associatedDomain});
		  }

		  # Construct the service DN using parameters from $p and configuration.
		  my ($ci, $rdn_val);
		  if ( exists $p->{'userCertificate;binary'} ) {
		    $ci = $self->h_cert_info({ cert => $p->{'userCertificate;binary'}, ts => "%Y%m%d%H%M%S" });
		    $rdn_val = $ci->{CN};
		  } elsif (exists $p->{login}) {
		    $rdn_val = $p->{login};
		  } else {
		    $rdn_val = $self->h_get_root_uid_val( $p->{dn_to_new_svc} // $p->{dn_to_onboard} );
		  }
		  my $svc_dn = sprintf(
				       '%s=%s,%s',
				       (exists $sc->{rdn}
					? $sc->{rdn}
					: $self->{app}->{cfg}->{ldap}->{defaults}->{rdn}),
				       $rdn_val,
				       $br->{br_dn}
				      );
		  # Search for an existing entry with that DN.
		  my $if_exist = $ldap->search({ base => $svc_dn, scope => 'base', attrs => [qw(uid authorizedService)] });
		  # If an entry exists, do nothing.
		  if ( $if_exist->count ) {
		    push @{$debug->{warn}}, '<mark>' . $svc_dn . '</mark> exists';
		    return { svc_dn => $svc_dn };
		  }

		  # Build a hash of all object classes from the LDAP schema.
		  my %objectclasses = map { $_->{name} => $_ } $ldap->schema->all_objectclasses;
		  my $schema = $ldap->schema;
		  my ($all_sup, $svc_attrs_must, $svc_attrs_may);
		  $all_sup = {}; $svc_attrs_must = {}; $svc_attrs_may = {};

		  # For each objectClass configured for the authorized service,
		  # mark it and all its superior classes.
		  foreach my $oc_name (@{$sc->{attr}->{objectClass}}) {
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
			next unless exists $sc->{attr}->{$attr};
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
		  if (exists $sc->{last_num_filter}) {
		    $uidNumber_last =
		      $ldap->last_num(
				      undef,
				      $sc->{last_num_filter},
				      undef,
				      'sub'
				     );
		  } else {
		    $uidNumber_last = $ldap->last_num;
		  }

		  # Generate a password (and other related values) for the service entry.
		  my $pwd;
		  my $svc_attrs = {};
		  my %svc_details;

		  # Set the objectClass attribute from configuration.
		  $svc_attrs->{objectClass} = $sc->{attr}->{objectClass};

		  #######################################################################
		  # processing of each form-field defined in the configuration          #
		  # EXAMPLE:								#
		  #									#
		  #   ssh-acc:								#
		  #     data_fields:							#
		  #       - associatedDomain						#
		  #       ...								#
		  #       - description							#
		  #     login_delim: "_"						#
		  #     attr:								#
		  #       cn: "%uid%"							#
		  #       homeDirectory: "/usr/local/home/%uid%"			#
		  #       ...								#
		  #       sn: "%sn%"							#
		  #       sshPublicKey: "%sshPublicKey%"				#
		  #######################################################################

		  foreach my $df (@{$sc->{data_fields}}) {
		    if ($df eq 'login') {
		      $svc_attrs->{uid} = $rdn_val;
		      $self->h_log($svc_attrs->{uid});
		      $svc_details{uid} = $svc_attrs->{uid};

		    } elsif ($df eq 'userPassword') {
		      $pwd = exists $p->{password2}
			? $self->h_pwdgen({ pwd_alg => 'alg-userdefined', pwd_userdefined => $p->{password2}, xk_num_words => 5 })
			: $self->h_pwdgen({ xk_num_words => 5 });
		      $svc_attrs->{userPassword} = $pwd->{ssha};
		      $svc_details{userPassword} = $pwd->{clear};
		      # $self->h_log($pwd);

		    } elsif ($df eq 'sshKeyText' || $df eq 'sshKeyFile') {
		      push @{$svc_attrs->{sshPublicKey}}, $p->{$df} if exists $p->{$df} && $p->{$df} ne '';

		    } elsif (!exists $p->{$df}) {
		      if (exists $sc->{attr}->{$df . '_prefix'}) {
			$svc_attrs->{$df} = sprintf(
						    "%s/%s.%s",
						    $sc->{attr}->{$df . '_prefix'},
						    lc $root->get_value('givenName'),
						    lc $root->get_value('sn')
						   );
		      } elsif (exists $sc->{attr}->{$df}) {
			$svc_attrs->{$df} = $sc->{attr}->{$df};
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
		    if ( $sc->{delim_mandatory} ) {
		      $replace{'%login%'} = $p->{login};
		    } else {
		      $replace{'%uid%'} = $svc_attrs->{uid};
		      $replace{'%cn%'} = $self->h_get_value_safe( $root, 'cn' ) // $replace{'%gecos%'};
		    }
		  }

		  $self->h_log(\%replace);
		  $self->h_log($svc_attrs);
		  foreach my $attr (keys %$svc_attrs_must) {
		    # $self->h_log($attr . ': ' . $self->h_np($replace{$attr}) . '; ' . $self->h_np($svc_attrs->{$attr}));
		    next if exists $svc_attrs->{$attr} && $svc_attrs->{$attr} =~ /^(?!.*%[[:alpha:]]+%).*$/;
		    if ($attr eq 'uidNumber') {
		      $svc_attrs->{$attr} = $uidNumber_last->[0] + 1;
		    } elsif (exists $sc->{attr}->{$attr}) {
		      $svc_attrs->{$attr} = $sc->{attr}->{$attr};
		      if ( $attr eq 'userCertificate;binary' ) { # binary data shouldn't be substituted
			$svc_attrs->{$attr} = $p->{'userCertificate;binary'};
		      } else {
			# looks for placeholders enclosed in percent signs like %FOO% or %FOO;BAR% in the string $a.
			#   For each placeholder:
			#     - If a corresponding key exists in %replace, substitute it with its value.
			#     - If the key is absent, leave the original placeholder unchanged.
			$svc_attrs->{$attr} =~ s/%([[:alpha:]]+(?:;[[:alpha:]]+)*)%/
			  exists $replace{"%$1%"} ? $replace{"%$1%"} : $&/ge;
		      }
		    } else {
		      $svc_attrs->{$attr} = undef;
		      $self->h_log('ERROR: must attribute is absent: ' . $attr);
		    }
		    $self->h_log('attr: ' . $attr . ' = ' . $self->h_np($svc_attrs->{$attr}));
		  }

		  foreach my $attr (keys %$svc_attrs_may) {
		    # next if exists $svc_attrs->{$attr} || !exists $sc->{attr}->{$attr};
		    next if exists $svc_attrs->{$attr} && $svc_attrs->{$attr} =~ /^(?!.*%[[:alpha:]]+%).*$/;
		    $svc_attrs->{$attr} = $sc->{attr}->{$attr};
		    if ( $attr eq 'userCertificate;binary' ) { # binary data shouldn't be substituted
		      $svc_attrs->{$attr} =$p->{'userCertificate;binary'};
		    } else {
		      # looks for placeholders enclosed in percent signs like %FOO% or %FOO;BAR% in the string $a.
		      #   For each placeholder:
		      #     - If a corresponding key exists in %replace, substitute it with its value.
		      #     - If the key is absent, leave the original placeholder unchanged.
		      $svc_attrs->{$attr} =~ s/%([[:alpha:]]+(?:;[[:alpha:]]+)*)%/
			exists $replace{"%$1%"} ? $replace{"%$1%"} : $&/ge;
		    }
		  }

		  $svc_attrs->{gecos} =$self->h_translit($svc_attrs->{gecos}) if exists$svc_attrs->{gecos};

		  $svc_attrs->{authorizedService} = sprintf('%s@%s', $p->{authorizedService},$p->{associatedDomain});
		  # $dry_run=1;
		  # $self->h_log($svc_attrs);$self->h_log($svc_attrs) if$dry_run == 1;

		  # Add the service entry to LDAP.
		  my $msg;
		  if ( $dry_run == 0 ) {
		    $msg =$ldap->add($svc_dn,$svc_attrs);
		  } else {
		    $msg = { status => 'ok',
			     message => sprintf('DRYRUN: h_service_add_if_not_exists() ldap->add dn: %s', $svc_dn) }
		  }
		  if ($msg) {
		    $self->h_log($msg);
		    push @{$debug->{$msg->{status}}},$msg->{message};
		    if ($msg->{status} eq 'ok') {
		      push @{$debug->{$msg->{status}}},
			sprintf('password: <span class="badge text-bg-secondary user-select-all">%s</span>', $pwd->{clear});

		      if ( $p->{authorizedService} =~ /^dot1x-eap-.*$/ ) {
			my $search_arg = { base =>$svc_attrs->{radiusGroupName},
					   scope => 'base',
					   filter => '(&(cn=*)(member=' . $svc_dn . '))', };
			my $if_exist =$ldap->search( $search_arg );$self->h_log( $self->h_ldap_err($if_exist, $search_arg) ) if$if_exist->code;
			if ( ! $if_exist->count ) {
			  my $mesg;
			  if ( $dry_run == 0 ) {
			    $mesg =$ldap->modify( $svc_attrs->{radiusGroupName}, [ add => [ member =>$svc_dn, ], ], );
			    if ( $mesg->{status} eq 'error' ) {
			      push @{$debug->{error}},
				sprintf('Error during <mark>%s</mark> group modification:</br>%s',
					$svc_attrs->{radiusGroupName},$mesg->{message}->{html});
			    } else {
			      push @{$debug->{ok}},
				sprintf('Group <mark>%s</mark> successfully modified with %s',
					$svc_attrs->{radiusGroupName},$mesg->{message}->{html});
			    }
			  } else {
			    push @{$debug->{ok}},
			      sprintf('DRYRUN: RADIUS group <mark>%s</mark> modify:<br> [ add => [ member => <mark>%s</mark>, ], ]',
				      $svc_attrs->{radiusGroupName},$mesg->{message}->{html});
			  }

			} else {
			  push @{$debug->{error}},
			    sprintf('object <mark>%s</mark> is already a member of %s', $svc_dn, $self->h_np($svc_attrs->{radiusGroupName}));

			}
		      }


		    }
		  }
		  # $self->h_log($debug);

		  my %r = ( svc_dn => $svc_dn, msg => $msg, svc_details => \%svc_details );$self->h_log(\%r);
		  return \%r;

		});

=head2 h_vcard

  my $vcards_str = $c->h_vcard($entries);

Generates a vCard address book string from LDAP search entries returned by C<as_struct>.

=over 4

=item B<Inputs>: C<$entries> (HashRef) - LDAP search entries hash reference from C<as_struct>.

=item B<Returns>: String - Concatenated vCard format text string.

=back

=cut

  $app->helper( h_vcard => sub {
		  my ($self,$entries) = @_;
		  # $self->h_log($entries );

		  my $abook = vCard::AddressBook->new();

		  foreach my $dn (sort keys %$entries) {
		    my %h;
		    my $e = $entries->{$dn};

		    $h{full_name}    =$e->{gecos}->[0] if ref($e->{gecos}) eq 'ARRAY' &&$e->{gecos}->[0] ne '';
		    $h{given_names}  =$e->{givenname}  if ref($e->{givenname}) eq 'ARRAY' &&$e->{givenname}->[0] ne '';
		    $h{family_names} =$e->{sn}         if ref($e->{sn}) eq 'ARRAY' &&$e->{sn}->[0] ne '';
		    $h{title}        =$e->{title}->[0] if ref($e->{title}) eq 'ARRAY' &&$e->{title}->[0] ne '';
		    # otherwise warning '... uninitialized value ... vCard.pm line 112' occures
		    $h{photo} = '';

		    if (exists $e->{mail}) {
		      for (@{$e->{mail}}) {
			next if $_ eq '';
			push @{$h{email_addresses}}, { type => ['work'], address =>$_ };
		      }
		    }

		    if (exists $e->{telephonenumber}) {
		      for (@{$e->{telephonenumber}}) {
			next if $_ eq '';
			push @{$h{phones}}, { type => ['work'], number =>$_ };
		      }
		    }

		    my $vcard = $abook->add_vcard();$vcard->load_hashref(\%h);
		    # $self->h_log($vcard->as_string );
		    # $self->h_log( \%h );
		  }

		  return $abook->as_string;
		});

  ### END OF REGISTER --------------------------------------------------------------------------------------------
}

1;
