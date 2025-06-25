# -*- mode: cperl; eval: (follow-mode 1); -*-

package Umi::Controller::Protected;

use Mojo::Base 'Mojolicious::Controller', -signatures;
use Mojo::Util qw(b64_encode dumper trim);
use Mojo::JSON qw(decode_json encode_json to_json);

use Mojolicious::Validator;

use IO::Compress::Gzip qw(gzip $GzipError);
use POSIX qw(strftime);
use Time::Piece;
use Encode qw(decode_utf8);
use Net::LDAP::Constant qw(
			    LDAP_ALREADY_EXISTS
			    LDAP_SUCCESS
			    LDAP_PROTOCOL_ERROR
			    LDAP_NO_SUCH_OBJECT
			    LDAP_INVALID_DN_SYNTAX
			    LDAP_INSUFFICIENT_ACCESS
			    LDAP_CONTROL_SORTRESULT
			 );
use Net::LDAP::Util qw(generalizedTime_to_time);

use Storable qw(nfreeze);
use Umi::Ldap;

sub homepage ($self) {
  if ($self->session('debug')) {
    $self->stash( debug => $self->session('debug') );
    delete $self->session->{debug};
  }

  my %debug;
  push @{$debug{ok}},
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
    'Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.';
  push @{$debug{error}},
    'call from <b><em>Umi::Ldap::modify</em></b>: <dl class="row mt-3 w-100">
  <dt class="col-2 text-end">DN</dt>
  <dd class="col-10 font-monospace">uid=testoid,ou=People,dc=nxc,dc=no</dd>
  <dt class="col-2 text-end">admin note</dt>
  <dd class="col-10 font-monospace"></dd>
  <dt class="col-2 text-end">supplementary data</dt>
  <dd class="col-10 font-monospace"></dd>
  <dt class="col-2 text-end">code</dt>
  <dd class="col-10 font-monospace">21</dd>
  <dt class="col-2 text-end">error name</dt>
  <dd class="col-10 font-monospace">LDAP_INVALID_SYNTAX</dd>
  <dt class="col-2 text-end">error text</dt>
  <dd class="col-10 font-monospace"><em><small><pre><samp>Some part of the request contained an invalid syntax. It could be a search
with an invalid filter or a request to modify the schema and the given
schema has a bad syntax.
</samp></pre></small></em></dd>
  <dt class="col-2 text-end">error description</dt>
  <dd class="col-10 font-monospace">Invalid syntax</dd>
  <dt class="col-2 text-end">server_error</dt>
  <dd class="col-10 font-monospace">objectClass: value #6 invalid per syntax</dd>
</dl>',
  '[
    [0] "replace",
    [1] [
	    [0] "l",
	    [1] "деревня Гадюкино",
	    [2] "title",
	    [3] "big ass to kick ну или просто дурачок",
	    [4] "objectClass",
	    [5] [
		    [0] "grayAccount",
		    [1] "inetOrgPerson",
		    [2] "organizationalPerson",
		    [3] "person",
		    [4] "posixAccount",
		    [5] "shadowAccount",
		    [6] "topxfsfdgfg",
		    [7] "umiUser"
		],
	    [6] "givenName",
	    [7] "Тестойид 11111111111111111111"
	]
]';
  push @{$debug{warn}},
    'Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.',
    'Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.';

  # $self->stash(debug => \%debug);

  $self->render( template => 'protected/home' );
}

sub other ($self) { $self->render(template => 'protected/other'); }

sub manage_chi ($self) {
  my $p = $self->req->params->to_hash;
  $self->h_log($p);

  my $command = $p->{command} // 'remove';

   if ( $command eq 'remove' ) {
     $self->chi('fs')->clear;
   }

  return $self->render(template => 'protected/home');
}

sub delete ($self) {
  my %debug;
  my $p = $self->req->params->to_hash;
  $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $auth = $self->h_is_authorized($p->{delete_dn});
  $self->h_log($auth);

  return $self->render(template => 'not_allowed',
		       debug => { warn => ['attempt to delete dn: ' . $p->{delete_dn}]})
    unless $auth;

  my $msg = $ldap->delete($p->{delete_dn},
			  exists $p->{delete_recursive} && $p->{delete_recursive} eq 'on' ? 1 : 0);
  push @{$debug{$msg->{status}}}, $msg->{message};
  $self->stash(debug => \%debug);
  $self->h_log(\%debug);

  ### alas, this redirect by nature performs a GET request
  return $self
    ->redirect_to($self->url_for('search_common')
		  ->query( search_base_case => $p->{search_base_case},
			   search_filter => $p->{search_filter},
			   ldap_subtree => $p->{ldap_subtree} )
		 );
}

=head1 fire

steps to do on employee firing

=cut

sub fire ($self) {
  my $p = $self->req->params->to_hash;
  $self->h_log($p);

  return $self->render(template => 'protected/home') unless $p->{fire_dn};

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $search_arg = { base => $p->{fire_dn},
		     scope => 'sub',
		     attrs => [] };
  # $self->h_log($search_arg);
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;

  my ($ldif, $root_e);
  foreach ($search->entries) {
    $root_e = $_ if $_->dn eq $p->{fire_dn};
    $ldif .= $_->ldif( %{$self->{app}->{cfg}->{ldap}->{defaults}->{ldif}} );
  }

  $ldif = sprintf("%s### description: %s\n\n%s",
		  $self->h_ldif_header,
		  length($p->{description}) ? $p->{description} : '',
		  $ldif);

  # $self->h_log($ldif);

  my $ldif_gz;
  # Compress the data
  gzip \$ldif => \$ldif_gz
    or die "ERROR: gzip failed: $GzipError\n";

  my $ldif_gz_b64 = b64_encode $ldif_gz;

  # $self->h_log($ldif_gz_b64);

  my $aaa = $root_e->get_value('objectClass',asref => 1);
  $self->h_log($aaa);
  my $is_objectClass = grep { $_ eq 'umiUser' } @$aaa;
  $self->h_log($is_objectClass);
  my ($changes, $add, $replace);
  if ( $root_e->exists('umiUserBackup') ) {
      push @$replace, umiUserBackup => $ldif_gz_b64;
      push @$changes, replace => $replace;
  } elsif ( $is_objectClass ) {
      push @$add, umiUserBackup => $ldif_gz_b64;
      push @$changes, add => $add;
  } else {
      push @$add, objectClass => 'umiUser', umiUserBackup => $ldif_gz_b64;
      push @$changes, add => $add;
  }

  push @$replace, gidNumber => $self->{app}->{cfg}->{ldap}->{defaults}->{group}->{blocked}->{gidnumber};
  push @$replace, userPassword => '!' . $root_e->get_value('userPassword') if $root_e->exists('userPassword');

  push @$changes, replace => $replace;

  # !!! TODO TO FINISH ERROR HANDLING !!!
  # $self->h_log($changes);
  my $msg = $ldap->modify($p->{fire_dn}, $changes);
  $self->h_log($msg);
  if ( $msg->{status} eq 'ok' ) {
    $self->session(debug => {$msg->{status} => [ $msg->{message} ]});

    $msg = $ldap->delete($p->{fire_dn}, 1, 'children');
    $self->session( debug => $msg );

    ### alas, this redirect by nature performs a GET request
    return $self
      ->redirect_to($self->url_for('search_common')
		    ->query( search_base_case => $p->{search_base_case},
			     search_filter => $p->{search_filter},
			     ldap_subtree => $p->{ldap_subtree} )
		   );
  }

}

=head2 block

block all user accounts (via password change and ssh-key modification)
to make it impossible to use any of them

unblock is possible only via password change, ssh-key modification and
removal from the special group for blocked users

=cut


sub block ($self) {
  my $p = $self->req->params->to_hash;
  $self->h_log($p);

  return $self->render(template => 'protected/home') unless $p->{block_dn};

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $search_arg = { base => $p->{block_dn}, scope => 'sub', attrs => [] };
  # $self->h_log($search_arg);
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;

  my (%debug, $msg);
  foreach my $e ( $search->entries ) {
    next if $e->dn =~ /^authorizedService=/;

    if ( $e->dn eq $p->{block_dn} ) {
      $msg = $ldap->modify( $e->dn,
			    [
			     replace => [ gidNumber => $self->{app}->{cfg}->{ldap}->{defaults}->{group}->{blocked}->{gidnumber},
					  userPassword => '!' . $e->get_value('userPassword') ]
			    ] );
      push @{$debug{$msg->{status}}}, $msg->{message};
    } else {

      if ( $e->exists('userPassword') && substr($e->get_value('userPassword'), 0, 1) ne '!') {
	$msg = $ldap->modify( $e->dn, [ replace =>
					[ userPassword =>	sprintf("!%s", $e->get_value('userPassword')), ],
				      ], );

	push @{$debug{$msg->{status}}}, $msg->{message};
      }

      if ( $e->exists('sshPublicKey') ) {
	my @keys = map
	  {
	    substr($_, 0, 4) eq 'ssh-' ? sprintf('from="0.0.0.0" %s', $_) : $_
	  }
	  @{$e->get_value('sshPublicKey', asref => 1)};

	$msg = $ldap->modify( $e->dn, [ replace => [ sshPublicKey => \@keys, ],], );
	push @{$debug{$msg->{status}}}, $msg->{message};
      }

      if ( $e->exists('grayPublicKey') ) {
	my @keys = map
	  {
	    substr($_, 0, 4) eq 'ssh-' ? sprintf('from="0.0.0.0" %s', $_) : $_
	  }
	  @{$e->get_value('grayPublicKey', asref => 1)};

	$msg = $ldap->modify( $e->dn, [ replace => [ grayPublicKey => \@keys, ],], );
	push @{$debug{$msg->{status}}}, $msg->{message};
      }

      if ( $e->exists('umiOvpnAddStatus') ) {
	$msg = $ldap->modify( $e->dn, [ replace => [ umiOvpnAddStatus => 'disabled', ], ], );
	push @{$debug{$msg->{status}}}, $msg->{message};
      }
    }
  }

  ### alas, this redirect by nature performs a GET request and the only way
  ### to pass debug is chi (not stash, not flash)
  #$self->chi('fs')->set( debug => \%debug );
  $self->flash( debug => \%debug );
  return $self
    ->redirect_to($self->url_for('search_common')
		  ->query( search_base_case => $p->{search_base_case},
			   search_filter => $p->{search_filter},
			   ldap_subtree => $p->{ldap_subtree} )
		 );


#   # is this user in block group?
#   my $blockgr_dn =
#     sprintf('cn=%s,%s',
#	    $self->cfg->{stub}->{group_blocked},
#	    $self->cfg->{base}->{group});

#   $msg = $self->search ( { base   => $self->cfg->{base}->{group},
#			   filter => sprintf('(&(cn=%s)(memberUid=%s))',
#					     $self->cfg->{stub}->{group_blocked},
#					     substr( (split /,/, $args->{dn})[0], 4 )),
#			   sizelimit => 0, } );
#   if ( $msg->is_error() ) {
#     $return->{error} .= $self->err( $msg )->{html};
#   } elsif ( $msg->count == 0) {
#     $msg_chg = $self->search ( { base => $blockgr_dn, } );
#     if ( $msg_chg->is_error() ) {
#       $return->{error} .= $self->err( $msg_chg )->{html};
#     } else {
#       $ent_chg = $self->modify( $blockgr_dn,
#				[ add =>
#				  [ memberUid => substr( (split /,/, $args->{dn})[0], 4 ), ], ], );
#       if ( ref($ent_chg) eq 'HASH' ) {
#	$return->{error} .= $ent_chg->{html};
#       } else {
#	$return->{success} .= $args->{dn} . " successfully blocked.\n";
#       }
#     }
#   }

#   log_debug { np( $return ) };

#   return $return;
}

=head1 ldif_import

import LDIF record or file

=cut

sub ldif_import ($self) {
  my $p = $self->req->params->to_hash;
  # $self->h_log($p);
  my $uploads = $self->req->uploads;
  # $self->h_log($uploads);
  $p->{file} = $uploads->[0]->slurp if @$uploads;

  my $v = $self->validation;
  return $self->render(template => 'protected/tool/ldif-import') unless $v->has_data;

  my ( $ldif, $err );
  $ldif->{ldif} = $p->{ldif} if defined $p->{ldif} && $p->{ldif} ne '';
  $ldif->{file} = $p->{file} if defined $p->{file};
  # $self->h_log($ldif);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $res = $ldap->ldif_read(defined $p->{file} && $p->{file} ne '' ? $p->{file} : $p->{ldif} );

  $self->stash(debug => $res->{debug});

  # $self->h_log($key);
  return $self->render(template => 'protected/tool/ldif-import',
		       # layout => undef
		      );
}

=head1 ldif_export

export LDIF record for the object chosen

=cut

sub ldif_export ($self) {
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/ldif-export') unless $v->has_data;

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $p = $self->req->params->to_hash;
  # $self->h_log($p);
  $p->{dn} =~ s/ //g;
  my $search_arg = { base => $p->{dn}, scope => $p->{scope} };
  $search_arg->{attrs} = [] if !exists $p->{sysinfo};
  # $self->h_log($search_arg);
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;

  my $ldif;
  $ldif .= $_->ldif( %{$self->{app}->{cfg}->{ldap}->{defaults}->{ldif}} ) foreach ($search->entries);

  # $self->h_log($ldif);
  $self->stash( ldif_export_params => $p,
		ldif => sprintf("%s##\n# dn: %s\n%s\n#\n%s",
				$self->h_ldif_header,
				$p->{dn},
				join("\n",
				     map {
				       '# ' . $_ . ': ' . $self->h_np($search_arg->{$_}, 0) if defined $search_arg->{$_}
				     }
				     sort keys %$search_arg),
				$ldif)
 );
  return $self->render(template => 'protected/tool/ldif-export'); #, layout => undef);
}

=head1 ldif_clone

generate LDIF for the object chosen and insert it into an import form
template

=cut

sub ldif_clone ($self) {
  my $p = $self->req->params->to_hash;

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my ($ldif, $search, $search_arg, $res);
  if ( ! exists $p->{ldif} ) {
    $search_arg = { base => $p->{dn_to_clone}, scope => 'base', attrs => [] };
    $search = $ldap->search( $search_arg );
    $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;
    $ldif .= $_->ldif( %{$self->{app}->{cfg}->{ldap}->{defaults}->{ldif}} ) foreach ($search->entries);
  } else {
    $res = $ldap->ldif_read( $p->{ldif} );
    $self->stash(debug => $res->{debug});
  }

  # $self->h_log($ldif);
  $self->stash(dn_to_clone => $p->{dn_to_clone},
	       ldif => exists $p->{ldif}
	       ? $p->{ldif}
	       : sprintf("%s##\n# dn: %s\n%s\n#\n%s",
			 $self->h_ldif_header,
			 $p->{dn_to_clone},
			 join("\n",
			      map {
				'# ' . $_ . ': ' . $self->h_np($search_arg->{$_}, 0) if defined $search_arg->{$_}
			      }
			      sort keys %$search_arg),
			 $ldif),
	       );
  return $self->render( template => 'protected/tool/ldif-clone', );
}

=head1 undo_al

undo changes in the accesslog object chosen

=cut

sub undo_al ($self) {
  my $p = $self->req->params->to_hash;

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  $self->h_log($ldap->undo_al($p->{dn_to_undo}));

  $self->req->params->merge( ldif => $ldap->undo_al($p->{dn_to_undo})->{ldif} );
  $self->stash(dn_to_undo => $p->{dn_to_undo});
  return $self->render( template => 'protected/tool/ldif-import', );
}

sub sysinfo ($self) {
  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my $schema = $ldap->schema;
  my %oc = map { $_->{name} => $_ } $schema->all_objectclasses;
  my %aa = map { $_->{name} => $_ } $schema->all_attributes;
  my %as = map { $_->{name} => $_ } $schema->all_syntaxes;
  my %s;
  $s{all_objectclasses} = \%oc;
  $s{all_attributes} = \%aa;
  $s{all_syntaxes} = \%as;

  my $chi;
  @{$chi->{keys}} = $self->chi('fs')->get_keys;
  @{$chi->{namespaces}} = $self->chi('fs')->get_namespaces;

  return $self->render( template => 'protected/tool/sysinfo',
			schema => encode_json(\%s),
			chi => $chi,
			); # layout => undef);
}

sub pwdgen ($self) {
  my $cf = $self->{app}->{cfg}->{tool}->{pwdgen}->{xk};
  my $par = $self->req->params->to_hash;
  # $self->h_log($par);

  if ( exists $par->{pwd_chg_dn} ) {
    $par->{pwd_chg_rdn} = $self->h_get_rdn_val($par->{pwd_chg_dn}) if ! exists $par->{pwd_chg_rdn};
    if ( ! exists $par->{pwd_chg_svc} && $par->{pwd_chg_dn} =~ /authorizedService=/ ) {
      my $re = qr/^.*,authorizedService=([^,]+),uid=.*,$self->{app}->{cfg}->{ldap}->{base}->{acc_root}$/i;
      $par->{pwd_chg_svc} = $1 if $par->{pwd_chg_dn} =~ /$re/;
    }
  }

  $self->stash({ pwdgen_params => $par }) if exists $par->{pwd_chg_dn};

  return $self->render( template => 'protected/tool/pwdgen' ) unless exists $par->{pwd_vrf} || exists $par->{pwd_alg};

  my $v = $self->validation;

  if ( ! exists $par->{pwd_vrf} ) {
    $v->error( xk_num_words => ['can not be empty']) if ! exists $par->{xk_num_words} || ( exists $par->{xk_num_words} && length($par->{xk_num_words}) < 1 );

    $v->error( xk_separator_character_char => ['can not be empty'] )
      if exists $par->{xk_separator_character} && $par->{xk_separator_character} eq 'sep-char'
      && exists $par->{xk_separator_character_char} && $par->{xk_separator_character_char} eq '';

    $v->error( xk_separator_alphabet => ['can not be empty'])
      if exists $par->{xk_separator_character} && $par->{xk_separator_character} eq 'sep-random'
      && exists $par->{xk_separator_alphabet} && length($par->{xk_separator_alphabet}) < 1;

    $v->error( xk_padding_digits_before => ['can not be empty']) if exists $par->{xk_padding_digits_before} && length($par->{xk_padding_digits_before}) < 1;
    $v->error( xk_padding_digits_after => ['can not be empty']) if exists $par->{xk_padding_digits_after} && length($par->{xk_padding_digits_after}) < 1;

    $v->error( xk_padding_characters_before => ['can not be empty'])
      if exists $par->{xk_padding_type} && $par->{xk_padding_type} eq 'pad-fixed'
      && exists $par->{xk_padding_characters_before} && length($par->{xk_padding_characters_before}) < 1;
    $v->error( xk_padding_characters_after => ['can not be empty'])
      if exists $par->{xk_padding_type} && $par->{xk_padding_type} eq 'pad-fixed'
      && exists $par->{xk_padding_characters_after} && length($par->{xk_padding_characters_after}) < 1;

    $v->error( xk_padding_character_char => ['can not be empty'])
      if exists $par->{xk_padding_character} && $par->{xk_padding_character} eq 'pch-character'
      && exists $par->{xk_padding_character_char} && length($par->{xk_padding_character_char}) < 1;
    $v->error( xk_padding_alphabet => ['can not be empty'])
      if exists $par->{xk_padding_character} && $par->{xk_padding_character} eq 'pch-random'
      && exists $par->{xk_padding_alphabet} && length($par->{xk_padding_alphabet}) < 1;

    $v->error( xk_pad_to_length => ['can not be empty'])
      if exists $par->{xk_padding_type} && $par->{xk_padding_type} eq 'pad-adaptive'
      && exists $par->{xk_pad_to_length} && length($par->{xk_pad_to_length}) < 1;

    $v->error( pwd_userdefined => ['can not be empty'])
      if $par->{pwd_alg} eq 'alg-userdefined'
      && exists $par->{pwd_userdefined} && length($par->{pwd_userdefined}) < 1;
  }

  my $pwdgen;
  if ( ! $v->has_error ) {

    # $self->h_log($par);
    $pwdgen = $self->h_pwdgen($par);
    my $qr = $self->h_qrcode({toqr => $pwdgen->{clear}, mod => 3, html => 1});
    # $self->h_log($pwdgen);
    if ( exists $pwdgen->{error} ) {
      $self->stash({debug => { error => [ $pwdgen->{error} ]}});
    } else {
      my ($ldap, $search, $search_arg, $pwd_from_ldap, $match, $mesg);
      if (exists $par->{pwd_chg_dn}) {
	$ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
	if (exists $par->{pwd_vrf}) {
	  ### password verification against LDAP
	  $search_arg = { base => $par->{pwd_chg_dn}, attrs => ['userPassword'] };
	  $search = $ldap->search( $search_arg );
	  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;
	  $pwd_from_ldap = $search->entry->get_value('userPassword');
	  $self->h_log($pwd_from_ldap);
	  $match = $pwd_from_ldap eq $pwdgen->{ssha} ? 1 : 0;
	  $self->stash({debug => { $match ? 'ok' : 'warn' => [ sprintf('provided password <span class="badge text-bg-secondary user-select-all">%s</span> %s',
								       $pwdgen->{clear},
								       $match ? 'match' : 'does not match') ]
				 }});
	} else {
	  ### userPassword attribute modification
	  $mesg = $ldap->modify( $par->{pwd_chg_dn}, [ replace => [ 'userPassword' => $pwdgen->{ssha}, ], ] );
	  $self->h_log($mesg );
	  # $self->h_log( $self->{app}->h_ldap_err($mesg, undef) ) if $mesg->code;
	  $self->stash({debug =>
			{ $mesg->{status} => [ $mesg->{message},
					       sprintf('new password: <span class="badge text-bg-secondary user-select-all">%s</span>',
						       $pwdgen->{clear}),
					       $qr->{html} ]
			}});
	}
      } else {
	$self->stash({debug =>
		      { ok  => [ sprintf('<span class="badge text-bg-secondary user-select-all">%s</span>',
						     $pwdgen->{clear}),
					     $qr->{html} ]
		      }});
      }
    }
  }
  return $self->render(template => 'protected/tool/pwdgen',
		       pwdgen_params => $par,
		       pwdgen => $pwdgen,
		       ); # layout => undef);
}

sub qrcode ($self) {
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/qrcode') unless $v->has_data;

  my $par = $self->req->params->to_hash;
  $self->stash(qrcode_params => $par);
  return $self->render(template => 'protected/tool/qrcode' => qrcode => $self->h_qrcode($par)); # , layout => undef);
}

sub keygen_ssh ($self) {
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/keygen/ssh') unless $v->has_data;

  my $par = $self->req->params->to_hash;
  $self->stash(kg_ssh_params => $par);

  my $k = $self->h_keygen_ssh($par);
  $self->stash(debug => $k->{debug});

  # $self->h_log($k);
  return $self->render(template => 'protected/tool/keygen/ssh',
		       key => {
			       ssh => $k,
			       name => { real => 'name will be here',
					 email => 'email will be here' }
			      },
		       # layout => undef
		      );
}

sub keygen_gpg ($self) {
  my (%debug, $ldap, $search_arg, $search, $msg, $k, $op_dn, $op_attrs);
  my $p = $self->req->params->to_hash;
  $self->h_log($p);
  my $v = $self->validation;
  return $self->render(template => 'protected/tool/keygen/gpg') unless $v->has_data;

  $p->{name} = {
		real => sprintf("%s %s", $self->session->{user_obj}->{givenname}, $self->session->{user_obj}->{sn}),
		email => exists $self->session->{user_obj}->{mail} ? $self->session->{user_obj}->{mail} : 'no email'
	       };

  $k = $self->h_keygen_gpg($p);
  %debug = %{$k->{debug}} if exists $k->{debug};
  #$self->h_log($k);

  if ( $p->{replace_keys} eq 'on') {
    # $self->h_log($self->session('user_obj')->{mail});
    # $self->h_log('!!! FINISH keygen_gpg controller !!!');

    $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
    $search_arg = {
		   base => $self->{app}->{cfg}->{ldap}->{base}->{pgp},
		   filter => sprintf("(|(pgpUserID=*%s*)(pgpUserID=*%s*))", $p->{name}->{real}, $p->{name}->{email})
		  };
    $search = $ldap->search( $search_arg );
    $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;
    # $self->h_log( $self->h_ldap_err($search) );
    if ( $search->count ) {
      foreach ($search->entries) {
	$msg = $ldap->delete($_->dn, 0);
	$self->h_log( $msg );
	push @{$debug{$msg->{status}}}, $msg->{message};
      }
      # $self->h_log( 'DELETE DN:' . $_->dn ) foreach ($search->entries);
    }

    $op_dn = sprintf("pgpCertID=%s,%s",
		     $k->{send_key}->{pgpCertID},
		     $self->{app}->{cfg}->{ldap}->{base}->{pgp});
    %{$op_attrs} = map { $_ => $k->{send_key}->{$_} } keys %{$k->{send_key}};
    # $self->h_log($op_dn);
    # $self->h_log($op_attrs);
    $msg = $ldap->add( $op_dn, $op_attrs );
    push @{$debug{$msg->{status}}}, $msg->{message};
  }

  $self->stash(debug => \%debug);

  # $self->h_log(\%debug);

  return $self->render(template => 'protected/tool/keygen/gpg',
		       key => $k,
		       # layout => undef
		      );
}


=head1 keyimport_gpg

Import GPG from file or string

=cut

sub keyimport_gpg ($self) {
  my $par = $self->req->params->to_hash;
  # $self->h_log($par);
  my $uploads = $self->req->uploads;
  # $self->h_log($uploads);
  $par->{key_file} = $uploads->[0]->slurp if @$uploads;

  my $v = $self->validation;
  return $self->render(template => 'protected/tool/keyimport/gpg') unless $v->has_data;

  my ( $key, $err );
  $key->{import}->{key_text} = $par->{key_text} if defined $par->{key_text} && $par->{key_text} ne '';
  $key->{import}->{key_file} = $par->{key_file} if defined $par->{key_file};
  # $self->h_log($key);

  $key->{gpg} = $self->h_keygen_gpg({ import => $key->{import}, });
  $self->stash(debug => $key->{gpg}->{debug}) if exists $key->{gpg}->{debug};

  if ( !exists $key->{gpg}->{debug}->{error} ) {
    my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
    my ($add_dn, $add_arg);
    $add_dn = sprintf("pgpCertID=%s,%s",
		      $key->{gpg}->{send_key}->{pgpCertID},
		      $self->{app}->{cfg}->{ldap}->{base}->{pgp});
    @{$add_arg} = map { $_ => $key->{gpg}->{send_key}->{$_} } keys %{$key->{gpg}->{send_key}};
    my $a = $ldap->add( $add_dn, $key->{gpg}->{send_key} );
    $self->h_log( $a->{message} ) if $a->{status} eq 'error';
    $self->stash(debug => {$a->{status} => [ $a->{message} ]});
  }

  # $self->h_log($key);
  return $self->render(template => 'protected/tool/keyimport/gpg',
		       key => $key,
		       # layout => undef
		      );
}

=head1 modify

method to modify whole oject or some definite attribute (if parameter
attr_to_modify exists)

=cut

sub modify ($self) {
  my $p = $self->req->params->to_hash;

  return $self->render(template => 'protected/home') unless exists $p->{dn_to_modify};

  my $uploads = $self->req->uploads;
  my ($crt, %debug, $service);
  # $self->h_log($p);
  # $self->h_log($uploads);
  if ( @$uploads ) {
    if ( exists $p->{authorizedService} ) {
      ($service) = $p->{authorizedService} =~ /([^@]+)/;
    }

    foreach ( @$uploads ) {
      # $self->h_log($_);
      my $n = $_->name;
      $n =~ s/_binary/;binary/;
      $p->{$n} = $_->slurp;

      if ( $n eq 'userCertificate;binary' ) {
	$crt = $self->h_cert_info({ cert => $p->{$n}, ts => "%Y%m%d%H%M%S", });
	$p->{umiUserCertificateSn}        = '' . $crt->{'S/N'},
	$p->{umiUserCertificateNotBefore} = '' . $crt->{'Not Before'},
	$p->{umiUserCertificateNotAfter}  = '' . $crt->{'Not After'},
	$p->{umiUserCertificateSubject}   = '' . $crt->{Subject},
	$p->{umiUserCertificateIssuer}    = '' . $crt->{Issuer};
	$p->{cn} = $crt->{CN}
	  if exists $p->{cn} && $self->{app}->{cfg}->{ldap}->{authorizedService}->{$service}->{rdn} ne 'cn';
	# FIX ?? this relates to the services like `dot1x-eap-tls`
	# and not necesseraly should be equal to certificate CN
	# need to check, wheather userPassword was provided to not overwrite it
	$p->{userPassword} = $crt->{CN} if exists $p->{userPassword};
      } elsif ( $n eq 'jpegPhoto' && $p->{$n} ne '' ) {
	$p->{$n} = $self->h_img_resize( $p->{$n}, $_->size );
      }
    }
  }
  # $self->h_log($p);

  my $attr_to_add = exists $p->{attr_to_add} && $p->{attr_to_add} ne '' ? $p->{attr_to_add} : undef;
  my $dn_to_modify = $p->{dn_to_modify};
  my $attr_to_ignore;
  my $rdn = $self->h_get_rdn($dn_to_modify);
  %{$attr_to_ignore} = map {$_ => 1}
    @{[qw(dn_to_modify attr_to_add attr_unused modifyTimestamp modifiersName creatorsName createTimestamp)]};
  $attr_to_ignore->{$rdn} = 1;

  ##############################################
  # check for permissions to modify the object #
  ##############################################
  my $auth = $self->h_is_authorized($p->{dn_to_modify});
  # $self->h_log($auth);
  return $self->render(template => 'not_allowed',
		       debug => { warn => ['attempt to modify dn: ' . $p->{dn_to_modify}]}) unless $auth;

  my $v = $self->validation;
  return $self->render(template => 'protected/tool/modify') unless $v->has_data;
  # return $self->render(template => 'protected/tool/modify') unless %$p;

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my $search_arg = { base => $p->{dn_to_modify}, scope => 'base' };
  $search_arg->{attrs} = defined $attr_to_add ? [$attr_to_add] : [];
  # $self->h_log( $search_arg );
  my $s = $ldap->search( $search_arg );
  if ( $s->code ) {
    $self->h_log( $self->h_ldap_err($s, $search_arg) );
    return $self->render(template => 'protected/home',
			 debug => {
				   status => 'error',
				   message => $ldap->err($s, 0, $p->{dn_to_modify})->{html}
				  });
    # $self->h_log( $s->as_struct );
  }

  my $e_orig = $self->h_modify_get_e_orig($s, $rdn, $p);

  # push @{$p->{objectClass}}, 'umiUser'
  #   if !grep { $_ eq 'umiUser' } @{$p->{objectClass}};

  # $self->h_log($p);
  # $self->h_log($e_orig);

  # `UNUSED ATTRIBUTES` select element
  my ($schema, %oc, %aa, %as, @attr_unused);
  if ( ! defined $attr_to_add ) {
    $schema = $ldap->schema;
    %oc = map { $_->{name} => $_ } $schema->all_objectclasses;
    %aa = map { $_->{name} => $_ } $schema->all_attributes;
    %as = map { $_->{name} => $_ } $schema->all_syntaxes;
    @attr_unused = $self->h_attr_unused($s->entry, \%oc);
  }
  # NEED to re-check what it is for :(
  $self->stash({ attr_to_add => $p->{attr_to_add} })
    if defined $attr_to_add;

  my ($add, $delete, $replace, $changes);
  if ( keys %$p < 3 && !exists $p->{add_objectClass} ) {
    # here we've just clicked, search result  menu `modify` button
    $self->h_log('~~~~~-> MODIFY [' . $self->req->method . ']: FIRST RUN (search result menu choosen)');
  } elsif (exists $p->{add_objectClass}) {
    # new objectClass addition is chosen
    $self->h_log('~~~~~-> MODIFY [' . $self->req->method . ']: ADD OBJECTCLASS');
    $self->h_log($p);
    foreach (keys(%$p)) {
      next if $_ !~ /^add_/;
      push @$add, substr($_,4) => $p->{$_};
    }
    push @$changes, add => $add;
    if ($changes) {
      $self->h_log($changes);
      my $msg = $ldap->modify($s->entry->dn, $changes);
      push @{$debug{$msg->{status}}}, $msg->{message};
    }
  } else {
    # form modification made
    $self->h_log('~~~~~-> MODIFY [' . $self->req->method . ']: IS FORM CHANGED?');
    delete $p->{$_} foreach (keys %{$attr_to_ignore});
    foreach (keys %$p) {
      delete $p->{$_} if $p->{$_} eq '';
    }

    my $diff = $self->h_hash_diff( $e_orig, $p);
    #$self->h_log($diff);
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
      # $self->h_log($changes);
      my $msg = $ldap->modify($s->entry->dn, $changes);
      push @{$debug{$msg->{status}}}, $msg->{message}, $self->h_np($changes);

      if ( exists $p->{'userCertificate;binary'} ) {
	# ($service) = $p->{authorizedService} =~ /([^@]+)/;
	# $self->h_log($service);
	my $moddn = $self->{app}->{cfg}->{ldap}->{authorizedService}->{$service}->{rdn} . '=' . $crt->{CN};
	$msg = $ldap->moddn({ src_dn => $s->entry->dn, newrdn => $moddn, });
	# $self->h_log($msg);
	push @{$debug{$msg->{status}}}, $msg->{message};
	my $modified_dn = $s->entry->dn;
	$modified_dn =~ s/^(.*?=)[^,]+(,.*)/$1$crt->{CN}$2/;
	# $self->h_log(\%debug);

	my $changes_serialized = nfreeze(\%debug);
	my $changes_size = length($changes_serialized);
	 $self->h_log($changes_size);
	if ( $changes_size < 1000 ) {
	  $self->stash(debug => \%debug);
	} else {
	  # causes `Cookie "xxx" is bigger than 4KiB`, so ... if we really need it then put it into CHI
	  $self->chi('fs')->set( debug => { $msg->{status} => [ $msg->{message}, $self->h_np($changes) ] });
	}

	# return $self->session( debug => \%debug )
	return $self->redirect_to($self->url_for('modify')
				  ->query( dn_to_modify => $modified_dn ));
      }

    }
  }

  $search_arg->{base} = $dn_to_modify;
  $s = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($s, $search_arg) ) if $s->code;
  @attr_unused = $self->h_attr_unused($s->entry, \%oc) if ! defined $attr_to_add;

  $self->stash(
	       entry => $s->entry,
	       aa => \%aa, as => \%as, oc => \%oc,
	       attr_unused => \@attr_unused,
	       attr_to_add => $attr_to_add,
	       attr_to_ignore => $attr_to_ignore,
	       #dn_to_modify => $attr_to_add
	      );

  my $changes_serialized = nfreeze(\%debug);
  my $changes_size = length($changes_serialized);
  if ( $changes_size < 3500 ) {
    $self->stash(debug => \%debug);
  } else {
    # causes `Cookie "xxx" is bigger than 4KiB`, so ... if we really need it then put it into CHI
    $self->chi('fs')->set( debug => \%debug );
  }

  return $self->render(template => 'protected/tool/modify'); #, layout => undef);
}

=head1 profile

prepares user/s data to show profile/s (conditionally) according a route
placeholder :uid, which must not be empty (in this case redirect to home
page is done) and can be one of these keywords:

    all
    disabled
    active
    uid-of-user

=cut

sub profile ($self) {
  my $p = $self->req->params->to_hash;
  my $reqpath = $self->req->url->to_abs->path;
  my ($uid, $filter, $chi, $chi_key, $chi_template, $to_chi);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $contextCSN = $ldap->get_contextCSN;
  if ( $reqpath =~ /^\/audit\/.*$/ ) {
    $chi_key = 'profile_audit';
    $chi_template = 'protected/audit/users';
    $uid = 'all';
  } else {
    $uid = $p->{uid} // $self->stash->{uid} // '';
    $chi_template = 'protected/profile';
  }

  ### PROFILE TO GET:
  if ($uid eq 'all') {
    $chi_key = 'profile_all' if ! defined $chi_key;
    $filter = '(uid=*)';
    ### $filter = '(uid=al*)';
  } elsif ($uid eq 'disabled') {
    $chi_key = 'profile_disabled';
    $filter = sprintf("(&(uid=*)(gidNumber=%s))",
		      $self->{app}->{cfg}->{ldap}->{defaults}->{group}->{blocked}->{gidnumber});
  } elsif ($uid eq 'active') {
    $chi_key = 'profile_active';
    $filter = sprintf("(&(uid=*)(!(gidNumber=%s)))",
		      $self->{app}->{cfg}->{ldap}->{defaults}->{group}->{blocked}->{gidnumber});
  } elsif ($uid ne '') {
    $chi_key = $uid;
    $filter = sprintf("(|(uid=%s)(givenName=%s)(sn=%s))", $uid, $uid, $uid);
  } else {
    $chi_key = 'nokey';
    $filter = sprintf("(uid=%s)", $self->session('uid'));
  }

  $chi = $self->chi('fs')->get($chi_key); #.'tmp-stub-so-killme');
  if ( $chi ) {
    if ($chi->{contextCSN} ge $contextCSN) {
      $self->h_log($chi->{contextCSN});
      $self->h_log($contextCSN);
      $self->stash(
		   contextCSN => $contextCSN,
		   profiled_user => $chi->{profiled_user},
		   groups => $chi->{groups},
		   modifiersname => $chi->{modifiersname},
		   pgp => $chi->{pgp},
		   projects => $chi->{projects},
		   search_base_case => $chi->{search_base_case},
		   server_alive => $chi->{server_alive},
		   servers => $chi->{servers},
		   servers_alive_list => $chi->{servers_alive_list},
		   services => $chi->{services},
		  );
      if ( exists $p->{as_json} && $p->{as_json} eq 'yes' ) {
	return $self->render(json => $chi);
      } else {
	return $self->render(template => $chi_template);
      }
    } else {
      $self->h_log($chi->{contextCSN});
      $self->h_log($contextCSN);
      $self->chi('fs')->remove($chi_key);
    }
  }

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     filter => $filter,
		     scope => 'one' };
  $search_arg->{attrs} = [qw(
			      gidNumber
			      givenName
			      mail
			      modifiersName
			      sn
			      telephoneNumber
			      uid
			      umiUserDateOfBirth
			      umiUserDateOfEmployment
			      umiUserDateOfTermination
			      umiUserIm
			   )]
    if $reqpath =~ /^\/audit\/.*$/;

  # $self->{app}->h_log( $search_arg);
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  my $profiled_user = $search->as_struct;
  # $self->h_log($profiled_user);

  my ( $cf_svc, $groups, $k, $kk, $modifiersname, $pr, $pgp, $pgp_e, $projects, $server_names, $server_alive, $servers_alive_list, $servers, $service, $svc, $svc_details, $svc_msg, $v, $vv, );
  while (($k, $v) = each %$profiled_user) {
    ### name of the last who modified this user root object
    $search_arg = { base => $v->{modifiersname}->[0], scope => 'base', attrs => ['gecos', 'uid'] };
    $search = $ldap->search( $search_arg );
    $modifiersname->{$k} = $search->as_struct->{$v->{modifiersname}->[0]};

    ### only admins and coadmins need this info
    if ( $self->is_role('admin,coadmin,hr', {cmp => 'or'}) || $reqpath eq '/audit/users') {
      ### GROUPS: list of all groups user is a member of
      $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{group},
		      filter => '(memberUid=' . $v->{uid}->[0] . ')',
		      attrs => ['cn'] };
      $search = $ldap->search( $search_arg );
      my $g = $search->as_struct;
      push @{$groups->{$k}}, $vv->{cn}->[0] while (($kk, $vv) = each %$g);

      ### SERVERS: list of all servers available for the user
      $search_arg = { base => 'ou=access,' . $self->{app}->{cfg}->{ldap}->{base}->{netgroup},
		      filter => '(nisNetgroupTriple=*,' . $v->{uid}->[0] . ',*)',
		      attrs => ['nisNetgroupTriple'] };
      $search = $ldap->search( $search_arg );
      $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
      my $netgroups = $search->as_struct;
      my $tuple;
      while (my ($kk, $vv) = each %$netgroups) {
	foreach (@{$vv->{nisnetgrouptriple}}) {
	  @$tuple = split(/,/, substr($_, 1, -1));
	  push @{$server_names->{$k}}, sprintf("%s.%s", $tuple->[0], $tuple->[2]);
	}
      }
      @{$servers->{$k}} = do {
	my %seen;
	sort grep { !$seen{$_}++ } @{$server_names->{$k}};
      };
      foreach (@{$servers->{$k}}) {
	$search_arg = { base => 'cn=' . $_ . ',' . $self->{app}->{cfg}->{ldap}->{base}->{machines},
			attrs => ['cn'] };
	$search = $ldap->search( $search_arg );
	$self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;
	$server_alive->{$k}->{$_} = $search->count;
	$servers_alive_list->{$_} = $search->count;
      }
      # $self->h_log($servers);
    }

    ### SERVICES
    $search_arg = { base => $k,
		    scope => 'one',
		    sizelimit => 0,
		    filter => 'authorizedService=*',
		    attrs => [ 'authorizedService'],};
    $search = $ldap->search( $search_arg );
    $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;

    foreach $svc (@{[$search->sorted( 'authorizedService' )]}) {
      $svc_msg = $ldap->search( { base => $svc->dn, scope => 'children', });
      $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;
      next if ! $svc_msg->count;

      $cf_svc = $self->{app}->{cfg}->{ldap}->{authorizedService}->{(split('@', $svc->get_value('authorizedService')))[0]};

      $svc_details = {
		      branch_dn => $svc->dn,
		      # authorizedService => $svc->get_value('authorizedService'),
		      auth => $cf_svc->{auth},
		      icon => $cf_svc->{icon},
		      descr => $cf_svc->{descr},
		     };

      foreach my $e (@{[$svc_msg->sorted( 'authorizedService' )]}) {
	# !!! WARNING may there be something except `cn` and `uid`?
	# $svc_details->{leaf}->{$e->dn} = $e->get_value('uid') // $e->get_value('cn');
	%{$svc_details->{obj}->{$e->dn}} =
	  map { $_ => $e->get_value($_, asref => 1) } $e->attributes;
      }
      $service->{$k}->{$svc->get_value('authorizedService')} = $svc_details;
      undef $svc_details;
    }
    # $self->h_log($service);

    ### GPG
    $filter = '(|';
    $filter .= sprintf("(pgpUserID=*%s*)", $v->{sn}->[0]);
    $filter .= sprintf("(pgpUserID=*%s*)", $v->{mail}->[0]) if exists $v->{mail};
    $filter .= ')';
    $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{pgp}, filter => $filter };
    $search = $ldap->search( $search_arg );
    $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != 32;
    $pgp_e = $search->as_struct;
    foreach (keys %$pgp_e) {
      $pgp->{$k}->{$pgp_e->{$_}->{pgpuserid}->[0]} =
	{
	 keyid => $pgp_e->{$_}->{pgpkeyid}->[0],
	 key   => $pgp_e->{$_}->{pgpkey}->[0],
	};
    }
    #$self->h_log($pgp);

    ### PROJECTS: list of all projects user is a member of
    $search_arg = { base => 'ou=group,' . $self->{app}->{cfg}->{ldap}->{base}->{project},
		    filter => '(memberUid=' . $v->{uid}->[0] . ')',
		    attrs => ['cn'] };
    $search = $ldap->search( $search_arg );
    $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
    $pr = $search->as_struct;
    @{$projects->{$k}} = sort map { $pr->{$_}->{cn}->[0] =~ s/_/:/r } keys(%$pr);
  }

  $to_chi = {
	     contextCSN => $contextCSN,
	     profiled_user => $profiled_user,
	     groups => $groups,
	     pgp => $pgp,
	     servers => $servers,
	     services => $service,
	     server_alive => $server_alive,
	     servers_alive_list => $servers_alive_list,
	     search_base_case => $self->{app}->{cfg}->{ldap}->{base}->{machines},
	     projects => $projects,
	     modifiersname => $modifiersname,
	    };

  # $self->chi('fs')->set( profile_audit => $to_chi) if $reqpath =~ /^\/audit\/.*$/;
  # $self->chi('fs')->set( profile_all => $to_chi) if $uid eq 'all';
  $self->chi('fs')->set( $chi_key => $to_chi);

  $self->stash(
	       profiled_user => $profiled_user,
	       groups => $groups,
	       pgp => $pgp,
	       servers => $servers,
	       services => $service,
	       server_alive => $server_alive,
	       servers_alive_list => $servers_alive_list,
	       search_base_case => $self->{app}->{cfg}->{ldap}->{base}->{machines},
	       projects => $projects,
	       modifiersname => $modifiersname,
	      );

  if ( exists $p->{as_json} && $p->{as_json} eq 'yes' ) {
    return $self->render(json => $to_chi);
  } else {
    my $template = $reqpath =~ /^\/audit\/.*/ ? 'protected/audit/users' : 'protected/profile';
    # $self->h_log($template);
    return $self->render(template => $template); #layout => undef);
  }
}

=head1 profile_new

create a new user account - profile

=cut

sub profile_new ($self) {
  my $p = $self->req->params->to_hash;
  $self->h_log($p);
  $self->stash(profile_new_params => $p);
  my $upload;
  my $uploads = $self->req->uploads;
  # $self->h_log($uploads);
  if ( @$uploads ) {
    %$upload = map { $_->name => $_ } @$uploads;
  }

  my $v = $self->validation;
  return $self->render(template => 'protected/profile/new') unless $v->has_data;

  my $re_name = qr/^\p{Lu}\p{L}*([-']\p{L}+)*[0-9]*$/;
  my $re_date = qr/^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
  $v->required('givenName')->like($re_name);
  $v->required('sn')->like($re_name);
  $v->required('title');
  $v->required('umiUserDateOfEmployment')->like($re_date);
  ### $v->required('umiUserDateOfBirth')->like($re_date);
  $v->required('l');
  $v->required('umiUserGender');
  $v->required('umiUserCountryOfResidence');

  $v->error(givenName => ['Required, can contain alfanumeric characters and dash, first letter capital']) if $v->error('givenName');
  $v->error(sn => ['Required, can contain alfanumeric characters and dash, first letter capital']) if $v->error('sn');

  my $nf = $self->h_translit(lc $p->{givenName});
  my $nl = $self->h_translit(lc $p->{sn});
  my $nn = sprintf("%s %s", $self->h_translit($p->{givenName}), $self->h_translit($p->{sn}));

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     filter => sprintf("(|(&(givenName=%s)(sn=%s))(uid=%s.%s))",
				       $p->{givenName},
				       $p->{sn},
				       $nf,
				       $nl),
		     scope => "one" };
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  $v->error(givenName => ['User with such first and last names exists']) if $search->count > 0;
  $v->error(sn  => ['User with such first and last names exists']) if $search->count > 0;

  my $phone_numbers;
  if ( exists $p->{telephoneNumber} && $p->{telephoneNumber} ne '' ) {
    $phone_numbers = $self->h_telephonenumber( $p->{telephoneNumber} );
    $v->error(telephoneNumber => [$phone_numbers->{err}]) if exists $phone_numbers->{err} && $phone_numbers->{err} ne '';
  }

  # my $jpegPhoto_error;
  # if ($upload->{jpegPhoto}->size) {
  #   my $sides = $self->h_img_info($upload->{jpegPhoto}->slurp);
  #   if ( $sides->{width} > $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{jpegPhoto}->{max_side} ) {
  #     $jpegPhoto_error .= sprintf('File %s width is %s what is bigger than %s px; ',
  #				  $upload->{jpegPhoto}->filename,
  #				  $sides->{width},
  #				  $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{jpegPhoto}->{max_side});
  #   } elsif ( $sides->{height} > $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{jpegPhoto}->{max_side} ) {
  #     $jpegPhoto_error .= sprintf('File %s height is %s what is bigger than %s px; ',
  #				  $upload->{jpegPhoto}->filename,
  #				  $sides->{height},
  #				  $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{jpegPhoto}->{max_side});
  #   }
  # }
  # $jpegPhoto_error .= sprintf('File %s is bigget than %s bytes.',
  #			      $upload->{jpegPhoto}->filename,
  #			      $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{jpegPhoto}->{max_size})
  #   if $upload->{jpegPhoto}->size > $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{jpegPhoto}->{max_size};
  # $v->error( jpegPhoto => [ $jpegPhoto_error ] ) if defined $jpegPhoto_error;

  if ( ! $v->has_error ) {
    my $attrs = {
		 cn        => $nn,
		 gecos     => $nn,
		 gidNumber => $self->{app}->{cfg}->{ldap}->{defaults}->{attr}->{gidNumber}->{onboarding},
		 givenName => $p->{givenName},
		 l         => $p->{l},
		 homeDirectory => sprintf("/usr/local/home/%s.%s", $nf, $nl),
		 objectClass   => $self->{app}->{cfg}->{ldap}->{objectClass}->{acc_root},
		 umiUserGender => $p->{umiUserGender},
		 sn            => $p->{sn},
		 title         => $p->{title},
		 uid           => sprintf("%s.%s", $nf, $nl),
		 umiUserCountryOfResidence => $p->{umiUserCountryOfResidence},
		 umiUserDateOfEmployment   => $self->h_ts_to_generalizedTime($p->{umiUserDateOfEmployment}),
		 umiUserDateOfBirth        => $self->h_ts_to_generalizedTime($p->{umiUserDateOfBirth}),
		};

    # $attrs->{jpegPhoto} = $upload->{jpegPhoto}->slurp if $upload->{jpegPhoto}->size > 0;
    $attrs->{jpegPhoto} = $self->h_img_resize( $upload->{jpegPhoto}->slurp ) if $upload->{jpegPhoto}->size > 0;
    @{$attrs->{telephoneNumber}} = @{$phone_numbers->{num}} if exists $phone_numbers->{num} && @{$phone_numbers->{num}};

    if ( exists $p->{umiUserIm} && $p->{umiUserIm} ne '' ) {
      my @im = split /\s*,\s*/, $p->{umiUserIm};
      @im = map { s/[\s]+//gr } @im;
      my %t;
      $t{$_} = 1 foreach (@im);
      @im = keys %t;
      @{$attrs->{umiUserIm}} = @im if @im;
    }


    my $u = $ldap->last_num;
    if ( $u->[1] ) {
      $self->h_log($u->[1]);
      $attrs->{uidNumber} = undef;
    } else {
      $attrs->{uidNumber} = $u->[0] + 1;
    }

    # $self->h_log($attrs);

    my $msg = $ldap->add(sprintf("uid=%s.%s,%s",
				 $nf,
				 $nl,
				 $self->{app}->{cfg}->{ldap}->{base}->{acc_root}),
			 $attrs);
    $self->stash(debug => {$msg->{status} => [ $msg->{message} ]});
  }

  $self->render(template => 'protected/profile/new');
}

=head1 profile_modify

modification of profile

=cut

sub profile_modify ($self) {
  my $from_form = $self->req->params->to_hash;
  # $self->h_log($from_form);
  $self->h_compact($from_form);
  $self->h_log($from_form);

  if (
      ! exists $from_form->{uid_to_modify} &&
      ( ! defined $self->stash('uid') || $self->stash('uid') eq '' )
      ) {
    return $self->render(template => 'protected/home');
  }

  my $attrs = [qw(
		   givenName
		   jpegPhoto
		   l
		   sn
		   telephoneNumber
		   title
		   umiUserCountryOfResidence
		   umiUserDateOfBirth
		   umiUserDateOfEmployment
		   umiUserDateOfTermination
		   umiUserGender
		   umiUserIm
		)];

  my $uid = $self->stash('uid') // $from_form->{uid_to_modify} // '';
  ###$from_form->{uid_to_modify} = $self->stash->{uid} if exists $self->stash->{uid};
  $from_form->{uid_to_modify} = $uid;
  $self->stash(uid_to_modify => $uid);

  my $ldap = Umi::Ldap->new($self->{app}, $self->session('uid'), $self->session('pwd'));
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     filter => '(uid=' . $uid .')',
		     scope => 'one',
		     attrs => $attrs, };
  # $self->h_log($search_arg);
  my $search = $ldap->search( $search_arg );
  $self->{app}->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  my ($from_ldap, $dn, $e);
  if ($search->count) {
    $e = $search->entry;
    %$from_ldap = map {
      if ( $_ eq 'mail' || $_ eq 'jpegPhoto' ) {
	$_ => $e->get_value($_);
      } elsif ( $_ eq 'telephoneNumber' || $_ eq 'umiUserIm' ) {
	#############################################################################
	# telephoneNumber and umiUserIm attributes values are treated as array refs #
	#############################################################################
	$_ => $e->get_value($_, asref => 1);
      } else {
	# deprecated $_ => utf8::is_utf8($e->get_value($_)) ? $e->get_value($_) : decode_utf8($e->get_value($_));
	$_ => $self->h_decode_text($e->get_value($_));
      }
    } $e->attributes;
    $dn = $e->dn;
  }

  # $self->h_log($from_ldap);
  # $self->h_log($from_form);
  $self->stash(from_ldap => $from_ldap);

  $from_form->{telephoneNumber} = $self->h_telephonenumber($from_form->{telephoneNumber})->{num}
    if exists $from_form->{telephoneNumber} && $from_form->{telephoneNumber} ne '';

  if ( exists $from_form->{umiUserIm} && $from_form->{umiUserIm} ne '' ) {
    my @im = split /\s*,\s*/, $from_form->{umiUserIm};
    @im = map { s/[\s]+//gr } @im;
    my %t;
    $t{$_} = 1 foreach (@im);
    @im = keys %t;
    $from_form->{umiUserIm} = \@im if @im;
  }

  $self->stash(from_form => $from_form);

  my $v = $self->validation;
  # return $self->render(template => 'protected/profile/modify') unless $v->has_data;

  ###############################
  # data population to the form #
  ###############################
  unless (keys %$from_form > 1) {
    foreach (@$attrs) {
      next if $_ eq 'jpegPhoto';
      if ( $_ eq 'telephoneNumber' || $_ eq 'umiUserIm' ) {
	###############################################################
	# telephoneNumber and umiUserIm attributes values are stings, #
	# form field assumes comma delimited string		      #
	###############################################################
	$self->req->params->merge( $_ => join(', ', @{$from_ldap->{$_}}) )
	  if exists $from_ldap->{$_};
      } elsif ( $_ eq 'umiUserDateOfBirth' || $_ eq 'umiUserDateOfEmployment' || $_ eq 'umiUserDateOfTermination' ) {
	###################################################
	# attribute value to form field conversion	  #
	###################################################
	$self->req->params->merge( $_ => strftime '%Y-%m-%d', localtime(generalizedTime_to_time($from_ldap->{$_})) )
	  if exists $from_ldap->{$_};
      } else {
	$self->req->params->merge( $_ => $from_ldap->{$_} ) if $e->exists($_);
      }
    }
    $self->req->params->merge( uid_to_modify => $uid );
    return $self->render(template => 'protected/profile/new');
  }

  my $upload;
  my $uploads = $self->req->uploads;
  # $self->h_log($uploads);
  if ( @$uploads ) {
    %$upload = map { $_->name => $_ } @$uploads;
  }

  my $re_name = qr/^\p{Lu}\p{L}*([-']\p{L}+)*[0-9]*$/;
  my $re_date = qr/^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
  $v->required('givenName')->like($re_name);
  $v->required('sn')->like($re_name);
  $v->required('title');
  $v->required('umiUserDateOfEmployment')->like($re_date);
  ### $v->required('umiUserDateOfBirth')->like($re_date);
  $v->required('umiUserGender');
  $v->required('l');
  $v->required('umiUserCountryOfResidence');
  $v->error( givenName => ['UTF-8 and - characters only'] ) if $v->error('givenName');
  $v->error( sn        => ['UTF-8 and - characters only'] ) if $v->error('sn');
  $v->error( title     => ['UTF-8 and - characters only'] ) if $v->error('title');

  if ( ! $v->has_error ) {
    # $self->h_log($from_form);
    $from_form->{jpegPhoto} = $upload->{jpegPhoto}->slurp if $upload->{jpegPhoto}->size > 0;

    my ($tmp_k, $tmp_v) = ('uid_to_modify', $from_form->{uid_to_modify});

    my %l = %$from_ldap;
    delete $l{jpegPhoto} if exists $l{jpegPhoto};
    my %f = %$from_form;
    delete $f{jpegPhoto} if exists $f{jpegPhoto};
    delete $f{uid_to_modify};

    $f{umiUserDateOfBirth} = $self->h_ts_to_generalizedTime($f{umiUserDateOfBirth})
      if exists $f{umiUserDateOfBirth} && $f{umiUserDateOfBirth} ne '';
    $f{umiUserDateOfEmployment} = $self->h_ts_to_generalizedTime($f{umiUserDateOfEmployment})
      if exists $f{umiUserDateOfEmployment} && $f{umiUserDateOfEmployment} ne '';
    $f{umiUserDateOfTermination} = $self->h_ts_to_generalizedTime($f{umiUserDateOfTermination})
      if exists $f{umiUserDateOfTermination} && $f{umiUserDateOfTermination} ne '';

    ############################################################
    # telephoneNumber and umiUserIm attributes values are      #
    # treated as array refs, so diif should be done separately #
    ############################################################
    my ($l_tel, $f_tel, $diff_tel, $l_im, $f_im, $diff_im);
    if ( exists $l{telephoneNumber} && exists $f{telephoneNumber} ) {
      $l_tel = delete $l{telephoneNumber};
      $f_tel = delete $f{telephoneNumber};
      $diff_tel = $self->h_array_diff($l_tel, $f_tel);
      #$self->h_log($diff_tel);
    }
    if ( exists $l{umiUserIm} && exists $f{umiUserIm} ) {
      $l_im = delete $l{umiUserIm};
      $f_im = delete $f{umiUserIm};
      $diff_im = $self->h_array_diff($l_im, $f_im);
      #$self->h_log($diff_im);
    }

    my $diff = $self->h_hash_diff( \%l, \%f);
    # $self->h_log($diff);
    # $self->h_log([keys(%l)]);
    # $self->h_log([keys(%f)]);

    my ($add, $delete, $replace, $changes);

    push @$add,     jpegPhoto => $self->h_img_resize( $upload->{jpegPhoto}->slurp, $upload->{jpegPhoto}->size )
      if ! exists $from_ldap->{jpegPhoto} && exists $upload->{jpegPhoto} && $upload->{jpegPhoto}->size > 0;

    push @$replace, jpegPhoto => $self->h_img_resize( $upload->{jpegPhoto}->slurp, $upload->{jpegPhoto}->size )
      if exists $from_ldap->{jpegPhoto} && exists $upload->{jpegPhoto} && $upload->{jpegPhoto}->size > 0;

    if ( %{$diff->{added}} ) {
      push @$add, $_ => $diff->{added}->{$_} foreach (keys(%{$diff->{added}}));
    }
    push @$add, telephoneNumber => $diff_tel->{added} if defined $diff_tel && exists $diff_tel->{added} && @{$diff_tel->{added}};
    push @$add, umiUserIm => $diff_im->{added} if defined $diff_im && exists $diff_im->{added} && @{$diff_im->{added}};

    if ( %{$diff->{removed}} ) {
      push @$delete, $_ => [] foreach (keys(%{$diff->{removed}}));
    }
    push @$delete, telephoneNumber => $diff_tel->{removed} if defined $diff_tel && exists $diff_tel->{removed} && @{$diff_tel->{added}};
    push @$delete, umiUserIm => $diff_im->{removed} if defined $diff_im && exists $diff_im->{removed} && @{$diff_im->{added}};

    if ( %{$diff->{changed}} ) {
      push @$replace, $_ => $diff->{changed}->{$_}->{new} foreach (keys(%{$diff->{changed}}));
    }
    push @$changes, add => $add         if $add;
    push @$changes, delete => $delete   if $delete;
    push @$changes, replace => $replace if $replace;

    $self->h_log($changes);
    $from_form->{$tmp_k} = $tmp_v;
    $self->stash(from_form => $from_form);

    if ( $changes ) {
      my $msg = $ldap->modify($dn, $changes);
      $self->stash(debug => {$msg->{status} => [ $msg->{message} ]});
    }
  }

  $self->render(template => 'protected/profile/new'); #, layout => undef);
}

=head1 project_new

creation of a new project

=cut

sub project_new ($self) {
  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my ($search, $search_arg, $debug);
  my ($employees, $err) = $ldap->all_users;

  my $par = $self->req->params->to_hash;
  $self->h_log($par);
  $self->stash(project_new_params => $par, employees => $employees);

  my $v = $self->validation;
  return $self->render(template => 'protected/project/new') unless $v->has_data;

  $v->required('cn')->check('size', 2, 50)->check('like', qr/^[A-Za-z0-9.-_]+$/);
  $v->error( cn   => ['Must be 2-50 charaters in length and can be only ASCII characters: A-Za-z0-9.-_'] )
    if $v->error('cn');
  # looks like some projects can be empty
  # $v->required('team_pm');
  # $v->required('team_back');
  # $v->required('team_front');
  # $v->required('team_devops');
  # $v->required('team_qa');
  # $v->error( team_pm     => ['Select at least one member.']) if $v->error('team_pm');
  # $v->error( team_back   => ['Select at least one member.']) if $v->error('team_back');
  # $v->error( team_front  => ['Select at least one member.']) if $v->error('team_front');
  # $v->error( team_devops => ['Select at least one member.']) if $v->error('team_devops');
  # $v->error( team_qa    => ['Select at least one mamber.'])                 if $v->error('team_qa');

  # $self->h_log($v->error);

  if ( ! $v->has_error ) {
    $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{project},
		    filter => "(cn=" . $par->{cn} . ")",
		    scope => "one",
		    attrs => ['cn'] };
    $search = $ldap->search( $search_arg );
    $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;
    $v->error(cn => ['Project with such name exists']) if $search->count > 0;

    my $attrs =
      {
       objectClass => $self->{app}->{cfg}->{ldap}->{objectClass}->{project},
       cn => lc $par->{cn},
       description => $par->{description} ne '' ? $par->{description} : 'no description',
       #------------------------------------------------------------------------------
       # attribute associatedDomain is set by admins after project object is creation
       #------------------------------------------------------------------------------
       associatedDomain => 'unknown'
      };
    $self->h_log($attrs);

    my $p_dn = sprintf("cn=%s,%s", lc $par->{cn}, $self->{app}->{cfg}->{ldap}->{base}->{project});
    my $msg = $ldap->add( $p_dn, $attrs );
    push @{$debug->{$msg->{status}}}, $msg->{message};

    if ( ! exists $msg->{error} ) {
      ###################################################
      # creating all, even empty, project teams groups  #
      ###################################################
      foreach my $g (keys %{$self->{app}->{cfg}->{ui}->{project}->{team}->{roles}}) {
	my $g_rdn = sprintf("%s_%s", lc $par->{cn}, $g);
	my $g_dn = sprintf("cn=%s,%s", $g_rdn, $self->{app}->{cfg}->{ldap}->{base}->{project_groups});
	$search_arg = { base => $g_dn, score => 'base' };
	$search = $ldap->search( $search_arg );
	$self->h_log( $self->h_ldap_err($search, $search_arg) )
	  if $search->code != LDAP_NO_SUCH_OBJECT;

	if ( $search->count > 0  ) {
	  push @{$debug->{warn}}, $g_dn . ' exists';
	} else {
	  $attrs = {
		    objectClass => $self->{app}->{cfg}->{ldap}->{objectClass}->{project_groups},
		    cn => $g_rdn,
		   };

	  $attrs->{memberUid} = $par->{$g}
	    if $self->h_is_meaningful_arrayref($g) || $par->{$g} ne '';

	  my $gn = $ldap->last_num($self->{app}->{cfg}->{ldap}->{base}->{project_groups}, '(cn=*)', 'gidNumber');
	  if ( $gn->[1] ) {
	    $self->h_log($gn->[1]);
	    $attrs->{gidNumber} = undef;
	  } else {
	    $attrs->{gidNumber} = $gn->[0] + 1;
	  }
	  # $self->h_log($attrs);

	  $msg = $ldap->add( $g_dn, $attrs);
	  push @{$debug->{$msg->{status}}}, $msg->{message};
	}
      }
    }
    $self->stash(debug => $debug);
  }
  $self->render(template => 'protected/project/new'); #, layout => undef);
}

=head1 project_modify

modification of project

=cut

sub project_modify ($self) {
  my $from_form = $self->req->params->to_hash;
  my $debug;
  $self->h_log($from_form);

  if (
      ! exists $from_form->{proj_to_modify} &&
      ( ! defined $self->stash('proj') || $self->stash('proj') eq '' )
     ) {
    $self->h_log($from_form);
    return $self->render(template => 'protected/home');
  }

  my $proj = $self->stash->{proj} // $from_form->{proj_to_modify};
  $from_form->{proj_to_modify} = $proj;
  $self->stash(proj_to_modify => $proj);

  my $ldap = Umi::Ldap->new($self->{app}, $self->session('uid'), $self->session('pwd'));

  ### PROJECT OBJECT
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{project},
		     filter => '(cn=' . $proj .')',
		     scope => 'one',
		     attrs => [qw(cn description)]};
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  my $from_ldap;
  if ($search->count) {
    %{$from_ldap->{proj}->{obj}} =
      map {
	$_ => ref($search->entry->get_value($_)) eq 'ARRAY'
	  ? [$search->entry->get_value($_)]
	  : $search->entry->get_value($_)
	}
      $search->entry->attributes;
    $from_ldap->{proj}->{dn} = $search->entry->dn;
  }

  ### PROJECT GROUPS
  $from_ldap->{groups} = {};
  $search_arg = { base => 'ou=group,' . $self->{app}->{cfg}->{ldap}->{base}->{project},
		  filter => '(cn=' . $proj . '*)', };
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code;
  foreach ($search->entries) {
    $from_ldap->{groups}->{$_->get_value('cn')} =
      $_->exists('memberUid') ? $_->get_value('memberUid', asref => 1) : [];
  }

  ### EMPLOYEES:TEAM MEMBERS SELECT ELEMENTS
  my ($employees, $err) = $ldap->all_users;
  push @{$debug->{$err->{status}}}, $err->{message} if defined $err;
  undef $err;
  $self->stash( debug => $debug, employees => $employees );
  #$self->h_log($employees);

  ### REST

  $self->h_log($from_ldap, 'from_ldap');
  $self->stash(from_ldap => $from_ldap);

  $self->h_log($from_form, 'from_form');
  $self->stash(from_form => $from_form);

  $self->stash( proj => $self->stash->{proj},
		from_ldap => $self->stash->{from_ldap},
		project_team_roles => [ keys %{$self->{app}->{cfg}->{ui}->{project}->{team}->{roles}} ] );

  #############################################
  # data population to html form on first run #
  #############################################
  unless (keys %$from_form > 1) {
    $self->req->params->merge( cn => $from_ldap->{proj}->{obj}->{cn} );
    $self->req->params->merge( description => $from_ldap->{proj}->{obj}->{description});
    ##########################################################################
    # group name notation is PROJNAME_TEAMNAME, html form uses only TEAMNAME #
    ##########################################################################
    foreach (keys %{$from_ldap->{groups}}) {
      $self->req->params->merge( substr($_, length($proj) + 1)
				 =>
				 $from_ldap->{groups}->{$_} )
	if $self->h_is_meaningful_arrayref($from_ldap->{groups}->{$_});
    }

    return $self->render(template => 'protected/project/new');
  }

  my $re = qr/^[a-z0-9_.\-]+$/;
  my $v = $self->validation;
  $v->required('cn')->size(1, 50)->like($re);

  #############################
  # processing project object #
  #############################
  my ($msg, $diff, $add, $delete, $replace, $changes, $chg);
  $diff = $self->h_hash_diff( $from_ldap->{proj}->{obj},
			      { cn => $from_form->{cn},
				description => $from_form->{description} } );
  #$self->h_log($diff);
  if ( %{$diff->{added}} ) {
    push @$add, $_ => $diff->{added}->{$_} foreach (keys(%{$diff->{added}}));
    push @$changes, add => $add;
  }
  if ( %{$diff->{removed}} ) {
    push @$delete, $_ => [] foreach (keys(%{$diff->{removed}}));
    push @$changes, delete => $delete;
  }
  if ( %{$diff->{changed}} ) {
    push @$replace, $_ => $diff->{changed}->{$_}->{new}
      foreach (keys(%{$diff->{changed}}));
    push @$changes, replace => $replace;
  }

  if (defined $changes) {
    $msg = $ldap->modify($from_ldap->{proj}->{dn}, $changes);
    ### !!! to push to debug_message rather than overwrite
    push @{$debug->{$msg->{status}}}, $msg->{message};
    $chg->{proj} = $changes;
  }
  $diff = $add = $delete = $replace = $changes = undef;

  #####################################
  # processing project groups objects #
  #####################################
  foreach my $team_role (keys %{$self->{app}->{cfg}->{ui}->{project}->{team}->{roles}} ) {
    my $f = $from_form->{$team_role} if exists $from_form->{$team_role};
    my $lgn = $from_ldap->{proj}->{obj}->{cn} . '_' . $team_role;
    my $l = $from_ldap->{groups}->{$lgn} if exists $from_ldap->{groups}->{$lgn};
    # $self->h_log($l, "from_ldap->{groups}->{$lgn}");
    # $self->h_log($f, "from_form->{$team_role}");

    if ( (! defined $f && ! defined $l)
	 || (! defined $f && ! $self->h_is_meaningful_arrayref($l)) ) {
      # this is redundant since we create groups (even empty) for each role
      next;
    } elsif ( ! defined $f && defined $l && $self->h_is_meaningful_arrayref($l) ) {
      push @$changes, delete => [memberUid => []];
    } elsif ( defined $f && ! defined $l ) {
      push @$changes, add =>
	[ memberUid => ref($f) ne 'ARRAY' ? [ $f ] : $f ];
    } else {
      # $self->h_log($l); $self->h_log($f);
      $diff = $self->h_array_diff( $l, ref($f) ne 'ARRAY' ? [$f] : $f );
      # $self->h_log($diff);
      if ( scalar @{$diff->{added}} > 0 ) {
	push @$add, memberUid => $diff->{added};
	push @$changes, add => $add;
      }
      if ( scalar @{$diff->{removed}} > 0 ) {
	push @$delete, memberUid => [];
	push @$changes, delete => $delete;
      }
    }

    if (defined $changes) {
      $msg = $ldap->modify('cn=' . $lgn . ','
			   . $self->{app}->{cfg}->{ldap}->{base}->{project_groups},
			   $changes);
      ### !!! to push to debug_message rather than overwrite
      push @{$debug->{$msg->{status}}}, $msg->{message};
      $chg->{group}->{$team_role} = $changes if defined $changes;;
    }
    $diff = $add = $delete = $replace = $changes = undef;
  }
  $self->h_log($chg);

  $self->render(template => 'protected/project/new', debug => $debug); # , layout => undef);
}

# before Helper::Dnssub resolve ($self) {
# before Helper::Dns  my $p = $self->req->params->to_hash;
# before Helper::Dns  $self->h_log($p);
# before Helper::Dns
# before Helper::Dns  my $a = { query => { A   => $p->{a}   // '',
# before Helper::Dns		       PTR => $p->{ptr} // '',
# before Helper::Dns		       MX  => $p->{mx}  // '', }, };
# before Helper::Dns
# before Helper::Dns  my $res;
# before Helper::Dns  while ( my($k, $v) = each %{$a->{query}} ) {
# before Helper::Dns    next if $v eq '';
# before Helper::Dns    $res = ref($v) eq 'ARRAY' ? $v : [ $v ];
# before Helper::Dns
# before Helper::Dns    push @{$a->{reply}}, $self->h_dns_resolver({ type  => $k,
# before Helper::Dns						 debug => 0,
# before Helper::Dns						 name  => $_ })
# before Helper::Dns      foreach (@{$res});
# before Helper::Dns  }
# before Helper::Dns
# before Helper::Dns  foreach (@{$a->{reply}}) {
# before Helper::Dns    push @{$a->{body}}, $_->{success}         if exists $_->{success};
# before Helper::Dns    push @{$a->{body}}, $_->{error}->{errstr} if exists $_->{error};
# before Helper::Dns  }
# before Helper::Dns
# before Helper::Dns  # $self->h_log($_) foreach (@{$a->{body}});
# before Helper::Dns
# before Helper::Dns  $self->render( #template => 'protected/tool/resolv',
# before Helper::Dns		 layout => undef,
# before Helper::Dns		 text => join("\n", @{$a->{body}}) // '' );
# before Helper::Dns}

sub resolve ($self) {
  my $p = $self->req->params->to_hash;
  $self->h_log($p);

  my $q = $self->h_dns_rr({
			   fqdn => $p->{name},
			   type => $p->{type}
			  });
  $self->h_log($q);
  my @r;
  @r = map { $_->{rdstring} } @{$q->{success}} if exists $q->{success};
  push @r, $q->{error}->{errstr}     if exists $q->{error} && $q->{error}->{errstr} ne 'NOERROR';

  $self->render( #template => 'protected/tool/resolv',
		 layout => undef,
		 text => join("\n", @r) // '' );
}

=head1 moddn

Rename the entry given by "DN" on the server.

=cut

sub moddn ($self) {

  my $par = $self->req->params->to_hash;
  # $self->h_log($par);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my $msg = $ldap->moddn($par);
  $self->session( debug => $msg );

  ### alas, this redirect by nature performs a GET request
  return $self
    ->redirect_to($self->url_for('search_common')
		  ->query( search_base_case => $par->{search_base_case},
			   search_filter => $par->{search_filter},
			   ldap_subtree => $par->{ldap_subtree} )
		 );
}

sub groups ($self) {
  my $p = $self->req->params->to_hash;
  $self->h_log($p);

  return $self->render(template => 'protected/home') unless exists $p->{dn_to_group};

  if ( exists $p->{group} ) {
    $p->{group} = ref($p->{group}) eq 'ARRAY' ? $p->{group} : [ $p->{group} ];
  }
  $self->h_log($self->h_get_rdn_val($p->{dn_to_group}));
  $self->stash( dn_to_group => $p->{dn_to_group} );

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  #--- BEFORE SUBMIT start --------------------------------------
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{group},
		     filter => '(memberUid=' . $self->h_get_rdn_val($p->{dn_to_group}) .')',};
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  my %u = map { $_->get_value('cn') => 1 } $search->entries;

  $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{group}, scope => 'one' };
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;
  my @group_names = $search->sorted('cn');

  my @e = map {
    exists $u{$_->get_value('cn')} ?
      [ $_->get_value('cn') => $_->get_value('cn'), selected => 'selected'] :
      $_->get_value('cn')
    } @group_names;

  my @o = keys(%u);
  my $diff = $self->h_array_diff(\@o,$p->{group});
  $self->h_log($diff);
  #--- BEFORE SUBMIT stop ---------------------------------------

  my ($debug, $msg);
  #if ( exists $p->{group} ) {
    foreach (@{$diff->{added}}) {
      $msg = $ldap->modify( sprintf('cn=%s,%s',$_, $self->{app}->{cfg}->{ldap}->{base}->{group}),
			    [ add => [ memberUid => $self->h_get_rdn_val($p->{dn_to_group}) ]] );
      $self->h_log( $msg->{message} ) if $msg->{status} eq 'error';
      push @{$debug->{$msg->{status}}}, $msg->{message};
    }
    foreach (@{$diff->{removed}}) {
      $msg = $ldap->modify( sprintf('cn=%s,%s',$_, $self->{app}->{cfg}->{ldap}->{base}->{group}),
			    [ delete => [ memberUid => $self->h_get_rdn_val($p->{dn_to_group}) ]] );
      $self->h_log( $msg->{message} ) if $msg->{status} eq 'error';
      push @{$debug->{$msg->{status}}}, $msg->{message};
    }
  #}

  #--- AFTER SUBMIT start --------------------------------------
  $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{group},
		  filter => '(memberUid=' . $self->h_get_rdn_val($p->{dn_to_group}) .')',};
  $search = $ldap->search( $search_arg );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  %u = map { $_->get_value('cn') => 1 } $search->entries;

  @e = map {
    exists $u{$_->get_value('cn')} ?
      [ $_->get_value('cn') => $_->get_value('cn'), selected => 'selected'] :
      $_->get_value('cn')
    } @group_names;

  #--- AFTER SUBMIT stop ---------------------------------------

  $self->stash( select_options => \@e, debug => $debug );
  $self->render(template => 'protected/profile/groups');
}

=head1 onboarding

structure of svc_details

    $svc_details = {
      $service_name => {
	exists => 0 | 1,   # whether the service entry already existed (1) or was newly created (0)
	added  => [        # present only if exists == 0 and new entries were added
	  {
	    fqdn        => $fqdn,          # fully qualified domain name (associatedDomain)
	    svc_details => {
	      uid          => $uid,        # login name generated or supplied
	      userPassword => $cleartext,  # cleartext password, if generated (or cert CN, if cert-based)
	      # more fields may appear in future if svc_details is expanded
	    },
	  },
	  ...
	],
      },
      ...
    };

=cut

sub onboarding ($self) {
  my $p = $self->req->params->to_hash;
  $self->h_log($p);
  $self->stash( dn_to_onboard => $p->{dn_to_onboard} );

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my $search_arg = { base => $p->{dn_to_onboard}, scope => 'base', };
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;
  my $root = $search->entry;

  my $v = $self->validation;

  my (%debug, $service);
  my $svcs = $self->{app}->{cfg}->{ui}->{onboarding}->{services};
  # $self->h_log($svcs);

  ###########################################
  # what services user does have or doesn't #
  ###########################################
  foreach my $svc (keys %$svcs) {
    foreach my $d (@{$svcs->{$svc}->{fqdn}}) {
      $search_arg = { base => sprintf('authorizedService=%s@%s,%s', $svcs->{$svc}->{svc}, $d, $self->session->{user_obj}->{dn}),
		      scope => 'one' };
      # $self->h_log($search_arg);
      $search = $ldap->search( $search_arg );
      $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code && $search->code != LDAP_NO_SUCH_OBJECT;
      if ($search->code && $search->code == LDAP_NO_SUCH_OBJECT) {
	$service->{$svc}->{exists} = 0;
	push @{$debug{ok}}, sprintf("You don't have account for service <mark>%s</mark>, will be created", $svc)
	  if ! $v->has_data;
      } else {
	foreach my $e ($search->entries) {
	  $service->{$svc}->{exists} = 1;
	  push @{$service->{$svc}->{acc}}, $e;
	  push @{$debug{warn}}, sprintf("Service <mark>%s</mark> account, login: <mark>%s</mark>, exists (created on %s)",
					$svc, $e->get_value('uid'), $e->get_value('createTimestamp'))
	    if ! $v->has_data;
	}
      }
    }
  }
  # $self->h_log($service);

  $self->stash( debug => \%debug );

  # On GET (not POST), render the form and stop here
  return $self->render(template => 'protected/profile/onboarding') unless $v->has_data;

  $self->stash( is_submited => 1 );

  ########################
  # Generate SSH keypair #
  ########################
  my $k_ssh = $self->h_keygen_ssh;
  # $self->stash(debug => $k_ssh->{debug});
  # $self->h_log($k_ssh);
  # $self->h_log(\%debug);

  my ($svc_details, $br, $s);
  my $dry_run = 0;

  my (%to_enc, $op_dn, $mesg, $op_attrs);
  foreach my $svc (keys %$service) {
    # next if $service->{$svc}->{exists} == 1;

    $p->{authorizedService} = $svcs->{$svc}->{svc};
    $p->{sshKeyText} = $k_ssh->{public} if $svc eq 'ssh-acc';

    foreach my $d (@{$svcs->{$svc}->{fqdn}}) {
      $p->{associatedDomain} = $d;
      if ( $service->{$svc}->{exists} == 0 ) {
	$br = $self->h_branch_add_if_not_exists($p, $ldap, $root, \%debug, $dry_run);
	$s = $self->h_service_add_if_not_exists($p, $ldap, $root, $br, \%debug, $dry_run);
	push @{$svc_details->{$svc}->{added}}, { fqdn => $d, svc_details => $s->{svc_details} };
	$to_enc{ 'svc_' . $svc . $d . $s->{svc_details}->{uid} } = $s->{svc_details}->{userPassword};
      } elsif ( $svc eq 'ssh-acc' ) {
	$op_dn = sprintf('uid=%s,authorizedService=%s@%s,%s',
			 lc(sprintf("%s.%s", $self->session->{user_obj}->{givenname}, $self->session->{user_obj}->{sn})),
			 $svc,
			 $d,
			 $self->session->{user_obj}->{dn});
	$op_attrs = [ add => [ sshPublicKey => $k_ssh->{public} ] ];
	#$self->h_log($add_dn);
	#$self->h_log($add_attrs);
	$mesg = $ldap->modify( $op_dn, $op_attrs );
	push @{$debug{$mesg->{status}}}, $mesg->{message};
      }
    }

    $svc_details->{$svc}->{exists} = $service->{$svc}->{exists} == 1 ? 1 : 0;
  }

  my $root_pwd = $self->h_pwdgen;
  $to_enc{root} = $root_pwd->{clear};
  $mesg = $ldap->modify( $self->session->{user_obj}->{dn},
			 [ replace => [ userPassword => $root_pwd->{ssha} ] ] );
  push @{$debug{$mesg->{status}}}, $mesg->{message};

  ##################################################
  # Generate GPG keypair and uload GPG key to LDAP #
  ##################################################
  my $k_gpg = $self->h_keygen_gpg({ name => {
					     real  => sprintf("%s %s",
							      $self->session->{user_obj}->{givenname},
							      $self->session->{user_obj}->{sn}) // "name is absent",
					     email => $self->session->{user_obj}->{mail} // "mail is absent"
					    },
				    to_enc => \%to_enc
				  });
  # $self->stash(debug => $k_gpg->{debug});

  if ( $dry_run == 0 && exists $k_gpg->{send_key} ) {
    $op_dn = sprintf("pgpCertID=%s,%s",
		     $k_gpg->{send_key}->{pgpCertID},
		     $self->{app}->{cfg}->{ldap}->{base}->{pgp});
    %{$op_attrs} = map { $_ => $k_gpg->{send_key}->{$_} } keys %{$k_gpg->{send_key}};
    #$self->h_log($add_dn);
    #$self->h_log($add_attrs);
    $mesg = $ldap->add( $op_dn, $op_attrs );
    push @{$debug{$mesg->{status}}}, $mesg->{message};
  }

  delete $debug{ok};
  delete $service->{$_}->{acc} foreach (keys %$service);

  $self->stash( debug => \%debug,
		root_pwd => $root_pwd->{clear},
		svc_added => $svc_details,
		k_gpg => $k_gpg,
		k_ssh => $k_ssh );

  $self->render(template => 'protected/profile/onboarding');
}

sub sargon ($self) {
  my (%debug, $p);
  $p = $self->req->params->to_hash;
  $self->h_log($p);
  foreach (keys %$p) {
     if ( $p->{$_} eq '' ) {
       delete $p->{$_};
     } elsif (ref($p->{$_}) eq 'ARRAY') {
       @{$p->{$_}} = grep { $_ ne "" } @{$p->{$_}};
     }
  }
  $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my %schema_all_attributes = map { $_->{name} => $_ } $ldap->schema->all_attributes;

  my ($sargonUser, $groups, $sargonHost, $err);
  ($sargonUser, $err) = $ldap->all_users;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;
  ($groups, $err) = $ldap->all_groups;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;
  ($sargonHost, $err) = $ldap->all_hosts;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;

  $p->{sargonMount} = [$p->{sargonMount}] if exists $p->{sargonMount} && ref($p->{sargonMount}) ne 'ARRAY';
  $p->{sargonMount} = [''] if ! exists $p->{sargonMount};

  $self->stash(
	       sargonUser => $sargonUser,
	       groups => $groups,
	       sargonHost => $sargonHost,
	       sargonMount => $p->{sargonMount},
	       schema => \%schema_all_attributes,
	       debug => \%debug,
	      );

  my $v = $self->validation;
  return $self->render(template => 'protected/sargon/new') unless $v->has_data;

  my $re_cn = qr/^[[:alnum:]_-]+$/;
  $v->required('cn')->like($re_cn);
  $v->error( cn => ['ASCII alnum, - and _ characters only'] ) if $v->error('cn');

  if ( ! $v->has_error ) {
    my $attrs;
    $attrs->{$_} = $p->{$_} foreach keys %$p;
    $attrs->{objectClass} = $self->{app}->{cfg}->{ldap}->{objectClass}->{sargon};

    if ( exists $attrs->{groups} ) {
      my @g = map { '+'.$_ } @{$attrs->{groups}};
      $attrs->{sargonUser} = [ @{$attrs->{sargonUser}}, @g ];
      delete $attrs->{groups};
    }
    if ( exists $attrs->{sargonAllowPrivileged} ) {
      $attrs->{sargonAllowPrivileged} = $attrs->{sargonAllowPrivileged} eq 'on' ? 'TRUE' : 'FALSE';
    }
    $attrs->{sargonNotBefore} .= 'Z' if exists $attrs->{sargonNotBefore};
    $attrs->{sargonNotAfter} .= 'Z' if exists $attrs->{sargonNotAfter};
    $self->h_log($attrs);

    my $msg = $ldap->add(sprintf("cn=%s,%s", $attrs->{cn}, $self->{app}->{cfg}->{ldap}->{base}->{sargon}),
			 $attrs);
    push @{$debug{$msg->{status}}}, $msg->{message};
  }

  $self->stash( debug => \%debug, schema => \%schema_all_attributes );
  $self->render(template => 'protected/sargon/new');

}

=head1 sudo

https://www.sudo.ws/docs/man/sudoers.ldap.man/

=cut

sub sudo ($self) {
  my (%debug, $p);
  $p = $self->req->params->to_hash;
  $self->h_log($p);
  foreach (keys %$p) {
     if ( $p->{$_} eq '' ) {
       delete $p->{$_};
     } elsif (ref($p->{$_}) eq 'ARRAY') {
       @{$p->{$_}} = grep { $_ ne "" } @{$p->{$_}};
     }
  }
  $self->h_log($p);

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my %schema_all_attributes = map { $_->{name} => $_ } $ldap->schema->all_attributes;

  my ($msg, $sudoUser, $groups, $sudoHost, $err);
  ($sudoUser, $err) = $ldap->all_users;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;
  unshift @$sudoUser, '', 'ALL';
  ($groups, $err) = $ldap->all_groups;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  undef $err;
  unshift @$groups, '', 'ALL';
  ($sudoHost, $err) = $ldap->all_hosts;
  push @{$debug{$err->{status}}}, $err->{message} if defined $err;
  unshift @$sudoHost, '', 'ALL';

  $p->{sudoCommand} = [$p->{sudoCommand}] if exists $p->{sudoCommand} && ref($p->{sudoCommand}) ne 'ARRAY';
  $p->{sudoCommand} = [''] if ! exists $p->{sudoCommand};

  $p->{sudoOption} = [$p->{sudoOption}] if exists $p->{sudoOption} && ref($p->{sudoOption}) ne 'ARRAY';
  $p->{sudoOption} = [''] if ! exists $p->{sudoOption};

  $self->stash(
	       sudoUser => $sudoUser,
	       groups => $groups,
	       sudoHost => $sudoHost,
	       sudoCommand => $p->{sudoCommand},
	       sudoOption => $p->{sudoOption},
	       schema => \%schema_all_attributes,
	       debug => \%debug,
	      );

  my $v = $self->validation;
  return $self->render(template => 'protected/sudo/new') unless $v->has_data;
  my $re_cn = qr/^[[:alnum:]_-]+$/;
  $v->required('cn')->like($re_cn);
  $v->error( cn => ['ASCII alnum, - and _ characters only'] ) if $v->error('cn');
  $v->error( sudoUser => ['user or group are mandatory'] ) if ! exists $p->{sudoUser} && ! exists $p->{groups};
  $v->error( groups => ['user or group are mandatory'] ) if ! exists $p->{sudoUser} && ! exists $p->{groups};

  if ( ! $v->has_error ) {
    my $attrs;
    $attrs->{$_} = $p->{$_} foreach keys %$p;
    $attrs->{objectClass} = $self->{app}->{cfg}->{ldap}->{objectClass}->{sudo};

    if ( exists $attrs->{groups} ) {
      $attrs->{sudoUser} = '%' . $attrs->{groups};
      delete $attrs->{groups};
    }
    $self->h_log($attrs);

    # $msg = $ldap->add(sprintf("cn=%s,%s", $attrs->{cn}, $self->{app}->{cfg}->{ldap}->{base}->{sargon}),
    #			 $attrs);
    $self->stash(attrs => $attrs);
    push @{$debug{$msg->{status}}}, $msg->{message};
  }

  $self->stash( debug => \%debug, schema => \%schema_all_attributes );
  $self->render(template => 'protected/sudo/new');
}

=head1 audit_dns_zones

AXFR zones configured in config file

=cut

sub audit_dns_zones ($self) {
  my $p = $self->req->params->to_hash;

  my $v = $self->validation;
  return $self->render(template => 'protected/audit/dns') unless $v->has_data;

  my ($zones, $axfr);
  if ( $p->{zone} eq 'all' ) {
    $axfr = $self->h_dns_rr({ type => 'AXFR', ns_custom => 1, with_txt => 1, whole_axfr => 1 })->{success};
  } else {
    $axfr = $self->h_dns_axfr_single_zone($p->{zone}, { type => 'AXFR', ns_custom => 1, with_txt => 1, whole_axfr => 1 })->{success};
  }
  # $self->h_log($_) foreach ($axfr);
  push @$zones, {
		 fqdn => $_,
		 type => $axfr->{$_}->{type},
		 zone => $axfr->{$_}->{zone},
		 rdstring => $axfr->{$_}->{rdstring},
		 txt => $axfr->{$_}->{txt}
		}
    foreach (sort keys %{$axfr});

  $self->render( template => 'protected/audit/dns', zones => $zones );
}

=head1 audit_dns_chart

Domain occurrence frequency in LDAP objects

=cut

sub audit_dns_chart ($self) {
  my %debug;
  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );
  my ($data, $err) = $ldap->all_hosts('frequencies');
  push @{$debug{error}}, @$err if defined $err;
  # $self->h_log($data);

  my $top_n = $self->{app}->{cfg}->{tool}->{dns}->{chart}->{top_number};
  my @top_pairs = sort { $data->{$b} <=> $data->{$a} } keys %$data;
  splice(@top_pairs, $top_n) if @top_pairs > $top_n;

  my %filtered = map { $_ => $data->{$_} } @top_pairs;

  $self->render( template => 'protected/audit/chart_dns',
		 debug => \%debug,
		 freq => encode_json(\%filtered) );
}

=head1 audit_ages_chart

personnel age chart

=cut

sub audit_ages_chart ($self) {
  my %debug;
  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		     scope => 'one',
		     attrs => [qw(uid umiUserDateOfBirth) ] };
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  my %ages;
  foreach ($search->entries) {
    # $self->h_log( $_->get_value('umiUserDateOfBirth') );
    $ages{ $_->get_value('uid') } = $self->h_years_since( $_->get_value('umiUserDateOfBirth') )
      if $_->exists('umiUserDateOfBirth');
  }

  # $self->h_log(\%ages);

  $self->render( template => 'protected/audit/chart_ages', debug => \%debug, chart => \@{[values %ages]} );
}

=head1 audit_gpg_keys



=cut

sub audit_gpg_keys ($self) {
  my $p = $self->req->params->to_hash;
  my $reqpath = $self->req->url->to_abs->path;
  my ($filter, $state);

  ### PROFILE TO GET:
  if ($self->stash->{key} eq 'all') {
    $filter = '(pgpCertId=*)';
  } elsif ($self->stash->{key} eq 'expired') {
    $filter = '(pgpCertId=*)';
    $state = $self->stash->{key};
  } elsif ($self->stash->{key} eq 'active') {
    $filter = '(pgpCertId=*)';
    $state = $self->stash->{key};
  } elsif ($self->stash->{key} ne '') {
    $filter = sprintf("(pgpUserID=*%s*)", $self->stash->{key});
    } else {
  }

  # $self->h_log($self->stash->{key});

  my $ldap = Umi::Ldap->new( $self->{app}, $self->session('uid'), $self->session('pwd') );

  my $attrs = [qw(pgpCertID pgpKeyID pgpUserID pgpKeyCreateTime pgpKeyExpireTime pgpKey)];
  my $search_arg = { base => $self->{app}->{cfg}->{ldap}->{base}->{pgp},
		     filter => $filter,
		     attrs => $attrs};
  my $search = $ldap->search( $search_arg );
  $self->h_log( $self->{app}->h_ldap_err($search, $search_arg) ) if $search->code;

  my %gpg;
  my $now = localtime;
  foreach ($search->entries) {
    my $exp_ts = $_->get_value('pgpKeyExpireTime') if $_->exists('pgpKeyExpireTime');
    # $self->h_log($exp_ts);
    my $exp = Time::Piece->strptime($exp_ts, '%Y%m%d%H%M%SZ') if defined $exp_ts;

    next if $self->stash->{key} eq 'active'  && defined $exp && $now > $exp;
    next if $self->stash->{key} eq 'expired' && ((defined $exp && $now < $exp) || ! defined $exp);

    $gpg{$_->get_value('pgpCertID')} = {
					pgpKeyID => $_->get_value('pgpKeyID'),
					pgpUserID => $_->get_value('pgpUserID'),
					pgpKeyCreateTime => $_->get_value('pgpKeyCreateTime'),
					pgpKeyExpireTime => $exp_ts // '',
				       };
    }

  return $self->render( template => 'protected/audit/gpg', gpg => \%gpg );
}


1;
