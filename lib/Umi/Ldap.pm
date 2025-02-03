# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Ldap;

use Mojo::Base qw( -base -signatures );
use Mojo::Log;
use Mojo::Util qw( dumper );

use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Schema;
use Net::LDAP::Constant qw(
			    LDAP_SUCCESS
			    LDAP_PROTOCOL_ERROR
			    LDAP_NO_SUCH_OBJECT
			    LDAP_INVALID_DN_SYNTAX
			    LDAP_INSUFFICIENT_ACCESS
			    LDAP_CONTROL_SORTRESULT
			 );
use Net::LDAP::Util qw(
			ldap_error_text
			ldap_error_name
			ldap_error_desc
			ldap_explode_dn
			escape_filter_value
			canonical_dn
			generalizedTime_to_time
			time_to_generalizedTime
		     );

use Try::Tiny;

sub new {
  my ($class, $app, $uid, $pwd) = @_;
  my $self =
    bless {
	   app => $app,
	   uid => $uid,
	   pwd => $pwd,
	  }, $class;

  my $cf = $self->{app}->{cfg}->{ldap};
  # $self->{app}->h_log('Umi::Ldap->ldap() HAS BEEN CALLED');

  my $ldap = Net::LDAP->new( $cf->{conn}->{host} );
  if ( ! defined $ldap ) {
    $self->{app}->h_log("Error connecting to $cf->{conn}->{host}: $@");
    return undef;
  }

  my $m = $ldap->bind(sprintf("uid=%s,%s",
			      $self->{uid},
			      $cf->{base}->{acc_root}),
		      password => $self->{pwd},
		      version  => 3,);
  if ( $m->is_error ) {
    $self->{app}->h_log(sprintf("Ldap.pm: ldap(): code: %s; mesg: %s; txt: %s",
				$m->code, $m->error_name, $m->error_text) );
      $self->{ldap} = $m;
  }

  if ( exists $cf->{conn}->{start_tls} ) {
    # $self->{log}->debug(dumper($cf->{conn}->{start_tls}));
    $m = try {
      $ldap->start_tls(
		       verify     => $cf->{conn}->{start_tls}->{verify},
		       cafile     => $cf->{conn}->{start_tls}->{cafile},
		       checkcrl   => $cf->{conn}->{start_tls}->{checkcrl},
		       sslversion => $cf->{conn}->{start_tls}->{sslversion},
		      );
    }
    catch {
      $self->{app}->h_log("Net::LDAP start_tls error: $@") if $m->error;
    } finally {
      if (@_) {
	$self->{ldap} = @_;
      } else {
	$self->{ldap} = $ldap;
      }
    }
  }

  $self->{ldap} = $ldap if ! exists $self->{ldap};

  # $self->{log}->debug(dumper($mesg));

  return $self;
}

sub ldap ($self) {
  return $self->{ldap};
}

sub err {
  my ($self, $mesg, $debug, $dn) = @_;

  my $caller = (caller(1))[3];
  my $err = {
	     code          => $mesg->code // 'NA',
	     name          => ldap_error_name($mesg),
	     text          => ldap_error_text($mesg),
	     desc          => ldap_error_desc($mesg),
	     srv           => $mesg->server_error,
	     caller        => $caller // 'main',
	     matchedDN     => $mesg->{matchedDN} // '',
	     dn            => $dn // '',
	     supplementary => '',
	    };

  $err->{supplementary} .= sprintf('<li><h6><b>matchedDN:</b><small> %s</small><h6></li>', $err->{matchedDN})
    if $err->{matchedDN} ne '';

  $err->{supplementary} = '<div class=""><ul class="list-unstyled">' . $err->{supplementary} . '</ul></div>'
    if $err->{supplementary} ne '';
  
  $err->{html} = sprintf( 'call from <b><em>%s</em></b>: <dl class="row mt-5">
  <dt class="col-2 text-end">DN</dt>
  <dd class="col-10 text-monospace">%s</dd>

  <dt class="col-2 text-end">admin note</dt>
  <dd class="col-10 text-monospace">%s</dd>

  <dt class="col-2 text-end">supplementary data</dt>
  <dd class="col-10 text-monospace">%s</dd>

  <dt class="col-2 text-end">code</dt>
  <dd class="col-10 text-monospace">%s</dd>

  <dt class="col-2 text-end">error name</dt>
  <dd class="col-10 text-monospace">%s</dd>
  
  <dt class="col-2 text-end">error text</dt>
  <dd class="col-10 text-monospace"><em><small><pre><samp>%s</samp></pre></small></em></dd>

  <dt class="col-2 text-end">error description</dt>
  <dd class="col-10 text-monospace">%s</dd>
 
  <dt class="col-2 text-end">server_error</dt>
  <dd class="col-10 text-monospace">%s</dd>
</dl>',
			  $caller,
			  $err->{dn},

			  defined $self->{app}->{cfg}->{ldap}->{err}->{$mesg->code} &&
			  $self->{app}->{cfg}->{ldap}->{err}->{$mesg->code} ne '' ?
			  $self->{app}->{cfg}->{ldap}->{err}->{$mesg->code} : '',

			  $err->{supplementary},
			  $mesg->code,
			  ldap_error_name($mesg),
			  ldap_error_text($mesg),
			  ldap_error_desc($mesg),
			  $mesg->server_error
			 );

  return $err; # if $mesg->code;
}

sub search {
  my ($self, $a) = @_;

  my $cf = $self->{app}->{cfg}->{ldap};
  my $o =
    {
     base   => $a->{base}   // $cf->{base}->{dc},
     attrs  => $a->{attrs}  // $cf->{defaults}->{attrs},
     deref  => $a->{deref}  // $cf->{defaults}->{deref},
     filter => $a->{filter} // $cf->{defaults}->{filter},
     scope  => $a->{scope}  // $cf->{defaults}->{scope},
     sizelimit => $a->{sizelimit} // $cf->{defaults}->{sizelimit},
    };

  # $self->{log}->debug(dumper($o));
  return $self->ldap->search( %{$o} );
}

sub add {
  my ($self, $dn, $attrs) = @_;
  my ($status, $message);
  my $msg = $self->ldap->add ( $dn, attrs => [%{$attrs}], );
  if ($msg->is_error()) {
    $message = $self->err( $msg, 0, $dn );
    $message->{caller} = 'call to Umi::Ldap::add from ' . (caller(1))[3] . ': ';
    $status = 'error';
  } else {
    $message->{html} = sprintf('DN: %s has been successfully added.', $dn);
    $status = 'ok';
  }
  return {status => $status, message => $message->{html}};
}

sub modify {
  my ($self, $dn, $changes ) = @_;
  my ($status, $message);
  my $msg = $self->ldap->modify ( $dn, changes => $changes, );
  if ($msg->is_error()) {
    $message = $self->err( $msg, 0, $dn );
    $message->{caller} = 'call to Umi::Ldap::add from ' . (caller(1))[3] . ': ';
    $status = 'error';
  } else {
    $message->{html} = sprintf('DN: %s has been successfully modified.', $dn);
    $status = 'ok';
  }
  return {status => $status, message => $message->{html}};
}

sub schema ($self) {
  return $self->ldap->schema();
}

=head2 get_all_superior_classes

Recursive routine to retrieve all superior object classes

=cut

sub get_all_superior_classes {
  my ($self, $schema, $oc_name, $seen) = @_;

  $seen ||= {};
  my @supers = ();

  return () if $seen->{$oc_name}++;

  my $oc = $schema->objectclass($oc_name);
  my @direct_supers = ();

  if ( ref($oc) eq 'HASH' ) {
    # If 'sup' is stored as an array ref, use it, otherwise force it into an array.
    if ( exists $oc->{sup} ) {
      @direct_supers = ref($oc->{sup}) eq 'ARRAY' ? @{$oc->{sup}} : ($oc->{sup});
    }
  }
  # Otherwise, if it's a blessed object that provides a 'sup' method, use it.
  elsif ( $oc and $oc->can("sup") ) {
    @direct_supers = $oc->sup;
  }

  for my $super (@direct_supers) {
    push @supers, $super;
    push @supers, $self->get_all_superior_classes($schema, $super, $seen);
  }
  return @supers;

}

=head2 last_num

find the bigest number among all values of an attributes like for uidNumber or gidNumber

on input it expects hash

    base      : base to search in (mandatory)
    filter_by : attribute to use in filter - `(ATTRIBUTE=*)`
    attr      : attribute, the bigest value of which to search for
    scope     : scope, default `one`

returns a ref to an array where the first element is the bigest number
(or undef) and the second value in an error (or undef)

=cut

sub last_num {
  my ($self, $base, $filter, $attr, $scope) = @_;
  my ($mesg, $search_arg, $err, $res);
  $search_arg = { base   => $base   // $self->{app}->{cfg}->{ldap}->{base}->{acc_root},
		  filter => $filter // '(uid=*)',
		  scope  => $scope  // 'one',
		  attrs  => [ $attr // 'uidNumber' ], };
  $mesg = $self->search( $search_arg );
  # $self->{app}->h_log( $search_arg );
  if ( $mesg->code ) {
    $self->{app}->h_log( $self->{app}->h_ldap_err($mesg, $search_arg) );
  } else {
    if ( $mesg->count ) {
      my @arr = $mesg->sorted ( $attr // 'uidNumber' );
      # $self->{app}->h_log( \@arr );
      $res = $arr[$#arr]->get_value( $attr // 'uidNumber' );
    }
  }
  return [ $res, $err ];
}

sub delete {
  my ($self, $dn, $recursively, $scope) = @_;
  $recursively = 0 if ! defined $recursively;
  $scope = 'sub' if ! defined $scope;
  my ($entries, $msg, $return, $search);

  # !! to add it latter # my $g_mod = $self->del_from_groups($dn);
  # !! to add it latter # push @{$return->{error}}, $g_mod->{error} if defined $g_mod->{error};

  if ($recursively) {
    $search = $self->search({ base => $dn, filter => '(objectclass=*)', scope => $scope });
    ## taken from perl-ldap/contrib/recursive-ldap-delete.pl
    # delete the entries found in a sorted way:
    # those with more "," (= more elements) in their DN, which are deeper in the DIT, first
    # trick for the sorting: tr/,// returns number of , (see perlfaq4 for details)
    @$entries = sort { $b->dn =~ tr/,// <=> $a->dn =~ tr/,// } $search->entries()
  } else {
    $entries = [ $dn ];
  }

  foreach my $e (@$entries) {
    $msg = $self->ldap->delete($e);
    # $self->{app}->h_log($self->err($msg));
    if ( $msg->code == LDAP_SUCCESS ) {
      $return = { ok => [ 'successfully deleted <mark class="bg-success">' . $dn . '</mark>' ] };
    } elsif ( $msg->code == LDAP_NO_SUCH_OBJECT ) {
      $return = { warn => [$self->err( $msg, 0, $dn )->{html}] };
    } else {
      $return = { error => [$self->err( $msg, 0, $dn )->{html}] };
    }
  }

  return $return;
}

=head2 moddn

Net::LDAP->moddn wrapper

=cut

sub moddn {
  my ($self, $args) = @_;
  # $self->{app}->h_log($args);
  my $msg;
  if (defined $args->{newsuperior} ) {
    $msg = $self->ldap->moddn ( $args->{src_dn},
				newrdn       => $args->{newrdn},
				deleteoldrdn => $args->{deleteoldrdn} // '1' );
  } else {
    $msg = $self->ldap->moddn ( $args->{src_dn},
				newrdn       => $args->{newrdn},
				deleteoldrdn => $args->{deleteoldrdn} // '1',
				newsuperior  => $args->{newsuperior} );
  }
  # $self->{app}->h_log($msg);
  my $return;
  if ($msg->is_error()) {
    $return = { error => [$self->err( $msg, 0, $args->{src_dn} )->{html}] };
  } else {
    $return = { ok => [ 'DN ' . $args->{src_dn} . ' successfully modified<br>new RDN <mark class="bg-success">' . $args->{newrdn} . '</mark>'] };
  }
  return $return;
}

=head2 ldif_read

LDIF processing from input ldif code

=cut

sub ldif_read {
  my ($self, $ldif) = @_;

  my ($file, $entry, $res);
  try {
    open( $file, "<", \$ldif);
  }
  catch {
    $self->{app}->h_log("Cannot open data from variable: \$file for reading: $_");
    return {debug => { error => [ "Cannot open data from variable: \$ldif for reading: $_", ] }};
  };

  my $l = Net::LDAP::LDIF->new( $file, "r", onerror => 'warn' );
  while ( not $l->eof ) {
    $entry = $l->read_entry;
    if ( $l->error ) {
      push @{$res->{debug}->{error}},
	sprintf('Error msg: %s\nError lines:\n%s\n',
		$l->error,
		$l->error_lines );
    } else {
      my $mesg = $entry->update($self->ldap);
      if ( $mesg->code ) {
	$self->{app}->h_log( $self->err($mesg) );
	return {debug => {error => [ $self->err($mesg)->{html} ]}};
      } else {
	push @{$res->{debug}->{ok}}, '<mark>' . $entry->dn . '</mark> successfully added';
      }
    }
  }
  $l->done;

  try {
    close $file;
  }
  catch {
    return {debug => { error => "Cannot close file: \$file error: $_" }};
  };

  return $res;
}

1;
