# -*- mode: cperl; eval: (follow-mode) -*-

package Umi::Ldap;

use Mojo::Base qw( -base -signatures );
use Mojo::Log;
use Mojo::Util qw( dumper );

use Net::LDAP;
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
  $self->{app}->h_log('Umi::Ldap->ldap() HAS BEEN CALLED');

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
  <dt class="col-2 text-right">DN</dt>
  <dd class="col-10 text-monospace">%s</dd>

  <dt class="col-2 text-right">admin note</dt>
  <dd class="col-10 text-monospace">%s</dd>

  <dt class="col-2 text-right">supplementary data</dt>
  <dd class="col-10 text-monospace">%s</dd>

  <dt class="col-2 text-right">code</dt>
  <dd class="col-10 text-monospace">%s</dd>

  <dt class="col-2 text-right">error name</dt>
  <dd class="col-10 text-monospace">%s</dd>
  
  <dt class="col-2 text-right">error text</dt>
  <dd class="col-10 text-monospace"><em><small><pre><samp>%s</samp></pre></small></em></dd>

  <dt class="col-2 text-right">error description</dt>
  <dd class="col-10 text-monospace">%s</dd>
 
  <dt class="col-2 text-right">server_error</dt>
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
    $message->{html} = sprintf('DN: <a href="/profile/%s">%s</a> has been successfully added.', $attrs->{uid}, $dn);
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

=head2 last_seq_val

find the bigest number among all values of an attributes like for uidNumber or gidNumber

on input it expects hash

    base      => base to search in (mandatory)
    attr      => attribute, the bigest value of which to search for
    filter_by => attribute to use in filter - `(ATTRIBUTE=*)`

returns a ref to an array where the first element is the bigest number
(or undef) and the second value in an error (or undef)

=cut

sub last_num {
  my ($self, $base, $filter_by, $attr) = @_;
  my ($mesg, $search_arg, $err, $res);
  $search_arg = { base   => $base,
		  filter => sprintf("(%s=*)", $filter_by),
		  scope  => 'one',
		  attrs  => [ $attr ], };
  $mesg = $self->search( $search_arg );
  #$self->{app}->h_log( $mesg );
  if ( $mesg->code ) {
    $self->{app}->h_log( $self->{app}->h_ldap_err($mesg, $search_arg) );
  } else {
    if ( $mesg->count ) {
      my @arr = $mesg->sorted ( $attr );
      $res = $arr[$#arr]->get_value( $attr );
    }
  }
  return [ $res, $err ];
}


1;
