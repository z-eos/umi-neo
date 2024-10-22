# -*- mode: cperl; eval(follow-mode); -*-

package Umi::Helpers::SearchResult;

use Mojo::Base 'Mojolicious::Plugin';

sub register {
    my ($self, $app) = @_;

    $app->helper(
	h_rewrite_dn => sub {
	    my ($c, $dn, $delim) = @_;
	    $delim = ' > ' if ! defined $delim;
	    my @x = split(/,/, $dn);
	    pop @x;
	    pop @x;
	    my @y = map { substr($_, index($_, '=') + 1) } @x;
	    return join($delim, @y);
	});

    $app->helper(
	h_dn_color => sub {
	    my ($c, $dn) = @_;
	    if ( $dn =~ /^author/ ) {
		return "warning";
	    } elsif ( $dn =~ /^(cn|uid)=[^,]+,auth/ ) {
		return "success";
	    } elsif ( $dn =~ /^uid=[^,]+,ou=People,dc=/i ) {
		return "info";
	    } else {
		return "secondary";
	    }
	  });
    use Data::Printer caller_info => 1;
    $app->helper(
		 h_attr_unused => sub {
		   my ($c, $e, $s) = @_;
		   # p $e;
		   my $au;
		   foreach my $oc (@{$e->get_value('objectClass', asref => 1)}) {
		     # p $oc;
		     # p $s->{$oc};
		     if ( exists $s->{$oc}->{must} ) {
		       $au->{$_} = 0 foreach (@{$s->{$oc}->{must}});
		     }
		     if ( exists $s->{$oc}->{may} ) {
		       $au->{$_} = 0 foreach (@{$s->{$oc}->{may}});
		     }
		   }
		   # p $au;
		   delete $au->{$_} foreach ($e->attributes);
		   # p $au;
		   return sort(keys %$au);
		 });

}

1;
