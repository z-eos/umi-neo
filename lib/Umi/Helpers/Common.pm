package Umi::Helpers::Common;

use Mojo::Base 'Mojolicious::Plugin';

sub register {
    my ($self, $app) = @_;

    # Example string helper
    $app->helper(header_form_subsearch_button => sub {
        my ($c, $text) = @_;
        return uc($text);
		 });

    # MAC address normalyzer
    $app->helper(macnorm => sub {
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

	    log_debug { np(@mac_arr) };
	    return lc( join( $arg->{dlm}, @mac_arr ) );
	    } else {
		return 0;
	}
		 });



}

1;
