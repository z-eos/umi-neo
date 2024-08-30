package Umi::Helpers::Common;

use Mojo::Base 'Mojolicious::Plugin';

sub register {
    my ($self, $app) = @_;

    # Example string helper
    $app->helper(header_form_subsearch_button => sub {
        my ($c, $text) = @_;
        return uc($text);
    });
}

1;
