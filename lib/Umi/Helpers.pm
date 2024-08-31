package Umi::Helpers;

use Mojo::Base 'Mojolicious::Plugin';

sub register {
    my ($self, $app) = @_;

    $app->plugin('Umi::Helpers::Common');

}

1;
