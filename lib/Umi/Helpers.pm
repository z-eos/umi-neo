package Umi::Helpers;

use Mojo::Base 'Mojolicious::Plugin';

sub register {
    my ($self, $app) = @_;

    $app->plugin('Umi::Helpers::Common');
    $app->plugin('Umi::Helpers::Dns');
    $app->plugin('Umi::Helpers::SearchResult');

}

1;
