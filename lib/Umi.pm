# -*- mode: perl; eval(follow-mode); -*-
#

package Umi;
use v5.24;
use Mojo::Base qw< Mojolicious -signatures >;
use Umi::Authentication;

has 'cfg' => sub { {} };

sub startup ($self) {

    $self->_startup_config;
    
    # in this example, we have a class that is devoted to handling our
    # authentication calls.
    my $authn = Umi::Authentication->new($self->app);

    # we use this class to provide the two callbacks required by the
    # Authentication plugin, namely load_user and validate_user. The two
    # sub:s close on lexical variable $authn, keeping it alive after we
    # exit from this "startup" method.
    $self->plugin(
	Authentication => {
	    load_user     => sub ($a, $x) { $authn->load_user($x)     },
	    validate_user => sub ($c, @A) { $authn->validate_user(@A) },
	},
	);
    $self->sessions->default_expiration(86400);

    $self->_startup_routes;

    return $self;
}

sub _startup_config ($self) {
    my $config = $self->plugin('NotYAMLConfig');
    $self->cfg->{ldap} = $config->{ldap};

    # # variables to be taken remapped from the environment
    # if (defined(my $remaps = $config->{remap_env})) {
    #    for my $definition (split m{,}mxs, $remaps) {
    #       my ($key, $env_key) = split m{=}mxs, $definition, 2;
    #       $env_key = $key unless length($env_key // '');
    #       $config->{$key} = $ENV{$env_key} if defined $ENV{$env_key};
    #    }
    # }

    return $self;
}

sub _startup_routes ($self) {
    # let's deal with routes like this:
    # - /login and /logout do what they imply and are not subject to
    #   authentication checks
    # - anything under /public is... public and not subject to
    #   authentication checks
    # - anything else under / is protected
    # - anything not dealt with explicitly is a 404
    my $root           = $self->routes;

    $self->_authentication_routes($root);

    # public routes: a home page and some other page
    my $public_root = $root->any('/public');
    $public_root->get('/')->to('public#homepage')->name('public_root');
    $public_root->get('/other')->to('public#other');

    # everything else under '/' will be protected. We make sure this will
    # be the case by attaching any following route "under" a common
    # ancestor that will perform the authentication check and redirect to
    # the homepage if it has not been performed correctly.
    my $protected_root = $root->under(
	'/' => sub ($c) {
	    if ($c->is_user_authenticated) {
		$c->stash(is_user_authenticated => 1);
		return 1;
	    }

	    $c->log->debug('not authenticated, bouncing to public home');
	    $c->stash(is_user_authenticated => 0);
	    $c->redirect_to('public_root');
	    return 0;
	}
	);
    
    $protected_root->get('/')->to('protected#homepage')->name('protected_root');
    $protected_root->get('/other')->to('protected#other');
    $protected_root->get('/profile')->to('protected#profile');

    # default to 404 for anything that has not been handled explicitly.
    # This is probably reinventing a wheel already present in Mojolicious
    my $nf = sub ($c) {$c->render(template => 'not_found', status => 404)};
    $public_root->any($_ => $nf) for qw< * / >;
    $protected_root->any($_ => $nf) for qw< * / >;

    $self->controller_class('Umi::Controller');
    $self->defaults(layout => 'default');
    $self->log->info('startup complete');

    return $self;
}

# Routes for authentication, without the need to check credentials
# before they are accessed.
sub _authentication_routes ($self, $root) {
   my %ctr = (controller => 'Controller::Public');
   # $root->get('/login'  )->to(%ctr, action => 'show_login');
   $root->post('/login' )->to(%ctr, action => 'do_login');
   $root->get('/logout' )->to(%ctr, action => 'do_logout');
   $root->post('/logout')->to(%ctr, action => 'do_logout');
   return $self;
}

sub _default_to_404 ($self, $root) {
   my $nf = sub ($c) {$c->render(template => 'not_found', status => 404)};
   $root->any($_ => $nf) for qw< * / >;
   return $self;
}
1;
