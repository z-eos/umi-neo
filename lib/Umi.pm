# -*- mode: perl; eval(follow-mode); -*-
#

package Umi;

use Umi::Authentication;

use Mojo::Base qw< Mojolicious -signatures >;

has 'cfg' => sub { {} };

sub startup ($self) {

    $self->_startup_config;
    
    $self->plugin('Umi::Helpers');

    # in this example, we have a class that is devoted to handling our
    # authentication calls.
    my $authn = Umi::Authentication->new($self->app);
    # we use this class to provide the two callbacks required by the
    # Authentication plugin, namely load_user and validate_user. The two
    # sub:s close on lexical variable $authn, keeping it alive after we
    # exit from this "startup" method.
    $self->plugin(
     	Authentication => {
     	    load_user     => sub ($app, $uid) { $authn->load_user($uid)     },
     	    validate_user => sub ($c, @A) { $authn->validate_user(@A) },
     	},
     	);

    $self->_startup_routes;

    $self->sessions->default_expiration($self->cfg->{session}->{expiration});
    $self->_startup_session;

    return $self;
}

sub _startup_session ($self) {
    # Helper to set user session after successful authentication
    $self->helper(set_user_session => sub {
        my ($c, $username, $password) = @_;
        $c->session(uid => $username);
        $c->session(pwd => $password);
        $c->session(last_seen => time());
		  });

    $self->helper(get_pwd => sub {
        my $c = shift;
        return $c->session('pwd');
		  });

    # Helper to check if user is authenticated
    $self->helper(is_user_authenticated => sub {
        my $c = shift;
        return $c->session('uid') ? 1 : 0;
		  });

    # Middleware to check session expiration
    $self->hook(before_dispatch => sub {
        my $c = shift;

        if ($c->is_user_authenticated) {
            my $last_seen = $c->session('last_seen');
            if (time() - $last_seen > $self->cfg->{session}->{expiration}) {
                # Session expired, clear it
                $c->session(expires => 1);
		$c->redirect_to('/');
		return 0;
            } else {
                # Update last_seen
                $c->session(last_seen => time());
            }
        }
	return 1;
		});
}

sub _startup_config ($self) {
    $self->cfg($self->plugin('NotYAMLConfig'));

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
#?		$c->is_user_authenticated => 1);
		$self->log->info("returning: 1");
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
    $protected_root->get('/tool/ldif-import')->to('protected#ldif_import');
    $protected_root->post('/search/common')->to('protected#search_common');

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
