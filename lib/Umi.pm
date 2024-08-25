# package Umi;

# use Mojo::Base 'Mojolicious', -signatures;
# use Umi::Model::Users;

# # use strict;
# # use warnings;

# use Data::Printer colored => 1, caller_info => 1;

# # This method will run once at server start
# sub startup {
#     my $self = shift;
#   # Load configuration from config file
#   my $config = $self->plugin('NotYAMLConfig');
#   # p $config;
#   # Configure the application
#   $self->secrets($config->{secrets});

#   # Router
#   my $r = $self->routes;

#   $self->helper( users => sub { state $users = Umi::Model::Users->new } );
#   my $user = $self->param('user') || '';
#   my $pass = $self->param('pass') || '';
#   # p $self->param;

#   $r->any()->to('Auth#login') unless $self->users->check($user, $pass);
#   $self->session(user => $user);
#   $self->flash(message => 'Thanks for logging in.');
#   # $self->log->debug("param user: $user;"); # sess user: $self->session('user')")
  
#   $r->get('/logout')->to('Auth#login');
#   $r->get('/login')->to('Auth#passed');
#   $r->post('/login')->to('Auth#passed');
#   $r->get('/passed')->to('Auth#passed');

#   # # Make sure user is logged in for actions in this group
#   # group {
#   #     under sub ($self) {

#   # 	  # Redirect to main page with a 302 response if user is not logged in
#   # 	  return 1 if $self->session('user');
#   # 	  $self->redirect_to('login');
#   # 	  return undef;
#   #     };

#   #     # A protected page auto rendering "protected.html.ep"
#   #     $r->get('/protected')->to();
#   # };
  
#   # $r->get('/')->to('Error#error');

# }

# 1;
package Umi;
use Mojo::Base 'Mojolicious', -signatures;

use Umi::Model::Users;

sub startup ($self) {

    # Load configuration from config file
    my $config = $self->plugin('NotYAMLConfig');
    # p $config;
    # Configure the application
    $self->secrets($config->{secrets});
    $self->plugin('tt_renderer' => {
	template_options => {
	    PRE_CHOMP => 1,
	    # PRE_PROCESS => '',
	    POST_CHOMP => 1,
	    TRIM => 1,
	    EVAL_PERL => 1,
	    WRAPPER => 'layouts/default.html.tt',
	},
		  });

    # $self->plugin(
    # 	Authentication => {
    # 	    load_user     => sub ($app, $uid) { load_account($uid) },
    # 	    validate_user => sub ($c, $u, $p, $e) {
    # 		validate($u, $p) ? $u : () },
    # 	}
    # 	);

    # $self->hook(
    # 	before_render => sub ($c, $args) {
    # 	    my $user = $c->is_user_authenticated ? $c->current_user : undef;
    # 	    $c->stash(user => $user);
    # 	    return $c;
    # 	}
    # 	);

    $self->renderer->default_handler('tt');

    $self->helper(users => sub { state $users = Umi::Model::Users->new });

    my $r = $self->routes;
    $r->any('/')->to('login#index')->name('index');
    $r->post('/index')->to('login#index')->name('index');
    $r->get('/index')->to('login#index')->name('index');

    my $logged_in = $r->under('/')->to('login#logged_in');
    $logged_in->get('/protected')->to('login#protected');

    $r->get('/logout')->to('login#logout');
}

1;
