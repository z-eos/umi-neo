package Umi;
use Mojo::Base 'Mojolicious', -signatures;
use Mojo::Util 'b64_decode';
use Umi::Model::Authentication;

use constant DEFAULTS => {
   CONFIG => {},
   DATABASE_URL => 'sqlite:./tmp/test.db',
   SECRETS => '[%=
      use MIME::Base64 "encode_base64";
      encode_base64(time() . "-" . rand(), '');
   %]',
   SECRETS => ['FIXME'],
   HARDCODED_AUTHENTICATION_DB => [
      { name => foo => secret => 123  },
      { name => bar => secret => 456  },
      { name => baz => secret => 789  },
      { name => galook => secret => 0 },
   ],
};
has 'model';

sub startup ($self) {
    $self->_startup_config;
    $self->_startup_secrets;
    $self->_startup_hooks;
    $self->_startup_model;
    $self->_startup_routes;
    $self->_startup_authentication;
    
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

    $self->renderer->default_handler('tt');

    # $self->helper(users => sub { state $users = Umi::Model::Users->new });

    # my $r = $self->routes;
    # $r->any('/')->to('login#index')->name('index');
    # $r->post('/index')->to('login#index')->name('index');
    # $r->get('/index')->to('login#index')->name('index');

    # my $logged_in = $r->under('/')->to('login#logged_in');
    # $logged_in->get('/protected')->to('login#protected');

    # $r->get('/logout')->to('login#logout');

    $self->log->info('startup complete');
    return $self;
}

sub _startup_config ($self) {
    my $config = $self->plugin('NotYAMLConfig');
    return $self;
}

sub _startup_secrets ($self) {
   my $secrets = $self->config->{secrets};
   $secrets = [ map { b64_decode($_) } split m{\s+}mxs, $secrets ]
      unless ref($secrets);
   $self->secrets($secrets);
   return $self;
}

sub _startup_model ($self) {
   my $config = $self->config;
   my $model = [% all_modules.model_module %]->new(
      [%= $pfx{db} %]db_url => $self->config->{database_url},

      authentication_options => {

         providers => [
            {
               name  => 'hashy',
               class => '[% all_modules.model_authn_hash_module %]',
               args  => [
                  db => DEFAULTS->{HARDCODED_AUTHENTICATION_DB},

                  # set to true if secrets in db already hashed 
                  secrets_already_hashed => 0,
               ],
            },
         ],

      },
      
   );
   $self->model($model);

   # do anything that's needed for initialization here...
   $model->wmdb->init($self->moniker);

   return $self;
}
sub _startup_hooks ($self) {
   return $self;
}

sub _startup_authentication ($self) {
   my $authn = $self->model->authentication;
   $self->plugin(
      Authentication => {
         load_user     => sub ($a, $x) { $authn->load_user($x)     },
         validate_user => sub ($c, @A) { $authn->validate_user(@A) },
      },
   );

   $self->hook(
      before_render => sub ($c, $args) {
         my $acct = $c->is_user_authenticated ? $c->current_user : undef;
         $c->stash(account => $acct);
         return $c;
      }
   );

   # routes scaffolding
   my $r = $self->routes;
   $r->get('login')->to('authentication#show_login');
   $r->post('login')->to('authentication#do_login');
   $r->get('logout')->to('authentication#do_logout');
   $r->post('logout')->to('authentication#do_logout');
   # FIXME add routes for API login/logout

   # to set authenticated routes, change method "_authenticated_routes"
   my $auth = $r->under('/auth')->to('authentication#check');
   $self->_authenticated_routes($auth);

   # add a final catchall to force anything under /auth to require
   # authentication, even non-existent routes. This avoids leaking info
   # about which authenticated routes are valid and which not.
   $auth->any('*' => sub ($c) { return $c->render(status => 404) });

   return $self;
}

sub _authenticated_routes ($self, $root) {
   $root->get('/')->to('authenticated-basic#root');
}

########################################################################
#
# Routes, where all the fun happens!
#
# By default, routes are private and subject to authentication. The
# exception set by default is everything under '/public', including
# '/public/auth' to cope with login/logout in locally managed accounts
#
sub _startup_routes ($self) {
   my $root = $self->routes;

   my $public_root = $root->any('/public')->name('public_root');
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

   $self->_public_routes($public_root)
      ->_authentication_routes($public_root->any('/auth'))
      ->_protected_routes($protected_root)
      ->_default_to_404($root);

   return $self;
}

# Routes for local authentication (trivial/db)
sub _authentication_routes ($self, $root) {
   my %ctr = (controller => 'Public::Authentication');
   $root->get('/login')->to(%ctr, action => 'show_login');
   $root->post('/login')->to(%ctr, action => 'do_login');
   $root->get('/logout')->to(%ctr, action => 'do_logout');
   $root->post('/logout')->to(%ctr, action => 'do_logout');
   return $self;
}

sub _default_to_404 ($self, $root) {
   my $nf = sub ($c) {$c->render(template => 'not_found', status => 404)};
   $root->any($_ => $nf) for qw< * / >;
   return $self;
}

############## MAIN BUSINESS LOGIC ##############

sub _public_routes ($self, $root) {
   $root->get('/')->to('public#root');
   return $self;
}

sub _protected_routes ($self, $root) {
   $root->get('/')->to('protected#root');
   $root->get('/example')->to(controller => 'Protected::Example',
      action => 'root');
   return $self;
}
1;
