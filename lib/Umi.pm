# -*- mode: cperl; eval: (follow-mode 1); -*-
#

package Umi;

use Umi::Authentication;
use Umi::Constants qw(COUNTRIES);

use Mojo::Base qw( Mojolicious -signatures );
use Mojo::Util qw( dumper );
use Mojolicious::Plugin::Authentication;
use Mojolicious::Plugin::Authorization;

# ?? # use Mojolicious::Plugin::Syslog;
use Data::Printer {
  caller_info => 1,
    hash_max => 0,
    array_max => 0,
    theme => 'Monokai',
    # max_depth   => 3,
    # use_prototypes => 0,
  };

has 'cfg' => sub { {} };

sub startup ($self) {

  $self->_startup_config;
  $self->secrets($self->cfg->{secrets});

  $self->plugin('Umi::Helpers');
  $self->plugin('Umi::Helpers::Common');
  $self->plugin('Umi::Helpers::SearchResult');

  # in this example, we have a class that is devoted to handling our
  # authentication calls.
  my $authn = Umi::Authentication->new($self->app);
  # we use this class to provide the two callbacks required by the
  # Authentication plugin, namely load_user and validate_user. The two
  # sub:s close on lexical variable $authn, keeping it alive after we
  # exit from this "startup" method.

  ### authentication is performed in lib/Umi/Controller/Public.pm
  $self->plugin('Authentication' =>
		{
		 load_user     => sub ($app, $uid) { $authn->load_user($uid) },
		 validate_user => sub ($c, @A) { $authn->validate_user(@A)   },
		});

  $self->plugin('Authorization' =>
		{
		 has_priv => sub {
		   my ($self, $priv, $extradata) = @_;
		   return 0 unless ($self->session('role'));
		   my $privileges = $self->session('privileges');
		   my @privs = split(/,/, $priv);
		   # p $priv; p $extradata; p $privileges; p @privs;
		   if ( scalar(@privs) == 1 ) {
		     return 1 if exists $privileges->{$priv};
		   } elsif ( $extradata->{cmp} eq 'or' ) {
		     foreach (@privs) {
		       return 1 if exists $privileges->{$_};
		     }
		   } elsif ( $extradata->{cmp} eq 'and' ) {
		     my $i;
		     foreach (@privs) {
		       $i++ if exists $privileges->{$_};
		     }
		     return 1 if $i == scalar(@privs);
		   }
		   #my $err = 'Privivege is not authorized';
		   #p $err;
		   return 0;
		 },
		 is_role => sub {
		   my ($self, $role, $extradata) = @_;
		   return 0 unless ($self->session('role'));
		   my $r = $self->session('role');
		   my @roles = split(/,/, $role);
		   # p $priv; p $extradata; p $roles; p @privs;
		   if ( scalar(@roles) == 1 ) {
		     return 1 if $roles[0] eq $r;
		   } elsif ( $extradata->{cmp} eq 'or' ) {
		     foreach (@roles) {
		       return 1 if $_ eq $r;
		     }
		   } elsif ( $extradata->{cmp} eq 'and' ) {
		     my $i;
		     foreach (@roles) {
		       $i++ if $_ eq $r;
		     }
		     return 1 if $i == scalar(@roles);
		   }
		   #my $err = 'Role is not authorized';
		   #p $err;
		   return 0;
		 },
		 user_privs => sub {
		   my ($self, $extradata) = @_;
		   return [] unless ($self->session('role'));
		   return keys(%{$self->session('privileges')});
		 },
		 user_role => sub {
		   my ($self, $extradata) = @_;
		   return $self->session('role');
		 },
		 ### doesn't work # 'fail_render' => { status => 401, text => 'not authorized' },
		 #'fail_render' => { status => 401, template => 'not_found' },
		});

  $self->_startup_routes;

  $self->sessions->default_expiration($self->cfg->{session}->{expiration});
  $self->_startup_session;

  return $self;
}

sub _startup_session ($self) {
  ## ?? # Mojolicious::Plugin::ServerSession
  $self->helper(
		h_log => sub {
		  my ($self, $data) = @_;
		  if ($self->app->cfg->{debug}->{level} > 0) {
		    my ($package, $filename, $line) = caller(1);
		    p $data, caller_message => "$package $filename:$line";
		  }
		});

  # Helper to set user session after successful authentication
  $self->helper(
		set_user_session => sub {
		  # my ($self, $username, $password) = @_;
		  # $self->session(uid => $username);
		  # $self->session(pwd => $password);
		  my ($self, $data_to_session) = @_;
		  my ($k, $v);
		  $self->session($k => $v) while (($k, $v) = each %$data_to_session);
		  $self->session(last_seen => time());
		});

  $self->helper(
		get_pwd => sub {
		  my $self = shift;
		  return $self->session('pwd');
		});

  # Helper to check if user is authenticated
  $self->helper(
		is_user_authenticated => sub {
		  my $self = shift;
		  return $self->session('uid') ? 1 : 0;
		});

  $self->helper(
		constant => sub {
		  my ($c, $name) = @_;
		  return Umi::Constants->can($name) ? Umi::Constants->$name() : undef;
		});

  # Middleware to check session expiration
  $self->hook(
	      before_dispatch => sub {
		my $self = shift;

		if ($self->is_user_authenticated) {
		  my $last_seen = $self->session('last_seen');
		  if (time() - $last_seen > $self->app->cfg->{session}->{expiration}) {
		    # Session expired, clear it
		    $self->session(expires => 1);
		    $self->redirect_to('/');
		    return 0;
		  } else {
		    # Update last_seen
		    $self->session(last_seen => time());
		  }
		}
		return 1;
	      });
}

sub _startup_config ($self) {
  $self->cfg($self->plugin('NotYAMLConfig', {file => 'conf/umi.yml'}));
  $self->plugin('StaticCache' => { even_in_dev => 0 });

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

  # public routes: a home page and some other page
  my $public_root = $root->any('/public');
  $public_root->get('/')->to('public#homepage')->name('public_root');
  $public_root->get('/other')->to('public#other');

  ## MACHINES
  $public_root->get( '/machines')->to('machines#list');
  $public_root->post('/machines')->to('machines#create_or_update');
  $public_root->put('/machines/:id')->to('machines#update');
  $public_root->delete('/machines/:id')->to('machines#delete');

  $self->_authentication_routes($root);

  # everything else under '/' will be protected. We make sure this will
  # be the case by attaching any following route "under" a common
  # ancestor that will perform the authentication check and redirect to
  # the homepage if it has not been performed correctly.
  my $protected_root = $root->
    under('/' => sub ($c) {
	    if ($c->is_user_authenticated) {
	      $c->stash(is_user_authenticated => 1);
	      $self->log->info("Successfull authentication occured, protected routes are available.");
	      return 1;
	    }

	    $c->log->debug('User is not authenticated, bouncing to public home');
	    $self->stash({ debug => { error => ['Authentication failed'] }});
	    $c->stash(is_user_authenticated => 0);
	    $c->redirect_to('public_root');
	    return 0;
	  }
	 );

  $protected_root->get('/')->to('protected#homepage')->name('protected_root');
  $protected_root->get('/other')->to('protected#other');

  ###
  ### mod Authorization start only with v.1.0.6 — $...->requires(has_priv => ['r-people,r-group', {cmp => 'and'}])->...;
  ###

  ## PROFILE
  $protected_root
    ->get( '/profile/new')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#profile_new');

  $protected_root
    ->post('/profile/new')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#profile_new');

  $protected_root
    ->get( '/profile/newsvc')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('newsvc#newsvc');
  $protected_root
    ->post('/profile/newsvc')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('newsvc#newsvc');

  $protected_root
    ->get( '/profile/groups')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('protected#groups');
  $protected_root
    ->post('/profile/groups')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('protected#groups');

  $protected_root
    ->get( '/profile/modify/:uid' => [ uid => qr/[^\/]+/ ])
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#profile_modify', uid => '');

  $protected_root
    ->post('/profile/modify')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#profile_modify');

  $protected_root
    ->get( '/profile/:uid' => [ uid => qr/[^\/]+/ ])
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#profile', uid => '');
  $protected_root
    ->post('/profile/:uid' => [ uid => qr/[^\/]+/ ])
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#profile', uid => '');

  $protected_root
    ->get( '/profile')
    ->to('protected#profile');

  $protected_root
    ->post('/profile')
    ->to('protected#profile');

  ## NET/GROUPs
  $protected_root
    ->get( '/group/new')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('group#new_grp');
  $protected_root
    ->post('/group/new')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('group#new_grp');

  $protected_root
    ->get( '/netgroup/new')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('group#new_netgrp');
  $protected_root
    ->post('/netgroup/new')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('group#new_netgrp');

  # ## MACHINES
  # $protected_root
  #   ->get( '/machines')
  #   ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
  #   ->to('machines#list');
  # $protected_root
  #   ->post('/machines')
  #   ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
  #   ->to('machines#new');
  # $protected_root
  #   ->put('/machines/:id')
  #   ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
  #   ->to('machines#update');
  # $protected_root
  #   ->delete('/machines/:id')
  #   ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
  #   ->to('machines#delete');

  ## PROJECT
  $protected_root
    ->get( '/project/new')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#project_new');
  $protected_root
    ->post('/project/new')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#project_new');

  $protected_root
    ->get( '/project/modify/:proj' => [ proj => qr/[^\/]+/ ])
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#project_modify', proj => '');

  $protected_root
    ->post('/project/modify')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#project_modify');

  $protected_root
    ->get( '/project/:proj')
    ->to('search#search_projects', proj => '*');
  $protected_root
    ->post('/project/:proj')
    ->to('search#search_projects', proj => '*');

  ## SEARCH
  $protected_root
    ->get( '/search/common')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('search#search_common');
  $protected_root
    ->post('/search/common')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('search#search_common')->name('search_common');

  ## DELETE
  $protected_root
    ->post('/delete')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('protected#delete');

  ## FIRE
  $protected_root
    ->post('/fire')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('protected#fire');

  ## AUDIT
  ### users
  $protected_root
    ->get( '/audit/users/:type') # => [ type => qr/[^a-z\-]+$/ ] )
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#profile', type => 'user-driven-rows');
  $protected_root
    ->get( '/audit/users')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#profile');
#    ->to('audit#users');

  ## TOOLs
  ### aside
  $protected_root
    ->get( '/tool/ldap-tree')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('ldaptree#obj');

  $protected_root
    ->get( '/tool/ipa-tree')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('ldaptree#ipa');

  $protected_root
    ->get( '/tool/resolve')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('protected#resolve');

  ### sidebar
  $protected_root->get( '/tool/ldif-export')->to('protected#ldif_export');
  $protected_root->post('/tool/ldif-export')->to('protected#ldif_export');

  $protected_root
    ->get( '/tool/ldif-import')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#ldif_import');
  $protected_root
    ->post('/tool/ldif-import')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#ldif_import');

  $protected_root
    ->get( '/tool/modify')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#modify');
  $protected_root
    ->post('/tool/modify')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#modify');

  $protected_root
    ->post('/tool/moddn')
    ->requires(is_role => ['admin,coadmin', {cmp => 'or'}])
    ->to('protected#moddn');

  $protected_root->get( '/onboarding')->to('protected#onboarding');
  $protected_root->post('/onboarding')->to('protected#onboarding');

  $protected_root->get( '/tool/pwdgen')->to('protected#pwdgen');
  $protected_root->post('/tool/pwdgen')->to('protected#pwdgen');

  $protected_root->get( '/tool/qrcode')->to('protected#qrcode');
  $protected_root->post('/tool/qrcode')->to('protected#qrcode');

  $protected_root->get( '/tool/keygen/ssh')->to('protected#keygen_ssh');
  $protected_root->post('/tool/keygen/ssh')->to('protected#keygen_ssh');

  $protected_root->get( '/tool/keygen/gpg')->to('protected#keygen_gpg');
  $protected_root->post('/tool/keygen/gpg')->to('protected#keygen_gpg');
  $protected_root->get( '/tool/keyimport/gpg')->to('protected#keyimport_gpg');
  $protected_root->post('/tool/keyimport/gpg')->to('protected#keyimport_gpg');

  $protected_root
    ->get( '/tool/sysinfo')
    ->requires(is_role => ['admin,coadmin,hr', {cmp => 'or'}])
    ->to('protected#sysinfo');

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
