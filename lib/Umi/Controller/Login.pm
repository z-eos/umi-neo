package Umi::Controller::Login;
use Mojo::Base 'Mojolicious::Controller', -signatures;

sub index ($c) {
  my $user = $c->param('user') || '';
  my $pass = $c->param('pass') || '';

  # $c->renderer->default_handler('tt_renderer');
  return $c->render unless $c->users->check($user, $pass);

  $c->session(user => $user);
  $c->flash(message => 'Thanks for logging in.');
  $c->redirect_to('protected');
}

sub logged_in ($c) {
  return 1 if $c->session('user');
  $c->redirect_to('index');
  return undef;
}

sub logout ($c) {
  $c->session(expires => 1);
  $c->redirect_to('index');
}

1;
