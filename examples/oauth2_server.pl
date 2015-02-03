#!perl

use strict;
use warnings;

use Mojolicious::Lite;

plugin 'OAuth2::Server' => {
  clients              => {
    1 => {
      client_secret => 'boo',
      scopes        => {
        act => 1,
      },
    },
  },
};

group {
  # /api - must be authorized
  under '/api' => sub {
    my ( $c ) = @_;
    return 1 if $c->oauth;
    $c->render( status => 401, text => 'Unauthorized' );
    return undef;
  };

  any '/act' => sub { shift->render( text => "Acted" ); };
};

any '/play' => sub {
  my ( $c ) = @_;
  $c->oauth( 'play' )
      || return $c->render( status => 401, text => 'You cannot play' );
  $c->render( text => "Played" );
};

get '/' => sub {
  my ( $c ) = @_;
  $c->render( text => "Welcome" );
};

app->start;

# vim: ts=2:sw=2:et
