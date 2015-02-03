#!perl

use strict;
use warnings;

use Mojolicious::Lite;

plugin 'OAuth2', {
  oauth2_test_server => {
     authorize_url => 'https://127.0.0.1:3000/oauth/authorize?response_type=code',
     token_url     => 'https://127.0.0.1:3000/oauth/access_token',
     key           => 1,
     secret        => 'boo',
     scope         => 'act',
  },
};

get '/' => sub {
  my ( $c ) = @_;
  $c->render( text => "Client" );
};

get '/auth' => sub {
  my $self = shift;
  $self->delay(
    sub {
      my $delay = shift;
      $self->get_token( oauth2_test_server => $delay->begin )
    },
    sub {
      my( $delay,$token,$tx ) = @_;
      return $self->render( json => $tx->res->json )  if ! $token;
      return $self->render( text => $token );
    },
  );
};

app->start;

# vim: ts=2:sw=2:et
