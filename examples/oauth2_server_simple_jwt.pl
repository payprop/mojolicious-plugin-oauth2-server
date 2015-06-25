#!perl

use strict;
use warnings;

use Mojolicious::Lite;
use Mojo::JWT;
use Try::Tiny;

my $jwt_secret     = "Is it secret?, Is it safe?";
my $oauth2_clients = {
  TrendyNewService => {
    client_secret => 'boo',
    scopes        => {
      "post_images"   => 1,
      "annoy_friends" => 1,
    },
  },
};

my $verify_auth_code_sub = sub {
  my ( $c,$client_id,$client_secret,$auth_code,$uri ) = @_;

  my $client = $oauth2_clients->{$client_id}
    || return ( 0,'unauthorized_client' );

  return ( 0,'invalid_grant' )
    if ( $client_secret ne $client->{client_secret} );

  my $auth_code_payload;

  try {
    $auth_code_payload = Mojo::JWT->new( secret => $jwt_secret )
      ->decode( $auth_code );
  } catch {
    chomp;
    $c->app->log->error( 'OAuth2::Server Auth code: ' . $_ );
    return ( 0,'invalid_grant' );
  };

  if (
    ! $auth_code_payload
    or $auth_code_payload->{type} ne 'auth'
    or $auth_code_payload->{client} ne $client_id
    or ( $uri && $auth_code_payload->{aud} ne $uri )
  ) {
    return ( 0,'invalid_grant' );
  }

  # scopes are those that were requested in the authorization request, not
  # those stored in the client (i.e. what the auth request restriced scopes
  # to and not everything the client is capable of)
  my $scope = $auth_code_payload->{scopes};

  # some user id - $c->session( 'user_id' ) or whatever your equivalent is
  return ( $client_id,undef,$scope,'some user id' );
};

my $verify_access_token_sub = sub {
  my ( $c,$access_token,$scopes_ref,$is_refresh_token ) = @_;

  my $access_token_payload;

  try {
    $access_token_payload = Mojo::JWT->new( secret => $jwt_secret )
      ->decode( $access_token );
  } catch {
    chomp;
    $c->app->log->error( 'OAuth2::Server Access token: ' . $_ );
    return ( 0,'invalid_grant' );
  };

  if ( $access_token_payload ) {

    if ( $scopes_ref ) {
      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if ( ! grep { $_ eq $scope } @{ $access_token_payload->{scopes} } ) {
          $c->app->log->debug(
            "OAuth2::Server: Access token does not have scope ($scope)"
          );
          return ( 0,'invalid_grant' );
        }
      }
    }

    return $access_token_payload;
  }

  $c->app->log->debug( "OAuth2::Server: Access token does not exist" );
  return 0;
};

plugin 'OAuth2::Server' => {
  jwt_secret          => $jwt_secret,
  # because we are using JWTs in this example we only need
  # to verify codes/tokens and don't need to store them
  verify_auth_code    => $verify_auth_code_sub,
  verify_access_token => $verify_access_token_sub,
  store_auth_code     => sub {},
  store_access_token  => sub {},
  clients             => $oauth2_clients,
};

group {
  # /api - must be authorized
  under '/api' => sub {
    my ( $c ) = @_;
    return 1 if $c->oauth;
    $c->render( status => 401, text => 'Unauthorized' );
    return undef;
  };

  any '/annoy_friends' => sub { shift->render( text => "Annoyed Friends" ); };
  any '/post_image'    => sub { shift->render( text => "Posted Image" ); };

};

any '/api/track_location' => sub {
  my ( $c ) = @_;
  $c->oauth( 'track_location' )
      || return $c->render( status => 401, text => 'You cannot track location' );
  $c->render( text => "Target acquired" );
};

get '/' => sub {
  my ( $c ) = @_;
  $c->render( text => "Welcome to Overly Attached Social Network" );
};

app->start;

# vim: ts=2:sw=2:et
