#!perl

use strict;
use warnings;

use Mojolicious::Lite;
use Mojo::Util qw/ b64_encode url_unescape /;
use Test::More;
use Test::Mojo;
use Mojo::URL;

my $VALID_ACCESS_TOKEN;

my $verify_client_sub = sub {
  my ( %args ) = @_;
  # in reality we would check a config file / the database to confirm the
  # client_id and client_secret match and that the scopes are valid
  return ( 1,undef );
};


my $store_access_token_sub = sub {
  my ( %args ) = @_;
  $VALID_ACCESS_TOKEN = $args{access_token};

  # again, store stuff in the database
  return;
};

my $verify_access_token_sub = sub {
  my ( %args ) = @_;

  my ( $c,$access_token,$scopes_ref,$is_refresh_token )
  	= @args{qw/ mojo_controller access_token scopes is_refresh_token /};

  # and here we should check the access code is valid, not expired, and the
  # passed scopes are allowed for the access token
  if ( @{ $scopes_ref // [] } ) {
    return 0 if grep { $_ eq 'sleep' } @{ $scopes_ref // [] };
  }

  # this will only ever allow one access token - for the purposes of testing
  # that when a refresh token is used the previous access token is revoked
  return 0 if $access_token ne $VALID_ACCESS_TOKEN;

  my $client_id = 1;

  return { client_id => $client_id };
};

MOJO_APP: {
  # plugin configuration
  plugin 'OAuth2::Server' => {
    args_as_hash        => 0,
    authorize_route     => '/o/auth',
    verify_client       => $verify_client_sub,
    store_access_token  => $store_access_token_sub,
    verify_access_token => $verify_access_token_sub,
  };

  get '/foo' => sub {
    my ( $c ) = @_;

    my $redirect_uri = $c->oauth2_auth_request({
      client_id     => 'Foo',
	  redirect_uri  => 'foo://wee',
	  response_type => 'token',
	});

    $c->render( text => $redirect_uri );
  };

  group {
    # /api - must be authorized
    under '/api' => sub {
      my ( $c ) = @_;
      return 1 if $c->oauth && $c->oauth->{client_id};
      $c->render( status => 401, text => 'Unauthorized' );
      return undef;
    };

    get '/eat' => sub { shift->render( text => "food"); };
  };

  # /sleep - must be authorized and have sleep scope
  get '/api/sleep' => sub {
    my ( $c ) = @_;
    $c->oauth( 'sleep' )
      || $c->render( status => 401, text => 'You cannot sleep' );

    $c->render( text => "bed" );
  };
};

my $t = Test::Mojo->new;
$t->get_ok( '/foo' )
  ->status_is( 200 )
  ->content_like( qr!^foo://wee#access_token=([^&]*)&token_type=bearer&expires_in=3600$! )
;

my $url = Mojo::URL->new( $t->tx->res->content->get_body_chunk );

my $fragment = $url->fragment;
ok( my ( $access_token ) = ( $fragment =~ qr/access_token=([^&]*)/ ),'includes token' );
$access_token = url_unescape( $access_token );

note( "don't use access token to access route" );
$t->get_ok('/api/eat')->status_is( 401 );
$t->get_ok('/api/sleep')->status_is( 401 );

note( "use access token to access route" );

$t->ua->on(start => sub {
  my ( $ua,$tx ) = @_;
  $tx->req->headers->header( 'Authorization' => "Bearer $access_token" );
});

$t->get_ok('/api/eat')->status_is( 200 );
$t->get_ok('/api/sleep')->status_is( 401 );

done_testing();

# vim: ts=2:sw=2:et
