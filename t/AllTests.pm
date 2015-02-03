package AllTests;

use strict;
use warnings;

use Mojo::URL;
use Test::More;
use Test::Deep;
use Test::Mojo;

sub run {
  my ( $args ) = @_;

  my $auth_route  = $args->{authorize_route}    // '/oauth/authorize';
  my $token_route = $args->{access_token_route} // '/oauth/access_token';

  my %valid_auth_params = (
    client_id     => 1,
    client_secret => 'boo',
    response_type => 'code',
    redirect_uri  => 'https://client/cb',
    scope         => 'eat',
    state         => 'queasy',
  );

  # now the testing begins
  my $t = Test::Mojo->new;
  note( "authorization request" );

  note( " ... not authorized (missing params)" );
  foreach my $form_params (
    { client_secret => 'boo', response_type => 'code', },
    { client_id     => 1,     response_type => 'code', },
    { client_id     => 1,     client_secret => 'boo', },
  ) {
    $t->post_ok( $auth_route => form => $form_params )
      ->status_is( 400 )
      ->json_is( {
        error => 'invalid_request',
        error_description => 'the request was missing one of: client_id, '
          . 'client_secret, response_type;'
          . 'or response_type did not equal "code"',
        error_uri         => '',
      } )
    ;
  }

  note( " ... not authorized (errors)" );

  foreach my $invalid_params (
    { client_id     => 2,       error => 'unauthorized_client', },
    { client_secret => 'eek',   error => 'access_denied', },
    { scope         => 'cry',   error => 'invalid_scope', },
    { scope         => 'drink', error => 'access_denied', },
  ) {
    my $expected_error = delete( $invalid_params->{error} );
    $t->post_ok( $auth_route => form => {
        %valid_auth_params, %{ $invalid_params }
      } )
      ->status_is( 302 )
    ;

    my $location = Mojo::URL->new( $t->tx->res->headers->location );
    is( $location->path,'/cb','redirect to right place' );
    ok( ! $location->query->param( 'code' ),'no code' );
    is( $location->query->param( 'error' ),$expected_error,'expected error' );
  }

  $t->post_ok( $auth_route => form => \%valid_auth_params )
    ->status_is( 302 )
  ;

  note( " ... authorized" );
  my $location = Mojo::URL->new( $t->tx->res->headers->location );
  is( $location->path,'/cb','redirect to right place' );
  ok( my $auth_code = $location->query->param( 'code' ),'includes code' );
  is( $location->query->param( 'state' ),'queasy','includes state' );

  note( "access token" );

  my %valid_token_params = (
    grant_type   => 'authorization_code',
    code         => $auth_code,
    redirect_uri => $valid_auth_params{redirect_uri},
  );

  $t->post_ok( $token_route => form => \%valid_token_params )
    ->status_is( 200 )
    ->header_is( 'Cache-Control' => 'no-store' )
    ->header_is( 'Pragma'        => 'no-cache' )
  ;

  cmp_deeply(
    $t->tx->res->json,
    {
      access_token  => re( '^.{48,52}$' ),
      token_type    => 'bearer',
      expires_in    => '3600',
      refresh_token => re( '^.{48,52}$' ),
    },
    'json_is_deeply'
  );

  my $access_token  = $t->tx->res->json->{access_token};
  my $refresh_token = $t->tx->res->json->{refresh_token};

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

  note( "refresh access token" );

  my %valid_refresh_token_params = (
    grant_type    => 'refresh_token',
    refresh_token => $refresh_token,
    scope         => 'eat',
  );

  $t->post_ok( $token_route => form => \%valid_refresh_token_params )
    ->status_is( 200 )
    ->header_is( 'Cache-Control' => 'no-store' )
    ->header_is( 'Pragma'        => 'no-cache' )
  ;

  cmp_deeply(
    $t->tx->res->json,
    {
      access_token  => re( '^.{48,52}$' ),
      token_type    => 'bearer',
      expires_in    => '3600',
      refresh_token => re( '^.{48,52}$' ),
    },
    'json_is_deeply'
  );

  isnt( $t->tx->res->json->{access_token},$access_token,'new access_token' );
  isnt( $t->tx->res->json->{refresh_token},$refresh_token,'new refresh_token' );

  $access_token  = $t->tx->res->json->{access_token};
  $refresh_token = $t->tx->res->json->{refresh_token};

  $t->ua->on(start => sub {
    my ( $ua,$tx ) = @_;
    $tx->req->headers->header( 'Authorization' => "Bearer $access_token" );
  });

  $access_token  = $t->tx->res->json->{access_token};
  $refresh_token = $t->tx->res->json->{refresh_token};

  $t->get_ok('/api/eat')->status_is( 200 );
  $t->get_ok('/api/sleep')->status_is( 401 );

  note( "access token (2nd time with same auth code fails)" );

  $t->post_ok( $token_route => form => \%valid_token_params )
    ->status_is( 400 )
  ;

  note( " ... access revoked" );
  $t->get_ok('/api/eat')->status_is( 401 );
  $t->get_ok('/api/sleep')->status_is( 401 );

}

1;

# vim: ts=2:sw=2:et
