#!perl

use strict;
use warnings;

use Mojolicious::Lite;
use Mojo::URL;
use Test::Mojo;
use Test::More;

my $t       = Test::Mojo->new;
my $app_url = $t->ua->server->url;
my $host    = $app_url->host;
my $port    = $app_url->port;

# plugin configuration
plugin 'OAuth2::Server' => {
  verify_client        => sub {
    my ( $client_id,$client_secret,$scope_ref ) = @_;
    return 1;
  },
  store_client_id      => sub { 1 },
  store_client_secret  => sub { 1 },
  scopes_for_client_id => sub { qw/ tweet post / },
  store_auth_code      => sub { 1 },
  verify_access_token  => sub { 1 },
};

# now the testing begins
note( "authorization request" );
$t->get_ok( '/oauth/authorize?'
  . join( '&',
      'client_id=1',
      'client_secret=boo',
      'response_type=code',
      'redirect_uri=https://nuts/nuts',
      'scope=that%27s+a+lot+of+nuts',
      'state=queasy',
    )
  )
  ->status_is( 302 )
;

my $location = Mojo::URL->new( $t->tx->res->headers->location );
note( $location );
is( $location->path,'/nuts','redirect to right place' );
ok( $location->query->param( 'code' ),'includes code' );
is( $location->query->param( 'state' ),'queasy','includes state' );

foreach my $q_string (
  'client_secret=boo&response_type=code',
  'client_id=1&response_type=code',
  'client_id=1&client_secret=boo',
) {
  $t->get_ok( '/oauth/authorize?',$q_string )
    ->status_is( 400 )
    ->json_is( { error => 'invalid_request' } )
  ;
}

done_testing();

# vim: ts=2:sw=2:et
