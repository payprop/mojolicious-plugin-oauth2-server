#!perl

use strict;
use warnings;

use Mojolicious::Lite;
use Test::More;
use FindBin qw/ $Bin /;
use lib $Bin;
use AllTests;

my $verify_client_sub = sub {
  my ( $c,$client_id,$client_secret,$scopes_ref ) = @_;

  # in reality we would check a config file / the database to confirm the
  # client_id and client_secret match and that the scopes are valid
  return ( 0,'access_denied' ) if $client_secret ne 'boo';
  return ( 0,'invalid_scope' ) if grep { $_ eq 'cry' } @{ $scopes_ref // [] };
  return ( 0,'access_denied' ) if grep { $_ eq 'drink' } @{ $scopes_ref // [] };
  return ( 0,'unauthorized_client' ) if $client_id ne '1';

  # all good
  return ( 1,undef );
};

MOJO_APP: {
  # plugin configuration
  plugin 'OAuth2::Server' => {
    verify_client => $verify_client_sub,
  };

  group {
    # /api - must be authorized
    under '/api' => sub {
      my ( $c ) = @_;
      return 1 if $c->oauth;
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

AllTests::run({});

done_testing();

# vim: ts=2:sw=2:et
