#!perl

use strict;
use warnings;

use Mojolicious::Lite;
use Test::More;
use Test::Mojo;
use Encode qw( encode );
use Mojo::Util qw( b64_encode );

# Based on VSCHAR definition in RFC 6749
my $secret = encode('UTF-8', join('', map { chr } 0x20 .. 0x7e));

MOJO_APP: {
  # plugin configuration
  plugin 'OAuth2::Server' => {
    clients => {
      boo => {
        client_secret => $secret,
        scopes => {},
      },
    },
  };
};

my $t = Test::Mojo->new;
$t->post_ok(
  "/oauth/access_token",
  { Authorization => "Basic @{[ b64_encode(qq{boo:$secret}, '') ]}" },
  form => { grant_type => 'client_credentials' }
)->status_is(200);

done_testing;
