#!perl

use strict;
use warnings;

use Mojolicious::Lite;
use Test::More;
use Test::Exception;

throws_ok(
  sub { plugin 'OAuth2::Server' => {}; },
  qr/OAuth2::Server config must provide either clients or overrides/,
  'plugin with no config croaks',
);

done_testing();

# vim: ts=2:sw=2:et
