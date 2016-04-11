package Mojolicious::Plugin::OAuth2::Server;

=head1 NAME

Mojolicious::Plugin::OAuth2::Server - Easier implementation of an OAuth2
Authorization Server / Resource Server with Mojolicious

=for html
<a href='https://travis-ci.org/G3S/mojolicious-plugin-oauth2-server?branch=master'><img src='https://travis-ci.org/G3S/mojolicious-plugin-oauth2-server.svg?branch=master' alt='Build Status' /></a>
<a href='https://coveralls.io/r/G3S/mojolicious-plugin-oauth2-server?branch=master'><img src='https://coveralls.io/repos/G3S/mojolicious-plugin-oauth2-server/badge.png?branch=master' alt='Coverage Status' /></a>

=head1 VERSION

0.23

=head1 SYNOPSIS

  use Mojolicious::Lite;

  plugin 'OAuth2::Server' => {
      ... # see CONFIGURATION
  };

  group {
    # /api - must be authorized
    under '/api' => sub {
      my ( $c ) = @_;

      return 1 if $c->oauth; # must be authorized via oauth

      $c->render( status => 401, text => 'Unauthorized' );
      return undef;
    };

    any '/annoy_friends' => sub { shift->render( text => "Annoyed Friends" ); };
    any '/post_image'    => sub { shift->render( text => "Posted Image" ); };
  };

  any '/track_location' => sub {
    my ( $c ) = @_;

    my $oauth_details = $c->oauth( 'track_location' )
        || return $c->render( status => 401, text => 'You cannot track location' );

    $c->render( text => "Target acquired: @{[$oauth_details->{user_id}]}" );
  };

  app->start;

Or full fat app:

  use Mojo::Base 'Mojolicious';

  ...

  sub startup {
    my $self = shift;

    ...

    $self->plugin( 'OAuth2::Server' => $oauth2_server_config );
  }

Then in your controller:

  sub my_route_name {
    my ( $c ) = @_;
 
    if ( my $oauth_details = $c->oauth( qw/required scopes/ ) ) {
      ... # do something, user_id, client_id, etc, available in $oauth_details
    } else {
      return $c->render( status => 401, text => 'Unauthorized' );
    }

    ...
  }

=head1 DESCRIPTION

This plugin implements the OAuth2 "Authorization Code Grant" flow as described
at L<http://tools.ietf.org/html/rfc6749#section-4.1>. It is not a complete
implementation of RFC6749, as that is rather large in scope. However the extra
functionality and flows may be added in the future.

This plugin enables you to easily (?) write an OAuth2 Authorization Server (AS)
and OAuth2 Resource Server (RS) using Mojolicious. It implements the required
flows and checks leaving you to add functions that are necessary, for example,
to verify an auth code (AC), access token (AT), etc.

In its simplest form you can call the plugin with just a hashref of known clients
and the code will "just work" - however in doing this you will not be able to
run a multi process persistent OAuth2 AS/RS as the known ACs and ATs will not be
shared between processes and will be lost on a restart.

To use this plugin in a more realistic way you need to at a minimum implement
the following functions and pass them to the plugin:

  login_resource_owner
  confirm_by_resource_owner
  verify_client
  store_auth_code
  verify_auth_code
  store_access_token
  verify_access_token

These will be explained in more detail below, in L<REQUIRED FUNCTIONS>, and you
can also see the tests and examples included with this distribution. OAuth2
seems needlessly complicated at first, hopefully this plugin will clarify the
various steps and simplify the implementation.

If you would still like to use the plugin in an easy way, but also have ACs and
ATs persistent across restarts and shared between multi processes then you can
supply a jwt_secret. What you lose when doing this is the ability for tokens to
be revoked. You could implement the verify_auth_code and verify_access_token
methods to handle the revoking in your app. So that would be halfway between
the "simple" and the "realistic" way. L<CLIENT SECRET, TOKEN SECURITY, AND JWT>
has more detail about JWTs.

Note that OAuth2 requires https, so you need to have the optional Mojolicious
dependency required to support it. Run the command below to check if
L<IO::Socket::SSL> is installed.

  $ mojo version

=head1 CONFIGURATION

The plugin takes several configuration options. To use the plugin in a realistic
way you need to pass several callbacks, documented in L<REQUIRED FUNCTIONS>, and
marked here with a *

=head2 jwt_secret

This is optional. If set JWTs will be returned for the auth codes, access, and
refresh tokens. JWTs allow you to validate tokens without doing a db lookup, but
there are certain considerations (see L<CLIENT SECRET, TOKEN SECURITY, AND JWT>)

=head2 authorize_route

The route that the Client calls to get an authorization code. Defaults to
GET /oauth/authorize

=head2 access_token_route

The route the the Client calls to get an access token. Defaults to
POST /oauth/access_token

=head2 auth_code_ttl

The validity period of the generated authorization code in seconds. Defaults to
600 seconds (10 minutes)

=head2 access_token_ttl

The validity period of the generated access token in seconds. Defaults to 3600
seconds (1 hour)

=head2 clients

A hashref of client details keyed like so:

  clients => {
    $client_id => {
      client_secret => $client_secret
      scopes        => {
        eat       => 1,
        drink     => 0,
        sleep     => 1,
      },
    },
  },

Note the clients config is not required if you add the verify_client callback,
but is necessary for running the plugin in its simplest form (when there are
*no* callbacks provided)

=head2 login_resource_owner *

A callback that tells the plugin if a Resource Owner (user) is logged in. See
L<REQUIRED FUNCTIONS>.

=head2 confirm_by_resource_owner *

A callback that tells the plugin if the Resource Owner allowed or disallowed
access to the Resource Server by the Client. See L<REQUIRED FUNCTIONS>.

=head2 verify_client *

A callback that tells the plugin if a Client is know and given the scopes is
allowed to ask for an authorization code. See L<REQUIRED FUNCTIONS>.

=head2 store_auth_code *

A callback to store the generated authorization code. See L<REQUIRED FUNCTIONS>.

=head2 verify_auth_code *

A callback to verify an authorization code. See L<REQUIRED FUNCTIONS>.

=head2 store_access_token *

A callback to store generated access / refresh tokens. See L<REQUIRED FUNCTIONS>.

=head2 verify_access_token *

A callback to verify an access token. See L<REQUIRED FUNCTIONS>.

=cut

use strict;
use warnings;
use base qw/ Mojolicious::Plugin /;

use Mojo::URL;
use Net::OAuth2::AuthorizationServer;

our $VERSION = '0.23';

my $args_as_hash;
my $Grant;

=head1 METHODS

=head2 register

Registers the plugin with your app - note that you must pass callbacks for
certain functions that the plugin expects to call if you are not using the
plugin in its simplest form.

  $self->register($app, \%config);

=head2 oauth

Checks if there is a valid Authorization: Bearer header with a valid access
token and if the access token has the requisite scopes. The scopes are optional:

  unless ( my $oauth_details = $c->oauth( @scopes ) ) {
    return $c->render( status => 401, text => 'Unauthorized' );
  }

=cut

sub register {
  my ( $self,$app,$config ) = @_;

  my $auth_route   = $config->{authorize_route}    // '/oauth/authorize';
  my $atoken_route = $config->{access_token_route} // '/oauth/access_token';
  $args_as_hash    = $config->{args_as_hash}       // 0; # zero for back compat

  $Grant = Net::OAuth2::AuthorizationServer->new->auth_code_grant(
    %{ $config },
    ( map { +"${_}_cb" => $config->{$_} } qw/
      verify_client store_auth_code verify_auth_code
      store_access_token verify_access_token
      login_resource_owner confirm_by_resource_owner
    / )
  );

  $app->routes->get(
    $auth_route => sub { _authorization_request( @_ ) },
  );

  $app->routes->post(
    $atoken_route => sub { _access_token_request( @_ ) },
  );

  $app->helper(
    oauth => sub {
      my $c = shift;
      my @scopes = @_;
      $Grant->legacy_args( $c ) if ! $args_as_hash;
      my @res = $Grant->verify_token_and_scope(
        scopes           => [ @scopes ],
        auth_header      => $c->req->headers->header( 'Authorization' ),
        mojo_controller  => $c,
      );
      return $res[0];
    },
  );
}

sub _authorization_request {
  my ( $self ) = @_;

  my ( $client_id,$uri,$type,$scope,$state )
    = map { $self->param( $_ ) // undef }
    qw/ client_id redirect_uri response_type scope state /;

  my @scopes = $scope ? split( / /,$scope ) : ();

  if (
    ! defined( $client_id )
    or ! defined( $type )
    or $type ne 'code'
  ) {
    $self->render(
      status => 400,
      json   => {
        error             => 'invalid_request',
        error_description => 'the request was missing one of: client_id, '
          . 'response_type;'
          . 'or response_type did not equal "code"',
        error_uri         => '',
      }
    );
    return;
  }

  $Grant->legacy_args( $self ) if ! $args_as_hash;

  my $mojo_url = Mojo::URL->new( $uri );
  my ( $res,$error ) = $Grant->verify_client(
    client_id       => $client_id,
    scopes          => [ @scopes ],
    mojo_controller => $self,
  );

  if ( $res ) {
    if ( ! $Grant->login_resource_owner( mojo_controller => $self ) ) {
      $self->app->log->debug( "OAuth2::Server: Resource owner not logged in" );
      # call to $resource_owner_logged_in method should have called redirect_to
      return;
    } else {
      $self->app->log->debug( "OAuth2::Server: Resource owner is logged in" );
      $res = $Grant->confirm_by_resource_owner(
        client_id       => $client_id,
        scopes          => [ @scopes ],
        mojo_controller => $self,
      );
      if ( ! defined $res ) {
        $self->app->log->debug( "OAuth2::Server: Resource owner to confirm scopes" );
        # call to $resource_owner_confirms method should have called redirect_to
        return;
      }
      elsif ( $res == 0 ) {
        $self->app->log->debug( "OAuth2::Server: Resource owner denied scopes" );
        $error = 'access_denied';
      }
    }
  }

  if ( $res ) {

    $self->app->log->debug( "OAuth2::Server: Generating auth code for $client_id" );
    my $auth_code = $Grant->token(
      client_id       => $client_id,
      scopes          => [ @scopes ],
      type            => 'auth',
      redirect_uri    => $uri,
    );

    $Grant->store_auth_code(
      auth_code       => $auth_code,
      client_id       => $client_id,
      expires_in      => $Grant->auth_code_ttl,
      redirect_uri    => $uri,
      scopes          => [ @scopes ],
      mojo_controller => $self,
    );

    $mojo_url->query->append( code  => $auth_code );

  } elsif ( $error ) {
    $mojo_url->query->append( error => $error );
  } else {
    # callback has not returned anything, assume server error
    $mojo_url->query->append(
      error             => 'server_error',
      error_description => 'call to verify_client returned unexpected value',
    );
  }

  $mojo_url->query->append( state => $state ) if defined( $state );

  $self->redirect_to( $mojo_url );
}

sub _access_token_request {
  my ( $self ) = @_;

  my ( $client_id,$client_secret,$grant_type,$auth_code,$uri,$refresh_token )
    = map { $self->param( $_ ) // undef }
    qw/ client_id client_secret grant_type code redirect_uri refresh_token /;

  if (
    ! defined( $grant_type )
    or ( $grant_type ne 'authorization_code' and $grant_type ne 'refresh_token' )
    or ( $grant_type eq 'authorization_code' and ! defined( $auth_code ) )
    or ( $grant_type eq 'authorization_code' and ! defined( $uri ) )
  ) {
    $self->render(
      status => 400,
      json   => {
        error             => 'invalid_request',
        error_description => 'the request was missing one of: grant_type, '
          . 'client_id, client_secret, code, redirect_uri;'
          . 'or grant_type did not equal "authorization_code" '
          . 'or "refresh_token"',
        error_uri         => '',
      }
    );
    return;
  }

  my $json_response = {};
  my $status        = 400;
  my ( $client,$error,$scope,$old_refresh_token,$user_id );

  $Grant->legacy_args( $self ) if ! $args_as_hash;

  if ( $grant_type eq 'refresh_token' ) {
    ( $client,$error,$scope,$user_id ) = $Grant->verify_token_and_scope(
      refresh_token    => $refresh_token,
      auth_header      => $self->req->headers->header( 'Authorization' ),
      mojo_controller  => $self,
    );
    $old_refresh_token = $refresh_token;
  } else {

    ( $client,$error,$scope,$user_id ) = $Grant->verify_auth_code(
      client_id       => $client_id,
      client_secret   => $client_secret,
      auth_code       => $auth_code,
      redirect_uri    => $uri,
      mojo_controller => $self,
    );
  }

  if ( $client ) {

    $self->app->log->debug( "OAuth2::Server: Generating access token for $client" );

    my $expires_in    = $Grant->access_token_ttl;
    my $access_token  = $Grant->token(
      client_id => $client,
      scopes    => $scope,
      type      => 'access',
      user_id   => $user_id,
    );

    my $refresh_token  = $Grant->token(
      client_id => $client,
      scopes    => $scope,
      type      => 'refresh',
      user_id   => $user_id,
    );

    $Grant->store_access_token(
      client_id         => $client,
      auth_code         => $auth_code,
      access_token      => $access_token,
      refresh_token     => $refresh_token,
      expires_in        => $expires_in,
      scopes            => $scope,
      old_refresh_token => $old_refresh_token,
      mojo_controller   => $self,
    );

    $status        = 200;
    $json_response = {
      access_token  => $access_token,
      token_type    => 'Bearer',
      expires_in    => $expires_in,
      refresh_token => $refresh_token,
    };

  } elsif ( $error ) {
      $json_response->{error} = $error;
  } else {
    # callback has not returned anything, assume server error
    $json_response = {
      error             => 'server_error',
      error_description => 'call to verify_auth_code returned unexpected value',
    };
  }

  $self->res->headers->header( 'Cache-Control' => 'no-store' );
  $self->res->headers->header( 'Pragma'        => 'no-cache' );

  $self->render(
    status => $status,
    json   => $json_response,
  );
}

1;

# vim: ts=2:sw=2:et
