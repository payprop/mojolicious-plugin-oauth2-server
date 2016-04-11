package Mojolicious::Plugin::OAuth2::Server;

=head1 NAME

Mojolicious::Plugin::OAuth2::Server - Easier implementation of an OAuth2
Authorization Server / Resource Server with Mojolicious

=for html
<a href='https://travis-ci.org/G3S/mojolicious-plugin-oauth2-server?branch=master'><img src='https://travis-ci.org/G3S/mojolicious-plugin-oauth2-server.svg?branch=master' alt='Build Status' /></a>
<a href='https://coveralls.io/r/G3S/mojolicious-plugin-oauth2-server?branch=master'><img src='https://coveralls.io/repos/G3S/mojolicious-plugin-oauth2-server/badge.png?branch=master' alt='Coverage Status' /></a>

=head1 VERSION

0.24

=head1 SYNOPSIS

  use Mojolicious::Lite;

  plugin 'OAuth2::Server' => {
      ... # see SYNOPSIS in Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant
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

    $self->plugin( 'OAuth2::Server' => $oauth2_auth_code_grant_config );
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

The bulk of the functionality is implemented in the L<Net::OAuth2::AuthorizationServer>
distribution, you should see that for more comprehensive documentation and
examples of usage.

=cut

use strict;
use warnings;
use base qw/ Mojolicious::Plugin /;

use Mojo::URL;
use Net::OAuth2::AuthorizationServer;

our $VERSION = '0.24';

my $args_as_hash;
my $Grant;

=head1 METHODS

=head2 register

Registers the plugin with your app - note that you must pass callbacks for
certain functions that the plugin expects to call if you are not using the
plugin in its simplest form.

  $self->register($app, \%config);

Registering the plugin will call the L<Net::OAuth2::AuthorizationServer>
and create a C<auth_code_grant> that can be accessed using the defined
C<authorize_route> and C<access_token_route>. The arguments passed to the
plugin are passed straight through to the C<auth_code_grant> method in
the L<Net::OAuth2::AuthorizationServer> module.

Note to support backwards compatibility arguments will be passed to the
callbacks (as detailed in L<Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant>)
as a flat list (not a hash). If you wish to receive the arguments as a
hash in the callbacks then pass args_as_hash => 1 to the plugin here.

=head2 oauth

Checks if there is a valid Authorization: Bearer header with a valid access
token and if the access token has the requisite scopes. The scopes are optional:

  unless ( my $oauth_details = $c->oauth( @scopes ) ) {
    return $c->render( status => 401, text => 'Unauthorized' );
  }

This calls the L<Net::OAuth2::AuthorizationServer::AuthorizationCodeGrant>
module (C<verify_token_and_scope> method) to validate the access/refresh token.

=cut

sub register {
  my ( $self,$app,$config ) = @_;

  my $auth_route   = $config->{authorize_route}    // '/oauth/authorize';
  my $atoken_route = $config->{access_token_route} // '/oauth/access_token';
  $args_as_hash    = $config->{args_as_hash}       // 0; # zero for back compat

  $Grant = Net::OAuth2::AuthorizationServer->new->auth_code_grant(
    ( map { +"${_}_cb" => ( $config->{$_} // undef ) } qw/
      verify_client store_auth_code verify_auth_code
      store_access_token verify_access_token
      login_resource_owner confirm_by_resource_owner
    / ),
    %{ $config },
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

=head1 SEE ALSO

L<Net::OAuth2::AuthorizationServer> - The dist that handles the bulk of the
functionality used by this plugin

=head1 AUTHOR

Lee Johnson - C<leejo@cpan.org>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. If you would like to contribute documentation
or file a bug report then please raise an issue / pull request:

    https://github.com/G3S/net-oauth2-authorizationserver

=cut

1;

# vim: ts=2:sw=2:et
