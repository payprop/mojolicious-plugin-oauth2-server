# NAME

Mojolicious::Plugin::OAuth2::Server - Easier implementation of an OAuth2
Authorization Server / Resource Server with Mojolicious

<div>

    <a href='https://travis-ci.org/leejo/mojolicious-plugin-oauth2-server?branch=master'><img src='https://travis-ci.org/leejo/mojolicious-plugin-oauth2-server.svg?branch=master' alt='Build Status' /></a>
    <a href='https://coveralls.io/r/leejo/mojolicious-plugin-oauth2-server?branch=master'><img src='https://coveralls.io/repos/leejo/mojolicious-plugin-oauth2-server/badge.png?branch=master' alt='Coverage Status' /></a>
</div>

# VERSION

0.01

# DESCRIPTION

This plugin enables you to easily (?) write an OAuth2 Authorization Server (AS)
and OAuth2 Resource Server (RS) using Mojolicious. It implements the necessary
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

These will be explained in more detail below, in ["REQUIRED FUNCTIONS"](#required-functions), and you
can also see the tests and examples included with this distribution. OAuth2
seems needlessly complicated at first, hopefully this plugin will clarify the
various steps and simplify the implementation.

Note that OAuth2 requires https, so you need to have the optional Mojolicious
dependency required to support it. Run the command below to check if
[IO::Socket::SSL](https://metacpan.org/pod/IO::Socket::SSL) is installed.

    $ mojo version

# SYNOPSIS

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

      $c->oauth( 'track_location' ) # must have track_location oauth scope
          || return $c->render( status => 401, text => 'You cannot track location' );

      $c->render( text => "Target acquired" );
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
    
       if ( ! $c->oauth( qw/required scopes to use this route/ ) ) {
         return $c->render( status => 401, text => 'Unauthorized' );
       }

       ...
     }

# CONFIGURATION

The plugin takes several configuration options. To use the plugin in a realistic
way you need to pass several callbacks, documented in ["REQUIRED FUNCTIONS"](#required-functions), and
marked here with a \*

## authorize\_route

The route that the Client calls to get an authorization code. Defaults to
GET /oauth/authorize

## access\_token\_route

The route the the Client calls to get an access token. Defaults to
POST /oauth/access\_token

## auth\_code\_ttl

The validity period of the generated authorization code in seconds. Defaults to
600 seconds (10 minutes)

## access\_token\_ttl

The validity period of the generated access token in seconds. Defaults to 3600
seconds (1 hour)

## clients

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

Note the clients config is not required if you add the verify\_client callback,
but is necessary for running the plugin in its simplest form (when there are
\*no\* callbacks provided)

## login\_resource\_owner \*

A callback that tells the plugin if a Resource Owner (user) is logged in. See
["REQUIRED FUNCTIONS"](#required-functions).

## confirm\_by\_resource\_owner \*

A callback that tells the plugin if the Resource Owner allowed or disallow
access to the Resource Server by the Client. See ["REQUIRED FUNCTIONS"](#required-functions).

## verify\_client \*

A callback that tells the plugin if a Client is know and given the scopes is
allowed to ask for an authorization code. See ["REQUIRED FUNCTIONS"](#required-functions).

## store\_auth\_code \*

A callback to store the generated authorization code. See ["REQUIRED FUNCTIONS"](#required-functions).

## verify\_auth\_code \*

A callback to verify an authorization code. See ["REQUIRED FUNCTIONS"](#required-functions).

## store\_access\_token \*

A callback to store generated access / refresh tokens. See ["REQUIRED FUNCTIONS"](#required-functions).

## verify\_access\_token \*

A callback to verify an access token. See ["REQUIRED FUNCTIONS"](#required-functions).

# METHODS

## register

Registers the plugin with your app - note that you must pass callbacks for
certain functions that the plugin expects to call

    $self->register($app, \%config);

## oauth

Checks if there is a valid Authorization: Bearer header with a valid access
token and if the access token has the requisite scopes. The scopes are optional:

    if ( ! $c->oauth( @scopes ) ) {
      return $c->render( status => 401, text => 'Unauthorized' );
    }

# REQUIRED FUNCTIONS

These are the callbacks necessary to use the plugin in a more realistic way, and
are required to make the auth code, access token, refresh token, etc available
across several processes and persistent.

The examples below use pseudocode for the code that would be bespoke to your
application - such as finding access codes in the database, and so on. You can
refer to the tests in t/ and examples in examples/ in this distribution for how
it could be done, but really you should be storing the data in a scalable and
persistent data store.

## login\_resource\_owner

A callback to tell the plugin if the Resource Owner is logged in. It is passed
the Mojolicious controller object. It should return 1 if the Resource Owner is
logged in, otherwise it should call the redirect\_to method on the controller
and return 0:

    my $resource_owner_logged_in_sub = sub {
      my ( $c ) = @_;

      if ( ! $c->session( 'logged_in' ) ) {
        # we need to redirect back to the /oauth/authorize route after
        # login (with the original params)
        my $uri = join( '?',$c->url_for('current'),$c->url_with->query );
        $c->flash( 'redirect_after_login' => $uri );
        $c->redirect_to( '/login' );
        return 0;
      }

      return 1;
    };

## confirm\_by\_resource\_owner

A callback to tell the plugin if the Resource Owner allowed or denied access to
the Resource Server by the Client. It is passed the Mojolicious controller
object, the client id, and an array reference of scopes requested by the client.

It should return 1 if access is allowed, 0 if access is not allow, otherwise it
should call the redirect\_to method on the controller and return undef:

    my $resource_owner_confirm_scopes_sub = sub {
      my ( $c,$client_id,$scopes_ref ) = @_;

      my $is_allowed = $c->flash( "oauth_${client_id}" );

      # if user hasn't yet allowed the client access, or if they denied
      # access last time, we check [again] with the user for access
      if ( ! $is_allowed ) {
        $c->flash( client_id => $client_id );
        $c->flash( scopes    => $scopes_ref );

        my $uri = join( '?',$c->url_for('current'),$c->url_with->query );
        $c->flash( 'redirect_after_login' => $uri );
        $c->redirect_to( '/confirm_scopes' );
      }

      return $is_allowed;
    };

## verify\_client

Reference: [http://tools.ietf.org/html/rfc6749#section-4.1.1](http://tools.ietf.org/html/rfc6749#section-4.1.1)

A callback to verify if the client asking for an authorization code is known
to the Resource Server and allowed to get an authorization code for the passed
scopes.

The callback is passed the Mojolicious controller object, the client id, and an
array reference of request scopes.  The callback should return a list with two
elements. The first element is either 1 or 0 to say that the client is allowed
or disallowed, the second element should be the error message in the case of the
client being disallowed:

    my $verify_client_sub = sub {
      my ( $c,$client_id,$scopes_ref ) = @_;

      # get client info from the database
      if ( $client = _load_client_data( $client_id ) ) {

          foreach my $scope ( @{ $scopes_ref // [] } ) {

            if ( ! exists( $client->{scopes}{$scope} ) ) {
              $c->app->log->debug( "Client lacks scope ($scope)" );
              return ( 0,'invalid_scope' );
            } elsif ( ! $client->{scopes}{$scope} ) {
              $c->app->log->debug( "Client cannot scope ($scope)" );
              return ( 0,'access_denied' );
            }
          }

          return ( 1 );
      }

      $c->app->log->debug( "Client ($client_id) does not exist" );
      return ( 0,'unauthorized_client' );
    };

## store\_auth\_code

A callback to allow you to store the generated authorization code. The callback
is passed the Mojolicious controller object, the generated auth code, the client
id, the time the auth code expires (seconds since Unix epoch), the Client
redirect URI, and a list of the scopes requested by the Client.

You should save the information to your data store, it can then be retrieved by
the verify\_auth\_code callback for verification:

    my $store_auth_code_sub = sub {
      my ( $c,$auth_code,$client_id,$expires_at,$uri,@scopes ) = @_;

      my $user_id = $c->session( 'user_id' );

      my $auth_code_rs = $c->db->resultset( 'AuthCode' )->create({
        client_id     => $client_id,
        user_id       => $user_id,
        auth_code     => $auth_code,
        expires       => $expires_at,
        redirect_uri  => $uri,
      });

      foreach my $scope ( @scopes ) {
        $auth_code_rs->create_related( 'auth_code_scope',$scope );
      }

      return;
    };

## verify\_auth\_code

Reference: [http://tools.ietf.org/html/rfc6749#section-4.1.3](http://tools.ietf.org/html/rfc6749#section-4.1.3)

A callback to verify the authorization code passed from the Client to the
Authorization Server. The callback is passed the Mojolicious controller object,
the client\_id, the client\_secret, the authorization code, and the redirect uri.

The callback should verify the authorization code using the rules defined in
the reference RFC above, and return a list with 3 elements. The first element
should be a client identifier (a scalar, or reference) in the case of a valid
authorization code or 0 in the case of an invalid authorization code. The second
element should be the error message in the case of an invalid authorization
code. The third element should be a hash reference of scopes as requested by the
client in the original call for an authorization code:

    my $verify_auth_code_sub = sub {
      my ( $c,$client_id,$client_secret,$auth_code,$uri ) = @_;

      my $auth_code = $c->db->resultset( 'AuthCode' )->search({
        client_id    => $client_id,
        auth_code    => $auth_code,
      });

      $auth_code || return ( 0,'unauthorized_client' );

      return ( 0,'invalid_grant' )
        if ( $auth_code->client->secret ne $client_secret );

      if (
        $auth_code->verified
        or $auth_code->revoked
        or $auth_code->redirect_uri ne $uri
        or $auth_code->expires <= time
      ) {

        if ( $auth_code->verified ) {
          # the auth code has been used before, revoke auth code and access tokens
          $auth_code->revoked( 1 );

          foreach my $access_token( @{ $auth_code->access_token->all // [] } ) {
            $access_token->revoked( 1 );
            $access_token->update;
          }

          $auth_code->update;
        }

        return ( 0,'invalid_grant' );
      }

      $auth_code->verified( 1 );
      $auth_code->update;

      # scopes are those that were requested in the authorization request, not
      # those stored in the client (i.e. what the auth request restriced scopes
      # to and not everything the client is capable of)
      my %scopes = map { $_ => 1 } @{ $auth_code->scopes->all // [] };

      return ( $client_id,undef,\%scopes );
    };

## store\_access\_token

A callback to allow you to store the generated access and refresh tokens. The
callback is passed the Mojolicious controller object, the client identifier as
returned from the verify\_auth\_code callback, the authorization code, the access
token, the refresh\_token, the validity period in seconds, and the scope returned
from the verify\_auth\_code callback.

Note that the passed authorization code could be undefined, in which case the
access token and refresh tokens were requested by the Client by the use of an
existing refresh token. In this case you should revoke the existing access and
refresh tokens.

The callback does not need to return anything.

You should save the information to your data store, it can then be retrieved by
the verify\_auth\_code callback for verification:

    my $store_access_token_sub = sub {
      my (
        $c,$client,$auth_code,$access_token,$refresh_token,$expires_in,$scope
      ) = @_;

      return;
    };

## verify\_access\_token

Reference: [http://tools.ietf.org/html/rfc6749#section-7](http://tools.ietf.org/html/rfc6749#section-7)

A callback to verify the acccess token. The callback is passed the Mojolicious
controller object, the access token, and an optional reference to a list of the
scopes.

The callback should verify the authorization code using the rules defined in
the reference RFC above, and return either 1 for a valid access token or 0 for
an invalid access token.

    my $verify_access_token_sub = sub {
      my ( $c,$access_token,$scopes_ref ) = @_;

      return 0;
    };

# REFERENCES

- [http://oauth.net/documentation/](http://oauth.net/documentation/)
- [http://tools.ietf.org/html/rfc6749](http://tools.ietf.org/html/rfc6749)

# SEE ALSO

[Mojolicious::Plugin::OAuth2](https://metacpan.org/pod/Mojolicious::Plugin::OAuth2) - A client side OAuth2 Mojolicious plugin

# AUTHOR

Lee Johnson - `leejo@cpan.org`

# LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. If you would like to contribute documentation
please raise an issue / pull request:

    https://github.com/leejo/mojolicious-plugin-oauth2-server
