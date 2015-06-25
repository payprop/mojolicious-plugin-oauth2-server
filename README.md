# NAME

Mojolicious::Plugin::OAuth2::Server - Easier implementation of an OAuth2
Authorization Server / Resource Server with Mojolicious

<div>

    <a href='https://travis-ci.org/leejo/mojolicious-plugin-oauth2-server?branch=master'><img src='https://travis-ci.org/leejo/mojolicious-plugin-oauth2-server.svg?branch=master' alt='Build Status' /></a>
    <a href='https://coveralls.io/r/leejo/mojolicious-plugin-oauth2-server?branch=master'><img src='https://coveralls.io/repos/leejo/mojolicious-plugin-oauth2-server/badge.png?branch=master' alt='Coverage Status' /></a>
</div>

# VERSION

0.20

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

# DESCRIPTION

This plugin implements the OAuth2 "Authorization Code Grant" flow as described
at [http://tools.ietf.org/html/rfc6749#section-4.1](http://tools.ietf.org/html/rfc6749#section-4.1). It is not a complete
implementation of RFC6749, as it is rather large in scope. However the extra
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

These will be explained in more detail below, in ["REQUIRED FUNCTIONS"](#required-functions), and you
can also see the tests and examples included with this distribution. OAuth2
seems needlessly complicated at first, hopefully this plugin will clarify the
various steps and simplify the implementation.

Note that OAuth2 requires https, so you need to have the optional Mojolicious
dependency required to support it. Run the command below to check if
[IO::Socket::SSL](https://metacpan.org/pod/IO::Socket::SSL) is installed.

    $ mojo version

# CONFIGURATION

The plugin takes several configuration options. To use the plugin in a realistic
way you need to pass several callbacks, documented in ["REQUIRED FUNCTIONS"](#required-functions), and
marked here with a \*

## jwt\_secret

This is optional. If set JWTs will be returned for the auth codes, access, and
refresh tokens. JWTs allow you to validate tokens without doing a db lookup, but
there are certain considerations (see ["CLIENT SECRET, TOKEN SECURITY, AND JWT"](#client-secret-token-security-and-jwt))

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

A callback that tells the plugin if the Resource Owner allowed or disallowed
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
certain functions that the plugin expects to call if you are not using the
plugin in its simplest form.

    $self->register($app, \%config);

## oauth

Checks if there is a valid Authorization: Bearer header with a valid access
token and if the access token has the requisite scopes. The scopes are optional:

    unless ( my $oauth_details = $c->oauth( @scopes ) ) {
      return $c->render( status => 401, text => 'Unauthorized' );
    }

# REQUIRED FUNCTIONS

These are the callbacks necessary to use the plugin in a more realistic way, and
are required to make the auth code, access token, refresh token, etc available
across several processes and persistent.

The examples below use monogodb (a db helper returns a MongoDB::Database object)
for the code that would be bespoke to your application - such as finding access
codes in the database, and so on. You can refer to the tests in t/ and examples
in examples/ in this distribution for how it could be done and to actually play
around with the code both in a browser and on the command line.

Also note that the examples below have no logging, you should probably make sure
to $c->log->debug (or warn/error) when falling through to the various code paths
to make debugging somewhat easier. The examples below don't have logging so the
code is shorter/clearer

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
        $c->redirect_to( '/oauth/login' );
        return 0;
      }

      return 1;
    };

Note that you need to pass on the current url (with query) so it can be returned
to after the user has logged in. You can see that the flash is in use here - be
aware that the default routes (if you don't pass them in the plugin config) for
authorize and access\_token are under /oauth/ so it is possible that the flash may
have a Path of /oauth/ - the consequence of this is that if your login route is
under a different path (likely) you will not be able to access the value you set in
the flash. The solution to this? Simply create another route under /oauth/ (so in
this case /oauth/login) that points to the same route as the /login route

## confirm\_by\_resource\_owner

A callback to tell the plugin if the Resource Owner allowed or denied access to
the Resource Server by the Client. It is passed the Mojolicious controller
object, the client id, and an array reference of scopes requested by the client.

It should return 1 if access is allowed, 0 if access is not allowed, otherwise
it should call the redirect\_to method on the controller and return undef:

    my $resource_owner_confirm_scopes_sub = sub {
      my ( $c,$client_id,$scopes_ref ) = @_;

      my $is_allowed = $c->flash( "oauth_${client_id}" );

      # if user hasn't yet allowed the client access, or if they denied
      # access last time, we check [again] with the user for access
      if ( ! $is_allowed ) {
        $c->flash( client_id => $client_id );
        $c->flash( scopes    => $scopes_ref );

        # we need to redirect back to the /oauth/authorize route after
        # confirm/deny by resource owner (with the original params)
        my $uri = join( '?',$c->url_for('current'),$c->url_with->query );
        $c->flash( 'redirect_after_login' => $uri );
        $c->redirect_to( '/oauth/confirm_scopes' );
      }

      return $is_allowed;
    };

Note that you need to pass on the current url (with query) so it can be returned
to after the user has confirmed/denied access, and the confirm/deny result is
stored in the flash (this could be stored in the user session if you do not want
the user to confirm/deny every single time the Client requests access). Also note
the caveat regarding flash and Path as documented above ([login\_resource\_owner](https://metacpan.org/pod/login_resource_owner))

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

      if (
        my $client = $c->db->get_collection( 'clients' )
          ->find_one({ client_id => $client_id })
      ) {
          foreach my $scope ( @{ $scopes_ref // [] } ) {

            if ( ! exists( $client->{scopes}{$scope} ) ) {
              return ( 0,'invalid_scope' );
            } elsif ( ! $client->{scopes}{$scope} ) {
              return ( 0,'access_denied' );
            }
          }

          return ( 1 );
      }

      return ( 0,'unauthorized_client' );
    };

## store\_auth\_code

A callback to allow you to store the generated authorization code. The callback
is passed the Mojolicious controller object, the generated auth code, the client
id, the auth code validity period in seconds, the Client redirect URI, and a list
of the scopes requested by the Client.

You should save the information to your data store, it can then be retrieved by
the verify\_auth\_code callback for verification:

    my $store_auth_code_sub = sub {
      my ( $c,$auth_code,$client_id,$expires_in,$uri,@scopes ) = @_;

      my $auth_codes = $c->db->get_collection( 'auth_codes' );

      my $id = $auth_codes->insert({
        auth_code    => $auth_code,
        client_id    => $client_id,
        user_id      => $c->session( 'user_id' ),
        expires      => time + $expires_in,
        redirect_uri => $uri,
        scope        => { map { $_ => 1 } @scopes },
      });

      return;
    };

## verify\_auth\_code

Reference: [http://tools.ietf.org/html/rfc6749#section-4.1.3](http://tools.ietf.org/html/rfc6749#section-4.1.3)

A callback to verify the authorization code passed from the Client to the
Authorization Server. The callback is passed the Mojolicious controller object,
the client\_id, the client\_secret, the authorization code, and the redirect uri.

The callback should verify the authorization code using the rules defined in
the reference RFC above, and return a list with 4 elements. The first element
should be a client identifier (a scalar, or reference) in the case of a valid
authorization code or 0 in the case of an invalid authorization code. The second
element should be the error message in the case of an invalid authorization
code. The third element should be a hash reference of scopes as requested by the
client in the original call for an authorization code. The fourth element should
be a user identifier:

    my $verify_auth_code_sub = sub {
      my ( $c,$client_id,$client_secret,$auth_code,$uri ) = @_;

      my $auth_codes      = $c->db->get_collection( 'auth_codes' );
      my $ac              = $auth_codes->find_one({
        client_id => $client_id,
        auth_code => $auth_code,
      });

      my $client = $c->db->get_collection( 'clients' )
        ->find_one({ client_id => $client_id });

      $client || return ( 0,'unauthorized_client' );

      if (
        ! $ac
        or $ac->{verified}
        or ( $uri ne $ac->{redirect_uri} )
        or ( $ac->{expires} <= time )
        or ( $client_secret ne $client->{client_secret} )
      ) {

        if ( $ac->{verified} ) {
          # the auth code has been used before - we must revoke the auth code
          # and access tokens
          $auth_codes->remove({ auth_code => $auth_code });
          $c->db->get_collection( 'access_tokens' )->remove({
            access_token => $ac->{access_token}
          });
        }

        return ( 0,'invalid_grant' );
      }

      # scopes are those that were requested in the authorization request, not
      # those stored in the client (i.e. what the auth request restriced scopes
      # to and not everything the client is capable of)
      my $scope = $ac->{scope};

      $auth_codes->update( $ac,{ verified => 1 } );

      return ( $client_id,undef,$scope,$ac->{user_id} );
    };

## store\_access\_token

A callback to allow you to store the generated access and refresh tokens. The
callback is passed the Mojolicious controller object, the client identifier as
returned from the verify\_auth\_code callback, the authorization code, the access
token, the refresh\_token, the validity period in seconds, the scope returned
from the verify\_auth\_code callback, and the old refresh token,

Note that the passed authorization code could be undefined, in which case the
access token and refresh tokens were requested by the Client by the use of an
existing refresh token, which will be passed as the old refresh token variable.
In this case you should use the old refresh token to find out the previous
access token and revoke the previous access and refresh tokens (this is \*not\* a
hard requirement according to the OAuth spec, but i would recommend it).

The callback does not need to return anything.

You should save the information to your data store, it can then be retrieved by
the verify\_access\_token callback for verification:

    my $store_access_token_sub = sub {
      my (
        $c,$client,$auth_code,$access_token,$refresh_token,
        $expires_in,$scope,$old_refresh_token
      ) = @_;

      my $access_tokens  = $c->db->get_collection( 'access_tokens' );
      my $refresh_tokens = $c->db->get_collection( 'refresh_tokens' );

      my $user_id;

      if ( ! defined( $auth_code ) && $old_refresh_token ) {
        # must have generated an access token via refresh token so revoke the old
        # access token and refresh token (also copy required data if missing)
        my $prev_rt = $c->db->get_collection( 'refresh_tokens' )->find_one({
          refresh_token => $old_refresh_token,
        });

        my $prev_at = $c->db->get_collection( 'access_tokens' )->find_one({
          access_token => $prev_rt->{access_token},
        });

        # access tokens can be revoked, whilst refresh tokens can remain so we
        # need to get the data from the refresh token as the access token may
        # no longer exist at the point that the refresh token is used
        $scope //= $prev_rt->{scope};
        $user_id = $prev_rt->{user_id};

        # need to revoke the access token
        $c->db->get_collection( 'access_tokens' )
          ->remove({ access_token => $prev_at->{access_token} });

      } else {
        $user_id = $c->db->get_collection( 'auth_codes' )->find_one({
          auth_code => $auth_code,
        })->{user_id};
      }

      if ( ref( $client ) ) {
        $scope  = $client->{scope};
        $client = $client->{client_id};
      }

      # if the client has en existing refresh token we need to revoke it
      $refresh_tokens->remove({ client_id => $client, user_id => $user_id });

      $access_tokens->insert({
        access_token  => $access_token,
        scope         => $scope,
        expires       => time + $expires_in,
        refresh_token => $refresh_token,
        client_id     => $client,
        user_id       => $user_id,
      });

      $refresh_tokens->insert({
        refresh_token => $refresh_token,
        access_token  => $access_token,
        scope         => $scope,
        client_id     => $client,
        user_id       => $user_id,
      });

      return;
    };

## verify\_access\_token

Reference: [http://tools.ietf.org/html/rfc6749#section-7](http://tools.ietf.org/html/rfc6749#section-7)

A callback to verify the access token. The callback is passed the Mojolicious
controller object, the access token, an optional reference to a list of the
scopes and if the access\_token is actually a refresh token. Note that the access
token could be the refresh token, as this method is also called when the Client
uses the refresh token to get a new access token (in which case the value of the
$is\_refresh\_token variable will be true).

The callback should verify the access code using the rules defined in the
reference RFC above, and return false if the access token is not valid otherwise
it should return something useful if the access token is valid - since this
method is called by the call to $c->oauth you probably need to return a hash
of details that the access token relates to (client id, user id, etc).

In the event of an invalid, expired, etc, access or refresh token you should
return a list where the first element is 0 and the second contains the error
message (almost certainly 'invalid\_grant' in this case)

    my $verify_access_token_sub = sub {
      my ( $c,$access_token,$scopes_ref,$is_refresh_token ) = @_;

      my $rt = $c->db->get_collection( 'refresh_tokens' )->find_one({
        refresh_token => $access_token
      });

      if ( $is_refresh_token && $rt ) {

        if ( $scopes_ref ) {
          foreach my $scope ( @{ $scopes_ref // [] } ) {
            if ( ! exists( $rt->{scope}{$scope} ) or ! $rt->{scope}{$scope} ) {
              return ( 0,'invalid_grant' )
            }
          }
        }

        # $rt contains client_id, user_id, etc
        return $rt;
      }
      elsif (
        my $at = $c->db->get_collection( 'access_tokens' )->find_one({
          access_token => $access_token,
        })
      ) {

        if ( $at->{expires} <= time ) {
          # need to revoke the access token
          $c->db->get_collection( 'access_tokens' )
            ->remove({ access_token => $access_token });

          return ( 0,'invalid_grant' )
        } elsif ( $scopes_ref ) {

          foreach my $scope ( @{ $scopes_ref // [] } ) {
            if ( ! exists( $at->{scope}{$scope} ) or ! $at->{scope}{$scope} ) {
              return ( 0,'invalid_grant' )
            }
          }

        }

        # $at contains client_id, user_id, etc
        return $at;
      }

      return ( 0,'invalid_grant' )
    };

# PUTTING IT ALL TOGETHER

Having defined the above callbacks, customized to your app/data store/etc, you
can configuration the plugin:

    $self->plugin(
      'OAuth::Server' => {
        login_resource_owner      => $resource_owner_logged_in_sub,
        confirm_by_resource_owner => $resource_owner_confirm_scopes_sub,
        verify_client             => $verify_client_sub,
        store_auth_code           => $store_auth_code_sub,
        verify_auth_code          => $verify_auth_code_sub,
        store_access_token        => $store_access_token_sub,
        verify_access_token       => $verify_access_token_sub,
      }
    );

This will make the /oauth/authorize and /oauth/access\_token routes available in
your app, which will call the above functions in the correct order. The helper
oauth also becomes available to call in various controllers, templates, etc:

    $c->oauth( 'post_image' ) or return $c->render( status => 401 );

# EXAMPLES

There are more examples included with this distribution in the examples/ dir.
See examples/README for more information about these examples.

# CLIENT SECRET, TOKEN SECURITY, AND JWT

The auth codes and access tokens generated by the plugin should be unique. When
jwt\_secret is **not** supplied they are generated using a combination of the
generation time (to microsecond precision) + rand() + a call to Crypt::PRNG's
random\_string function. These are then base64 encoded to make sure there are no
problems with URL encoding.

If jwt\_secret is set, which should be a strong secret, the tokens are created
with the [Mojo::JWT](https://metacpan.org/pod/Mojo::JWT) module and each token should contain a jti using a call
to Crypt::PRNG's random\_string function. You can decode the tokens, typically
with [Mojo::JWT](https://metacpan.org/pod/Mojo::JWT), to get the information about the client and scopes - but you
should not trust the token unless the signature matches.

As the JWT contains the client information and scopes you can, in theory, use
this information to validate an auth code / access token / refresh token without
doing a database lookup. However, it gets somewhat more complicated when you
need to revoke tokens. For more information about JWTs and revoking tokens see
[https://auth0.com/blog/2015/03/10/blacklist-json-web-token-api-keys/](https://auth0.com/blog/2015/03/10/blacklist-json-web-token-api-keys/) and
[https://tools.ietf.org/html/rfc7519](https://tools.ietf.org/html/rfc7519)

When using JWTs expiry dates will automatically checked ([Mojo::JWT](https://metacpan.org/pod/Mojo::JWT) has this
built in to the decoding) and the hash returned from the call to ->oauth will
look something like this:

    {
      'scopes' => [
                  'post_images',
                  'annoy_friends'
                ],
      'iat' => 1435225100,
      'type' => 'access', # type: auth, access, or refresh
      'exp' => 1435228700,
      'client' => 'TrendyNewService',
      'user_id' => 'some user id', # as returned from verify_auth_code
      'jti' => 'psclb1AcC2OjAKtVJRg1JjRJumkVTkDj',
      'aud' => undef # redirect uri in case of type: auth
    };

Since a call for an access token requires both the authorization code and the
client secret you don't need to worry too much about protecting the authorization
code - however you obviously need to make sure the client secret and resultant
access tokens and refresh tokens are stored securely. Since if any of these are
compromised you will have your app endpoints open to use by who or whatever has
access to them.

You should therefore treat the client secret, access token, and refresh token as
you would treat passwords - so hashed, salted, and probably encrypted. As with
the various checking functions required by the module, the securing of this data
is left to you. More information:

[https://stackoverflow.com/questions/1626575/best-practices-around-generating-oauth-tokens](https://stackoverflow.com/questions/1626575/best-practices-around-generating-oauth-tokens)

[https://stackoverflow.com/questions/1878830/securly-storing-openid-identifiers-and-oauth-tokens](https://stackoverflow.com/questions/1878830/securly-storing-openid-identifiers-and-oauth-tokens)

[https://stackoverflow.com/questions/4419915/how-to-keep-the-oauth-consumer-secret-safe-and-how-to-react-when-its-compromis](https://stackoverflow.com/questions/4419915/how-to-keep-the-oauth-consumer-secret-safe-and-how-to-react-when-its-compromis)

# REFERENCES

- [http://oauth.net/documentation/](http://oauth.net/documentation/)
- [http://tools.ietf.org/html/rfc6749](http://tools.ietf.org/html/rfc6749)

# SEE ALSO

[Mojolicious::Plugin::OAuth2](https://metacpan.org/pod/Mojolicious::Plugin::OAuth2) - A client side OAuth2 Mojolicious plugin

[Mojo::JWT](https://metacpan.org/pod/Mojo::JWT) - encode/decode JWTs

# AUTHOR

Lee Johnson - `leejo@cpan.org`

# LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. If you would like to contribute documentation
or file a bug report then please raise an issue / pull request:

    https://github.com/leejo/mojolicious-plugin-oauth2-server
