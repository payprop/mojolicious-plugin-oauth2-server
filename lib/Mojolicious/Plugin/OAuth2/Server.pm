package Mojolicious::Plugin::OAuth2::Server;

=head1 NAME

Mojolicious::Plugin::OAuth2::Server - Easier implementation of an OAuth2
Authorization Server / Resource Server with Mojolicious

=for html
<a href='https://travis-ci.org/leejo/mojolicious-plugin-oauth2-server?branch=master'><img src='https://travis-ci.org/leejo/mojolicious-plugin-oauth2-server.svg?branch=master' alt='Build Status' /></a>
<a href='https://coveralls.io/r/leejo/mojolicious-plugin-oauth2-server?branch=master'><img src='https://coveralls.io/repos/leejo/mojolicious-plugin-oauth2-server/badge.png?branch=master' alt='Coverage Status' /></a>

=head1 VERSION

0.20

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

These will be explained in more detail below, in L<REQUIRED FUNCTIONS>, and you
can also see the tests and examples included with this distribution. OAuth2
seems needlessly complicated at first, hopefully this plugin will clarify the
various steps and simplify the implementation.

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
use Mojo::JWT;
use Time::HiRes qw/ gettimeofday /;
use MIME::Base64 qw/ encode_base64 decode_base64 /;
use Carp qw/ croak /;
use Crypt::PRNG qw/ random_string /;

our $VERSION = '0.20';

my %CLIENTS;
my %AUTH_CODES;
my %ACCESS_TOKENS;
my %REFRESH_TOKENS;
my $JWT_SECRET;

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

  $JWT_SECRET = $config->{jwt_secret} // undef;

  if (
    # if we don't have a list of clients
    ! exists( $config->{clients} )
    # we must know how to verify clients and tokens
    and (
      ! $config->{verify_client}
      and ! $config->{store_auth_code}
      and ! $config->{verify_auth_code}
      and ! $config->{store_access_token}
      and ! $config->{verify_access_token}
    )
  ) {
    croak "OAuth2::Server config must provide either clients or overrides"
  }

  %CLIENTS = %{ $config->{clients} // {} };

  $app->routes->get(
    $auth_route => sub { _authorization_request( $app,$config,@_ ) },
  );

  $app->routes->post(
    $atoken_route => sub { _access_token_request( $app,$config,@_ ) },
  );

  $app->helper(
    oauth => sub {
      my @res = _verify_access_token_and_scope( $app,$config,0,@_ );
      return $res[0];
    },
  );
}

sub _authorization_request {
  my ( $app,$config,$self ) = @_;

  my ( $c_id,$url,$type,$scope,$state )
    = map { $self->param( $_ ) // undef }
    qw/ client_id redirect_uri response_type scope state /;

  my @scopes = $scope ? split( / /,$scope ) : ();

  if (
    ! defined( $c_id )
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

  my $resource_owner_logged_in = $config->{login_resource_owner} // sub {1};
  my $resource_owner_confirms  = $config->{confirm_by_resource_owner} // sub {1};
  my $verify_client            = $config->{verify_client} // \&_verify_client;

  my $uri = Mojo::URL->new( $url );
  my ( $res,$error ) = $verify_client->( $self,$c_id,\@scopes );

  if ( $res ) {
    if ( ! $resource_owner_logged_in->( $self ) ) {
      $self->app->log->debug( "OAuth2::Server: Resource owner not logged in" );
      # call to $resource_owner_logged_in method should have called redirect_to
      return;
    } else {
      $self->app->log->debug( "OAuth2::Server: Resource owner is logged in" );
      $res = $resource_owner_confirms->( $self,$c_id,\@scopes );
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

    $self->app->log->debug( "OAuth2::Server: Generating auth code for $c_id" );
    my $expires_in = $config->{auth_code_ttl} // 600;
    my $auth_code = _token( $expires_in,$c_id,\@scopes,'auth',$url );

    my $store_auth_code = $config->{store_auth_code} // \&_store_auth_code;
    $store_auth_code->( $self,$auth_code,$c_id,$expires_in,$url,@scopes );

    $uri->query->append( code  => $auth_code );

  } elsif ( $error ) {
    $uri->query->append( error => $error );
  } else {
    # callback has not returned anything, assume server error
    $uri->query->append(
      error             => 'server_error',
      error_description => 'call to verify_client returned unexpected value',
    );
  }

  $uri->query->append( state => $state ) if defined( $state );

  $self->redirect_to( $uri );
}

sub _access_token_request {
  my ( $app,$config,$self ) = @_;

  my ( $client_id,$client_secret,$grant_type,$auth_code,$url,$refresh_token )
    = map { $self->param( $_ ) // undef }
    qw/ client_id client_secret grant_type code redirect_uri refresh_token /;

  if (
    ! defined( $grant_type )
    or ( $grant_type ne 'authorization_code' and $grant_type ne 'refresh_token' )
    or ( $grant_type eq 'authorization_code' and ! defined( $auth_code ) )
    or ( $grant_type eq 'authorization_code' and ! defined( $url ) )
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

  if ( $grant_type eq 'refresh_token' ) {
    ( $client,$error,$scope,$user_id ) = _verify_access_token_and_scope(
      $app,$config,$refresh_token,$self
    );
    $old_refresh_token = $refresh_token;
  } else {
    my $verify_auth_code_sub = $config->{verify_auth_code} // \&_verify_auth_code;
    ( $client,$error,$scope,$user_id ) = $verify_auth_code_sub->(
      $self,$client_id,$client_secret,$auth_code,$url
    );
  }

  if ( $client ) {

    $self->app->log->debug( "OAuth2::Server: Generating access token for $client" );

    my $expires_in    = $config->{access_token_ttl} // 3600;
    my $access_token  = _token( $expires_in,$client,$scope,'access',undef,$user_id );
    my $refresh_token = _token( undef,$client,$scope,'refresh',undef,$user_id );

    my $store_access_token_sub
      = $config->{store_access_token} // \&_store_access_token;

    $store_access_token_sub->(
      $self,$client,$auth_code,$access_token,$refresh_token,
      $expires_in,$scope,$old_refresh_token
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

sub _token {
  my ( $ttl,$client_id,$scopes,$type,$redirect_url,$user_id ) = @_;

  my $code;

  if ( ! $JWT_SECRET ) {
    my ( $sec,$usec ) = gettimeofday;
    $code = encode_base64( join( '-',$sec,$usec,rand(),random_string(30) ),'' );
  } else {
    $code = Mojo::JWT->new(
      ( $ttl ? ( expires => time + $ttl ) : () ),
      secret  => $JWT_SECRET,
      set_iat => 1,
      # https://tools.ietf.org/html/rfc7519#section-4
      claims  => {
        # Registered Claim Names
#        iss    => undef, # us, the auth server / application (set using plugin config?)
#        sub    => undef, # the logged in user, we could get this by returning it from the resource_owner_logged_in callback
        aud    => $redirect_url, # the "audience"
        jti    => random_string(32),

        # Private Claim Names
        user_id      => $user_id,
        client       => $client_id,
        type         => $type,
        scopes       => $scopes,
      },
    )->encode;
  }

  return $code;
}

sub _verify_access_token_and_scope {
  my ( $app,$config,$refresh_token,$c,@scopes ) = @_;

  my $verify_access_token_sub
    = $config->{verify_access_token} // \&_verify_access_token;

  my $access_token;

  if ( ! $refresh_token ) {
    if ( my $auth_header = $c->req->headers->header( 'Authorization' ) ) {
      my ( $auth_type,$auth_access_token ) = split( / /,$auth_header );

      if ( $auth_type ne 'Bearer' ) {
        $c->app->log->debug( "OAuth2::Server: Auth type is not 'Bearer'" );
        return ( 0,'invalid_request' );
      } else {
        $access_token = $auth_access_token;
      }
    } else {
      $c->app->log->debug( "OAuth2::Server: Authorization header missing" );
      return ( 0,'invalid_request' );
    }
  } else {
    $access_token = $refresh_token;
  }
  
  return $verify_access_token_sub->( $c,$access_token,\@scopes,$refresh_token );
}

sub _revoke_access_token {
  my ( $c,$access_token ) = @_;
  delete( $ACCESS_TOKENS{$access_token} );
}

=head1 REQUIRED FUNCTIONS

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

=cut

=head2 login_resource_owner

A callback to tell the plugin if the Resource Owner is logged in. It is passed
the Mojolicious controller object. It should return 1 if the Resource Owner is
logged in, otherwise it should call the redirect_to method on the controller
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
authorize and access_token are under /oauth/ so it is possible that the flash may
have a Path of /oauth/ - the consequence of this is that if your login route is
under a different path (likely) you will not be able to access the value you set in
the flash. The solution to this? Simply create another route under /oauth/ (so in
this case /oauth/login) that points to the same route as the /login route

=head2 confirm_by_resource_owner

A callback to tell the plugin if the Resource Owner allowed or denied access to
the Resource Server by the Client. It is passed the Mojolicious controller
object, the client id, and an array reference of scopes requested by the client.

It should return 1 if access is allowed, 0 if access is not allowed, otherwise
it should call the redirect_to method on the controller and return undef:

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
the caveat regarding flash and Path as documented above (L<login_resource_owner>)

=head2 verify_client

Reference: L<http://tools.ietf.org/html/rfc6749#section-4.1.1>

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

=cut

sub _verify_client {
  my ( $c,$client_id,$scopes_ref ) = @_;

  if ( my $client = $CLIENTS{$client_id} ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {

        if ( ! exists( $CLIENTS{$client_id}{scopes}{$scope} ) ) {
          $c->app->log->debug( "OAuth2::Server: Client lacks scope ($scope)" );
          return ( 0,'invalid_scope' );
        } elsif ( ! $CLIENTS{$client_id}{scopes}{$scope} ) {
          $c->app->log->debug( "OAuth2::Server: Client cannot scope ($scope)" );
          return ( 0,'access_denied' );
        }
      }

      return ( 1 );
  }

  $c->app->log->debug( "OAuth2::Server: Client ($client_id) does not exist" );
  return ( 0,'unauthorized_client' );
}

=head2 store_auth_code

A callback to allow you to store the generated authorization code. The callback
is passed the Mojolicious controller object, the generated auth code, the client
id, the auth code validity period in seconds, the Client redirect URI, and a list
of the scopes requested by the Client.

You should save the information to your data store, it can then be retrieved by
the verify_auth_code callback for verification:

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

=cut

sub _store_auth_code {
  my ( $c,$auth_code,$client_id,$expires_in,$uri,@scopes ) = @_;

  $AUTH_CODES{$auth_code} = {
    client_id     => $client_id,
    expires       => time + $expires_in,
    redirect_uri  => $uri,
    scope         => { map { $_ => 1 } @scopes },
  };

  return 1;
}

=head2 verify_auth_code

Reference: L<http://tools.ietf.org/html/rfc6749#section-4.1.3>

A callback to verify the authorization code passed from the Client to the
Authorization Server. The callback is passed the Mojolicious controller object,
the client_id, the client_secret, the authorization code, and the redirect uri.

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

=cut

sub _verify_auth_code {
  my ( $c,$client_id,$client_secret,$auth_code,$uri ) = @_;

  my ( $sec,$usec,$rand ) = split( '-',decode_base64( $auth_code ) );

  if (
    ! exists( $AUTH_CODES{$auth_code} )
    or ! exists( $CLIENTS{$client_id} )
    or ( $client_secret ne $CLIENTS{$client_id}{client_secret} )
    or $AUTH_CODES{$auth_code}{access_token}
    or ( $uri && $AUTH_CODES{$auth_code}{redirect_uri} ne $uri )
    or ( $AUTH_CODES{$auth_code}{expires} <= time )
  ) {

    $c->app->log->debug( "OAuth2::Server: Auth code does not exist" )
      if ! exists( $AUTH_CODES{$auth_code} );
    $c->app->log->debug( "OAuth2::Server: Client ($client_id) does not exist" )
      if ! exists( $CLIENTS{$client_id} );
    $c->app->log->debug( "OAuth2::Server: Client secret does not match" )
      if (
        ! $client_secret
        or ! $CLIENTS{$client_id}
        or $client_secret ne $CLIENTS{$client_id}{client_secret}
      );

    if ( $AUTH_CODES{$auth_code} ) {
      $c->app->log->debug( "OAuth2::Server: Redirect URI does not match" )
        if ( $uri && $AUTH_CODES{$auth_code}{redirect_uri} ne $uri );
      $c->app->log->debug( "OAuth2::Server: Auth code expired" )
        if ( $AUTH_CODES{$auth_code}{expires} <= time );
    }

    if ( my $access_token = $AUTH_CODES{$auth_code}{access_token} ) {
      # this auth code has already been used to generate an access token
      # so we need to revoke the access token that was previously generated
      $c->app->log->debug(
        "OAuth2::Server: Auth code already used to get access token"
      );

      _revoke_access_token( $c,$access_token );
    }

    return ( 0,'invalid_grant' );
  } else {
    return ( 1,undef,$AUTH_CODES{$auth_code}{scope} );
  }

}

=head2 store_access_token

A callback to allow you to store the generated access and refresh tokens. The
callback is passed the Mojolicious controller object, the client identifier as
returned from the verify_auth_code callback, the authorization code, the access
token, the refresh_token, the validity period in seconds, the scope returned
from the verify_auth_code callback, and the old refresh token,

Note that the passed authorization code could be undefined, in which case the
access token and refresh tokens were requested by the Client by the use of an
existing refresh token, which will be passed as the old refresh token variable.
In this case you should use the old refresh token to find out the previous
access token and revoke the previous access and refresh tokens (this is *not* a
hard requirement according to the OAuth spec, but i would recommend it).

The callback does not need to return anything.

You should save the information to your data store, it can then be retrieved by
the verify_access_token callback for verification:

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

=cut

sub _store_access_token {
  my (
    $c,$c_id,$auth_code,$access_token,$refresh_token,
    $expires_in,$scope,$old_refresh_token
  ) = @_;

  if ( ! defined( $auth_code ) && $old_refresh_token ) {
    # must have generated an access token via a refresh token so revoke the old
    # access token and refresh token and update the AUTH_CODES hash to store the
    # new one (also copy across scopes if missing)
    $auth_code = $REFRESH_TOKENS{$old_refresh_token}{auth_code};

    my $prev_access_token = $REFRESH_TOKENS{$old_refresh_token}{access_token};

    # access tokens can be revoked, whilst refresh tokens can remain so we
    # need to get the data from the refresh token as the access token may
    # no longer exist at the point that the refresh token is used
    $scope //= $REFRESH_TOKENS{$old_refresh_token}{scope};

    $c->app->log->debug( "OAuth2::Server: Revoking old access token (refresh)" );
    _revoke_access_token( $c,$prev_access_token );
  }

  delete( $REFRESH_TOKENS{$old_refresh_token} )
    if $old_refresh_token;

  $ACCESS_TOKENS{$access_token} = {
    scope         => $scope,
    expires       => time + $expires_in,
    refresh_token => $refresh_token,
    client_id     => $c_id,
  };

  $REFRESH_TOKENS{$refresh_token} = {
    scope         => $scope,
    client_id     => $c_id,
    access_token  => $access_token,
    auth_code     => $auth_code,
  };

  $AUTH_CODES{$auth_code}{access_token} = $access_token;

  return $c_id;
}

=head2 verify_access_token

Reference: L<http://tools.ietf.org/html/rfc6749#section-7>

A callback to verify the access token. The callback is passed the Mojolicious
controller object, the access token, an optional reference to a list of the
scopes and if the access_token is actually a refresh token. Note that the access
token could be the refresh token, as this method is also called when the Client
uses the refresh token to get a new access token (in which case the value of the
$is_refresh_token variable will be true).

The callback should verify the access code using the rules defined in the
reference RFC above, and return false if the access token is not valid otherwise
it should return something useful if the access token is valid - since this
method is called by the call to $c->oauth you probably need to return a hash
of details that the access token relates to (client id, user id, etc).

In the event of an invalid, expired, etc, access or refresh token you should
return a list where the first element is 0 and the second contains the error
message (almost certainly 'invalid_grant' in this case)

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

=cut

sub _verify_access_token {
  my ( $c,$access_token,$scopes_ref,$is_refresh_token ) = @_;

  if (
    $is_refresh_token
    && exists( $REFRESH_TOKENS{$access_token} )
  ) {

    if ( $scopes_ref ) {
      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if (
          ! exists( $REFRESH_TOKENS{$access_token}{scope}{$scope} )
          or ! $REFRESH_TOKENS{$access_token}{scope}{$scope}
        ) {
          $c->app->log->debug( "OAuth2::Server: Refresh token does not have scope ($scope)" );
          return ( 0,'invalid_grant' )
        }
      }
    }

    return $REFRESH_TOKENS{$access_token}{client_id};
  }
  elsif ( exists( $ACCESS_TOKENS{$access_token} ) ) {

    if ( $ACCESS_TOKENS{$access_token}{expires} <= time ) {
      $c->app->log->debug( "OAuth2::Server: Access token has expired" );
      _revoke_access_token( $c,$access_token );
      return ( 0,'invalid_grant' )
    } elsif ( $scopes_ref ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if (
          ! exists( $ACCESS_TOKENS{$access_token}{scope}{$scope} )
          or ! $ACCESS_TOKENS{$access_token}{scope}{$scope}
        ) {
          $c->app->log->debug( "OAuth2::Server: Access token does not have scope ($scope)" );
          return ( 0,'invalid_grant' )
        }
      }

    }

    $c->app->log->debug( "OAuth2::Server: Access token is valid" );
    return $ACCESS_TOKENS{$access_token}{client_id};
  }

  $c->app->log->debug( "OAuth2::Server: Access token does not exist" );
  return ( 0,'invalid_grant' )
}

1;

=head1 PUTTING IT ALL TOGETHER

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

This will make the /oauth/authorize and /oauth/access_token routes available in
your app, which will call the above functions in the correct order. The helper
oauth also becomes available to call in various controllers, templates, etc:

  $c->oauth( 'post_image' ) or return $c->render( status => 401 );

=head1 EXAMPLES

There are more examples included with this distribution in the examples/ dir.
See examples/README for more information about these examples.

=head1 CLIENT SECRET, TOKEN SECURITY, AND JWT

The auth codes and access tokens generated by the plugin should be unique. When
jwt_secret is B<not> supplied they are generated using a combination of the
generation time (to microsecond precision) + rand() + a call to Crypt::PRNG's
random_string function. These are then base64 encoded to make sure there are no
problems with URL encoding.

If jwt_secret is set, which should be a strong secret, the tokens are created
with the L<Mojo::JWT> module and each token should contain a jti using a call
to Crypt::PRNG's random_string function. You can decode the tokens, typically
with L<Mojo::JWT>, to get the information about the client and scopes - but you
should not trust the token unless the signature matches.

As the JWT contains the client information and scopes you can, in theory, use
this information to validate an auth code / access token / refresh token without
doing a database lookup. However, it gets somewhat more complicated when you
need to revoke tokens. For more information about JWTs and revoking tokens see
L<https://auth0.com/blog/2015/03/10/blacklist-json-web-token-api-keys/> and
L<https://tools.ietf.org/html/rfc7519>

When using JWTs expiry dates will automatically checked (L<Mojo::JWT> has this
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

L<https://stackoverflow.com/questions/1626575/best-practices-around-generating-oauth-tokens>

L<https://stackoverflow.com/questions/1878830/securly-storing-openid-identifiers-and-oauth-tokens>

L<https://stackoverflow.com/questions/4419915/how-to-keep-the-oauth-consumer-secret-safe-and-how-to-react-when-its-compromis>

=head1 REFERENCES

=over 4

=item * L<http://oauth.net/documentation/>

=item * L<http://tools.ietf.org/html/rfc6749>

=back

=head1 SEE ALSO

L<Mojolicious::Plugin::OAuth2> - A client side OAuth2 Mojolicious plugin

L<Mojo::JWT> - encode/decode JWTs

=head1 AUTHOR

Lee Johnson - C<leejo@cpan.org>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. If you would like to contribute documentation
or file a bug report then please raise an issue / pull request:

    https://github.com/leejo/mojolicious-plugin-oauth2-server

=cut

# vim: ts=2:sw=2:et
