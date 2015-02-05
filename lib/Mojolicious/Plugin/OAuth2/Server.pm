package Mojolicious::Plugin::OAuth2::Server;

=head1 NAME

Mojolicious::Plugin::OAuth2::Server - Easier(?) implementation of an OAuth2
Authorization and Resource Server with Mojolicious

=head1 DESCRIPTION

Note that OAuth2 requires https, so you need to have the optional Mojolicious
dependency required to support it. Run the command below to check if
L<IO::Socket::SSL> is installed.

   $ mojo version

=cut

use strict;
use base qw/ Mojolicious::Plugin /;

use Mojo::URL;
use Time::HiRes qw/ gettimeofday /;
use MIME::Base64 qw/ encode_base64 decode_base64 /;
use Carp qw/croak/;

our $VERSION = '0.01';

my %CLIENTS;
my %AUTH_CODES;
my %ACCESS_TOKENS;
my %AUTH_CODES_BY_CLIENT;

=head1 METHODS

=head2 register

Registers the plugin with your app - note that you must pass callbacks for
certain functions that the plugin expects to call

  $self->register($app, \%config);

=cut

sub register {
  my ( $self,$app,$config ) = @_;

  my $auth_route   = $config->{authorize_route}    // '/oauth/authorize';
  my $atoken_route = $config->{access_token_route} // '/oauth/access_token';

  if (
    # if we don't have a list of clients
    ! exists( $config->{clients} )
    # we must know how to verify clients and tokens
    and (
      ! exists( $config->{verify_client} )
      or ! exists( $config->{store_auth_code} )
      or ! exists( $config->{verify_auth_code} )
      or ! exists( $config->{store_access_token} )
      or ! exists( $config->{verify_access_token} )
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
    oauth => sub { _verify_access_token_and_scope( $app,$config,@_ ) },
  );
}

sub _authorization_request {
  my ( $app,$config,$self ) = @_;

  my ( $c_id,$url,$type,$scope,$state ) = map { $self->param( $_ ) }
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
  my ( $res,$error );

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
    } else {
      ( $res,$error ) = $verify_client->( $self,$c_id,\@scopes );
    }
  }

  if ( $res ) {

    $self->app->log->debug( "OAuth2::Server: Generating auth code for $c_id" );
    my ( $auth_code,$expires_at ) = _generate_authorization_code(
      $c_id,$config->{auth_code_ttl}
    );

    if ( my $store_auth_code = $config->{store_auth_code} ) {
      $store_auth_code->( $self,$auth_code,$c_id,$expires_at,$url,@scopes );
    } else {
      _store_auth_code( $self,$auth_code,$c_id,$expires_at,$url,@scopes );
    }

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

  my ( $client_id,$client_secret,$grant_type,$auth_code,$url,$refresh_token ) = map { $self->param( $_ ) }
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
  my ( $c_id,$error,$scope );

  if ( $grant_type eq 'refresh_token' ) {
    $c_id = _verify_access_token_and_scope( $app,$config,$self );
  } else {
    my $verify_auth_code_sub = $config->{verify_auth_code} // \&_verify_auth_code;
    ( $c_id,$error,$scope ) = $verify_auth_code_sub->(
      $self,$client_id,$client_secret,$auth_code,$url
    );
  }

  if ( $c_id ) {

    $self->app->log->debug( "OAuth2::Server: Generating access token for $client_id" );

    my ( $access_token,$refresh_token,$expires_in )
      = _generate_access_token( $c_id,$config->{access_token_ttl} );

    my $store_access_token_sub
      = $config->{store_access_token} // \&_store_access_token;

    $store_access_token_sub->(
      $self,$c_id,$auth_code,$access_token,$refresh_token,$expires_in,$scope
    );

    $status        = 200;
    $json_response = {
      access_token  => $access_token,
      token_type    => 'bearer',
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

sub _generate_authorization_code {
  my ( $client_id,$ttl ) = @_;

  $ttl //= 600;
  my ( $sec,$usec ) = gettimeofday;

  return (
    encode_base64( join( '-',$sec,$usec,rand(),$client_id ),'' ),
    time + $ttl
  );
}

sub _generate_access_token {

  my ( $client_id,$ttl ) = @_;

  $ttl //= 3600;

  return (
    ( _generate_authorization_code( $client_id ) )[0],
    ( _generate_authorization_code( $client_id ) )[0],
    $ttl,
  );
}

sub _store_auth_code {
  my ( $c,$auth_code,$client_id,$expires_at,$uri,@scopes ) = @_;

  $AUTH_CODES{$auth_code} = {
    client_id     => $client_id,
    expires       => $expires_at,
    redirect_uri  => $uri,
    scope         => { map { $_ => 1 } @scopes },
  };

  $AUTH_CODES_BY_CLIENT{$client_id} = $auth_code;

  return 1;
}

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
      if ( $client_secret ne $CLIENTS{$client_id}{client_secret} );
    $c->app->log->debug( "OAuth2::Server: Redirect URI does not match" )
      if ( $uri && $AUTH_CODES{$auth_code}{redirect_uri} ne $uri );
    $c->app->log->debug( "OAuth2::Server: Auth code expired" )
      if ( $AUTH_CODES{$auth_code}{expires} <= time );

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
    return ( 1,$client_id,$AUTH_CODES{$auth_code}{scope} );
  }

}

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

sub _verify_access_token_and_scope {
  my ( $app,$config,$c,@scopes ) = @_;

  my $auth_header = $c->req->headers->header( 'Authorization' );
  my ( $auth_type,$access_token ) = split( / /,$auth_header );

  my $verify_access_token_sub
    = $config->{verify_access_token} // \&_verify_access_token;

  if ( $auth_type ne 'Bearer' ) {
    $c->app->log->debug( "OAuth2::Server: Auth type is not 'Bearer'" );
    return 0;
  } else {
    return $verify_access_token_sub->( $c,$access_token,\@scopes );
  }

}

sub _store_access_token {
  my (
    $c,$c_id,$auth_code,$access_token,$refresh_token,$expires_in,$scope
  ) = @_;

  if ( ! defined( $auth_code ) ) {
    # must have generated an access token via a refresh token so
    # revoke the old access token and update the AUTH_CODES hash
    # to store the new one (also copy across scopes if missing)
    $auth_code = $AUTH_CODES_BY_CLIENT{$c_id};

    my $prev_access_token = $AUTH_CODES{$auth_code}{access_token};

    if ( ! $ACCESS_TOKENS{$access_token}{scope} ) {
      $ACCESS_TOKENS{$access_token}{scope}
        = $ACCESS_TOKENS{$prev_access_token}{scope};
    }

    $c->app->log->debug( "OAuth2::Server: Revoking old access tokens (refresh)" );
    _revoke_access_token( $c,$prev_access_token );
  }

  $ACCESS_TOKENS{$access_token} = {
    scope         => $scope,
    expires       => time + $expires_in,
    refresh_token => $refresh_token,
    client_id     => $c_id,
  };

  $AUTH_CODES{$auth_code}{access_token} = $access_token;

  return $c_id;
}

sub _revoke_access_token {
  my ( $c,$access_token ) = @_;

  # need to revoke both the refresh token and the access token
  delete( $ACCESS_TOKENS{ $ACCESS_TOKENS{$access_token}{refresh_token} } );
  delete( $ACCESS_TOKENS{$access_token} );
}

sub _verify_access_token {
  my ( $c,$access_token,$scopes_ref ) = @_;

  if ( exists( $ACCESS_TOKENS{$access_token} ) ) {

    if ( $ACCESS_TOKENS{$access_token}{expires} <= time ) {
      $c->app->log->debug( "OAuth2::Server: Access token has expired" );
      _revoke_access_token( $c,$access_token );
      return 0;
    } elsif ( $scopes_ref ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if (
          ! exists( $ACCESS_TOKENS{$access_token}{scope}{$scope} )
          or ! $ACCESS_TOKENS{$access_token}{scope}{$scope}
        ) {
          $c->app->log->debug( "OAuth2::Server: Access token does not have scope ($scope)" );
          return 0;
        }
      }

    }

    $c->app->log->debug( "OAuth2::Server: Access token is valid" );
    return $ACCESS_TOKENS{$access_token}{client_id};
  }

  $c->app->log->debug( "OAuth2::Server: Access token does not exist" );
  return 0;
}

1;

=head2 REFERENCES

=over 4

=item * L<http://oauth.net/documentation/>

=item * L<http://tools.ietf.org/html/rfc6749>

=back

=head1 SEE ALSO

L<Mojolicious::Plugin::OAuth2> - A client side OAuth2 Mojolicious plugin

=head1 AUTHOR

Lee Johnson - C<leejo@cpan.org>

=head1 LICENSE

This software is licensed under the same terms as Perl itself.

=cut

# vim: ts=2:sw=2:et
