#!perl

use strict;
use warnings;

use Mojolicious::Lite;
use Mojo::JSON qw/ decode_json encode_json /;
use FindBin qw/ $Bin /;

chdir( $Bin );

# N.B. this uses a little JSON file, which would not scale - in reality
# you should be using a database of some sort
my $storage_file = "oauth2_db.json";

sub save_oauth2_data {
  my ( $config ) = @_;
  my $json = encode_json( $config );
  open( my $fh,'>',$storage_file )
    || die "Couldn't open $storage_file for write: $!";
  print $fh $json;
  close( $fh );
  return 1;
}

sub load_oauth2_data {
  open( my $fh,'<',$storage_file )
    || die "Couldn't open $storage_file for read: $!";
  my $json;
  while ( my $line = <$fh> ) {
    $json .= $line;
  }
  close( $fh );
  return decode_json( $json );
}

app->config(
  hypnotoad => {
    listen => [ 'https://*:3000' ]
  }
);

my $verify_client_sub = sub {
  my ( $c,$client_id,$scopes_ref ) = @_;

  my $oauth2_data = load_oauth2_data();

  if ( my $client = $oauth2_data->{clients}{$client_id} ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {

        if ( ! exists( $oauth2_data->{clients}{$client_id}{scopes}{$scope} ) ) {
          $c->app->log->debug( "OAuth2::Server: Client lacks scope ($scope)" );
          return ( 0,'invalid_scope' );
        } elsif ( ! $oauth2_data->{clients}{$client_id}{scopes}{$scope} ) {
          $c->app->log->debug( "OAuth2::Server: Client cannot scope ($scope)" );
          return ( 0,'access_denied' );
        }
      }

      return ( 1 );
  }

  $c->app->log->debug( "OAuth2::Server: Client ($client_id) does not exist" );
  return ( 0,'unauthorized_client' );
};

my $store_auth_code_sub = sub {
  my ( $c,$auth_code,$client_id,$expires_at,$uri,@scopes ) = @_;

  my $oauth2_data = load_oauth2_data();

  $oauth2_data->{auth_codes}{$auth_code} = {
    client_id     => $client_id,
    expires       => $expires_at,
    redirect_uri  => $uri,
    scope         => { map { $_ => 1 } @scopes },
  };

  $oauth2_data->{auth_codes_by_client}{$client_id} = $auth_code;

  save_oauth2_data( $oauth2_data );

  return;
};

my $verify_auth_code_sub = sub {
  my ( $c,$client_id,$client_secret,$auth_code,$uri ) = @_;

  my $oauth2_data = load_oauth2_data();

  my $client = $oauth2_data->{clients}{$client_id}
    || return ( 0,'unauthorized_client' );

  return ( 0,'invalid_grant' )
    if ( $client_secret ne $client->{client_secret} );

  my $error = undef;
  my $scope = $client->{scopes};

  if (
    ! exists( $oauth2_data->{auth_codes}{$auth_code} )
    or ! exists( $oauth2_data->{clients}{$client_id} )
    or ( $client_secret ne $oauth2_data->{clients}{$client_id}{client_secret} )
    or $oauth2_data->{auth_codes}{$auth_code}{access_token}
    or ( $uri && $oauth2_data->{auth_codes}{$auth_code}{redirect_uri} ne $uri )
    or ( $oauth2_data->{auth_codes}{$auth_code}{expires} <= time )
  ) {

    if ( $oauth2_data->{verified_auth_codes}{$auth_code} ) {
      # the auth code has been used before - we must revoke the auth code
      # and access tokens
      my $auth_code_data = delete( $oauth2_data->{auth_codes}{$auth_code} );
      _revoke_access_token( $c,$auth_code_data->{access_token} );
      save_oauth2_data( $oauth2_data );
    }

    return ( 0,'invalid_grant' );
  }

  $oauth2_data->{verified_auth_codes}{$auth_code} = 1;

  save_oauth2_data( $oauth2_data );

  return ( $client_id,$error,$scope );
};

my $store_access_token_sub = sub {
  my (
    $c,$client_id,$auth_code,$access_token,$refresh_token,$expires_in,$scope
  ) = @_;

  my $oauth2_data = load_oauth2_data();

  $oauth2_data->{access_tokens}{$access_token} = {
    scope         => $scope,
    expires       => time + $expires_in,
    refresh_token => $refresh_token,
    client_id     => $client_id,
  };

  if ( ! defined( $auth_code ) ) {
    # must have generated an access token via a refresh token so revoke the old
    # access token and update the oauth2_data->{auth_codes} hash to store the
    # new one (also copy across scopes if missing)
    $auth_code = $oauth2_data->{auth_codes_by_client}{$client_id};

    my $prev_access_token = $oauth2_data->{auth_codes}{$auth_code}{access_token};

    if ( ! $oauth2_data->{access_tokens}{$access_token}{scope} ) {
      $oauth2_data->{access_tokens}{$access_token}{scope}
        = $oauth2_data->{access_tokens}{$prev_access_token}{scope};
    }

    $c->app->log->debug( "OAuth2::Server: Revoking old access tokens (refresh)" );
    _revoke_access_token( $c,$prev_access_token );
  }

  $oauth2_data->{auth_codes}{$auth_code}{access_token} = $access_token;

  save_oauth2_data( $oauth2_data );
  return;
};

my $verify_access_token_sub = sub {
  my ( $c,$access_token,$scopes_ref ) = @_;

  my $oauth2_data = load_oauth2_data();

  if ( exists( $oauth2_data->{access_tokens}{$access_token} ) ) {

    if ( $oauth2_data->{access_tokens}{$access_token}{expires} <= time ) {
      $c->app->log->debug( "OAuth2::Server: Access token has expired" );
      _revoke_access_token( $c,$access_token );
      return 0;
    } elsif ( $scopes_ref ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {
        if (
          ! exists( $oauth2_data->{access_tokens}{$access_token}{scope}{$scope} )
          or ! $oauth2_data->{access_tokens}{$access_token}{scope}{$scope}
        ) {
          $c->app->log->debug( "OAuth2::Server: Access token does not have scope ($scope)" );
          return 0;
        }
      }

    }

    $c->app->log->debug( "OAuth2::Server: Access token is valid" );
    return $oauth2_data->{access_tokens}{$access_token}{client_id};
  }

  $c->app->log->debug( "OAuth2::Server: Access token does not exist" );
  return 0;
};

sub _revoke_access_token {
  my ( $c,$access_token ) = @_;

  my $oauth2_data = load_oauth2_data();

  # need to revoke both the refresh token and the access token
  delete( $oauth2_data->{access_tokens}{
    $oauth2_data->{access_tokens}{$access_token}{refresh_token}
  } );
  delete( $oauth2_data->{access_tokens}{$access_token} );

  save_oauth2_data( $oauth2_data );
}

plugin 'OAuth2::Server' => {
  verify_client       => $verify_client_sub,
  store_auth_code     => $store_auth_code_sub,
  verify_auth_code    => $verify_auth_code_sub,
  store_access_token  => $store_access_token_sub,
  verify_access_token => $verify_access_token_sub,
  clients              => {
    1 => {
      client_secret => 'boo',
      scopes        => {
        act => 1,
      },
    },
  },
};

group {
  # /api - must be authorized
  under '/api' => sub {
    my ( $c ) = @_;
    return 1 if $c->oauth;
    $c->render( status => 401, text => 'Unauthorized' );
    return undef;
  };

  any '/act' => sub { shift->render( text => "Acted" ); };
};

any '/play' => sub {
  my ( $c ) = @_;
  $c->oauth( 'play' )
      || return $c->render( status => 401, text => 'You cannot play' );
  $c->render( text => "Played" );
};

get '/' => sub {
  my ( $c ) = @_;
  $c->render( text => "Welcome" );
};

app->start;

# vim: ts=2:sw=2:et
