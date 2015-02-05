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

my $verify_client_sub = sub {
  my ( $c,$client_id,$scopes_ref ) = @_;

  my $oauth2_data = load_oauth2_data();

  if ( my $client = $oauth2_data->{clients}{$client_id} ) {

      foreach my $scope ( @{ $scopes_ref // [] } ) {

        if ( ! exists( $client->{scopes}{$scope} ) ) {
          $c->app->log->debug( "OAuth2::Server: Client lacks scope ($scope)" );
          return ( 0,'invalid_scope' );
        } elsif ( ! $client->{scopes}{$scope} ) {
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

  my $user_id = $c->session( 'user_id' );

  $oauth2_data->{auth_codes}{$auth_code} = {
    client_id     => $client_id,
    user_id       => $user_id,
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
      $oauth2_data = _revoke_access_token( $c,$auth_code_data->{access_token} );
      save_oauth2_data( $oauth2_data );
    }

    return ( 0,'invalid_grant' );
  }

  # scopes are those that were requested in the authorization request, not
  # those stored in the client (i.e. what the auth request restriced scopes
  # to and not everything the client is capable of)
  my $scope = $oauth2_data->{auth_codes}{$auth_code}{scope};

  $oauth2_data->{verified_auth_codes}{$auth_code} = 1;

  save_oauth2_data( $oauth2_data );

  return ( $client_id,$error,$scope );
};

my $store_access_token_sub = sub {
  my (
    $c,$client_id,$auth_code,$access_token,$refresh_token,$expires_in,$scope
  ) = @_;

  my $oauth2_data = load_oauth2_data();

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
    $oauth2_data = _revoke_access_token( $c,$prev_access_token );
  }

  $oauth2_data->{access_tokens}{$access_token} = {
    scope         => $scope,
    expires       => time + $expires_in,
    refresh_token => $refresh_token,
    client_id     => $client_id,
    user_id       => $oauth2_data->{auth_codes}{$auth_code}{user_id},
  };

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
      $oauth2_data = _revoke_access_token( $c,$access_token );
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
  return $oauth2_data;
}

plugin 'OAuth2::Server' => {
  login_resource_owner      => $resource_owner_logged_in_sub,
  confirm_by_resource_owner => $resource_owner_confirm_scopes_sub,
  verify_client             => $verify_client_sub,
  store_auth_code           => $store_auth_code_sub,
  verify_auth_code          => $verify_auth_code_sub,
  store_access_token        => $store_access_token_sub,
  verify_access_token       => $verify_access_token_sub,
};

group {
  # /api - must be authorized
  under '/api' => sub {
    my ( $c ) = @_;
    return 1 if $c->oauth;
    $c->render( status => 401, text => 'Unauthorized' );
    return undef;
  };

  any '/annoy_friends' => sub { shift->render( text => "Annoyed Friends" ); };
  any '/post_image'    => sub { shift->render( text => "Posted Image" ); };
};

any '/api/track_location' => sub {
  my ( $c ) = @_;
  $c->oauth( 'track_location' )
      || return $c->render( status => 401, text => 'You cannot track location' );
  $c->render( text => "Target acquired" );
};

get '/' => sub {
  my ( $c ) = @_;
  $c->render( text => "Welcome to Overly Attached Social Network" );
};

get '/login' => sub {
  my ( $c ) = @_;

  if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
    $c->flash( 'redirect_after_login' => $redirect_uri );
  }

  if ( $c->session( 'logged_in' ) ) {
    return $c->render( text => 'Logged in!' )
  } else {
    return $c->render( error  => undef );
  }
};

any '/logout' => sub {
  my ( $c ) = @_;
  $c->session( expires => 1 );
  $c->redirect_to( '/' );
};

post '/login' => sub {
  my ( $c ) = @_;

  my $username = $c->param('username');
  my $password = $c->param('password');

  if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
    $c->flash( 'redirect_after_login' => $redirect_uri );
  }

  if ( $username eq 'Lee' and $password eq 'P@55w0rd' ) {
    $c->session( logged_in => 1 );
    $c->session( user_id   => $username );
    if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
       return $c->redirect_to( $redirect_uri );
    } else {
      return $c->render( text => 'Logged in!' )
    }
  } else {
    return $c->render(
      status => 401,
      error  => 'Incorrect username/password',
    );
  }
};

any '/confirm_scopes' => sub {
  my ( $c ) = @_;

  # in theory we should only ever get here via a redirect from
  # a login (that was itself redirected to from /oauth/authorize
  if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
    $c->flash( 'redirect_after_login' => $redirect_uri );
  } else {
    return $c->render(
      text => "Got to /confirm_scopes without redirect_after_login?"
    );
  }

  if ( $c->req->method eq 'POST' ) {

    my $client_id = $c->flash( 'client_id' );
    my $allow     = $c->param( 'allow' );

    $c->flash( "oauth_${client_id}" => ( $allow eq 'Allow' ) ? 1 : 0 );

    if ( my $redirect_uri = $c->flash( 'redirect_after_login' ) ) {
      return $c->redirect_to( $redirect_uri );
    }

  } else {
    $c->flash( client_id => $c->flash( 'client_id' ) );
    return $c->render(
      client_id => $c->flash( 'client_id' ),
      scopes    => $c->flash( 'scopes' ),
    );
  }
};

app->secrets( ['Setec Astronomy'] );
app->sessions->cookie_name( 'oauth2_server' );
app->start;

# vim: ts=2:sw=2:et

__DATA__
@@ layouts/default.html.ep
<!doctype html><html>
  <head><title>Overly Attached Social Network</title></head>
  <body><h3>Welcome to Overly Attached Social Network</h3><%== content %></body>
</html>

@@ login.html.ep
% layout 'default';
% if ( $error ) {
<b><%= $error %></b>
% }
<p>
  username: Lee<br />
  password: P@55w0rd
</p>
%= form_for 'login' => (method => 'POST') => begin
  %= label_for username => 'Username'
  %= text_field 'username'

  %= label_for password => 'Password'
  %= password_field 'password'

  %= submit_button 'Log me in', class => 'btn'
% end

@@ confirm_scopes.html.ep
% layout 'default';
%= form_for 'confirm_scopes' => (method => 'POST') => begin
  <%= $client_id %> would like to be able to perform the following on your behalf:<ul>
% for my $scope ( @{ $scopes } ) {
  <li><%= $scope %></li>
% }
</ul>
  %= submit_button 'Allow', class => 'btn', name => 'allow'
  %= submit_button 'Deny', class => 'btn', name => 'allow'
% end
