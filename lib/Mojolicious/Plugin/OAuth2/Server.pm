package Mojolicious::Plugin::OAuth2::Server;

=head1 NAME

Mojolicious::Plugin::OAuth2::Server - Auth against OAuth2 APIs

=head1 DESCRIPTION

This Mojolicious plugin allows you to

Note that OAuth2 requires https, so you need to have the optional Mojolicious
dependency required to support it. Run the command below to check if
L<IO::Socket::SSL> is installed.

   $ mojo version

=cut

use strict;
use base qw/ Mojolicious::Plugin /;

use Mojo::URL;
use Time::HiRes qw/ gettimeofday /;
use MIME::Base64 qw/ encode_base64 /;

our $VERSION = '0.01';

my %CLIENTS;
my %AUTH_CODES;

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

  %CLIENTS = %{ $config->{clients} // {} };

  $app->routes->any(
    $auth_route => sub { _authorization_request( $app,$config,@_ ) }
  );

  $app->routes->any(
    $atoken_route => sub {},
  );
}

sub _authorization_request {
  my ( $app,$config,$self ) = @_;

  my ( $c_id,$c_secret,$url,$type,$scope,$state ) = map { $self->param( $_ ) }
    qw/ client_id client_secret redirect_uri response_type scope state /;

  my @scopes = $scope ? split( / /,$scope ) : ();

  if (
    ! defined( $c_id )
    or ! defined( $c_secret )
    or ! defined( $type )
    or $type ne 'code'
  ) {
    $self->render(
      status => 400,
      json   => {
        error             => 'invalid_request',
        error_description => 'the request was missing one of: client_id, '
          . 'client_secret, response_type;'
          . 'or response_type did not equal "code"',
        error_uri         => '',
      }
    );
    return;
  }

  $url = Mojo::URL->new( $url );

  my $code = $config->{verify_client} // \&_verify_client;

  if ( my $res = $code->( $self,$c_id,$c_secret,\@scopes ) ) {

    if ( $res eq '1' ) {

      my ( $auth_code,$expires_at ) = _generate_authorization_code( $c_id );

      if ( $code = $config->{store_auth_code} ) {
        $code->( $auth_code,$c_id,$c_secret,$expires_at );
      } else {
        _store_auth_code( $auth_code,$c_id,$c_secret,$expires_at );
      }

      $url->query->append( code  => $auth_code );

    } else {
      $url->query->append( error  => $res );
    }
  } else {
    # callback has not returned anything, assume server error
    $url->query->append(
      error             => 'server_error',
      error_description => 'call to verify_client returned unexpected value',
    );
  }

  $url->query->append( state => $state ) if defined( $state );

  $self->redirect_to( $url );
}

sub _generate_authorization_code {
  my ( $client_id ) = @_;

  my ( $sec,$usec ) = gettimeofday;

  return (
    encode_base64( join( '-',$sec,$usec,$client_id ) ),
    time + 600
  );
}

sub _store_auth_code {
  my ( $auth_code,$client_id,$client_secret,$expires_at ) = @_;

  $AUTH_CODES{$client_id}{$auth_code} = {
    expires       => $expires_at,
    client_secret => $client_secret,
    checked       => 0,
  };

  return 1;
}

sub _verify_client {
  my ( $self,$client_id,$client_secret,$scopes_ref ) = @_;

  if ( my $client = $CLIENTS{$client_id} ) {
    # TODO - scope checking?
    return $client->{client_secret} eq $client_secret;
  }

  return 0;
}

1;

=head2 References

=over 4

=item * L<http://oauth.net/documentation/>

=back

=head1 SYNOPSIS

=head1 AUTHOR

Lee Johnson - C<leejo@cpan.org>

=head1 LICENSE

This software is licensed under the same terms as Perl itself.

=cut

# vim: ts=2:sw=2:et
