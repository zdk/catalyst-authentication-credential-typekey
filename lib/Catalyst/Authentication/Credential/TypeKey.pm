package Catalyst::Authentication::Credential::TypeKey;
use Catalyst::Exception;
use Authen::TypeKey;
use Moose;
use MooseX::Types::Common::String qw/ NonEmptySimpleStr SimpleStr/;
use namespace::autoclean;

our $VERSION = '0.001';

has [qw/ key_cache version skip_expiry_check auth_store key_url /] => (
    isa      => NonEmptySimpleStr,
    is       => 'ro',
    required => 1
);

has _authen_typekey => (
    is      => 'ro',
    isa     => 'Authen::TypeKey',
    lazy    => 1,
    builder => '_build__authen_typekey',
);

sub _build__authen_typekey {
    my ( $self ) = @_;

    my $tk = Authen::TypeKey->new;
    $tk->version( $self->version );
    $tk->key_cache( $self->key_cache );
    $tk->skip_expiry_check( $self->skip_expiry_check );
    $tk->key_url( $self->key_url );
    return $tk;
}

=head2 BUILDARGS

Extracts from the authentication config

=cut

sub BUILDARGS {
    my ( $class, $config, $app, $realm ) = @_;
    unless ( $config->{version} and $config->{key_url} ) {
        Catalyst::Exception->throw(
            __PACKAGE__ . " credential for realm " . $realm->name . " missing version and key_url"
        );
    }
    return $config;
}

=head2 authenticate

Standard authentication method

=cut

sub authenticate {
    my ( $self, $c, $realm, $auth_info ) = @_;

    my $res = $self->_authen_typekey->verify( $c->req );
    if (! $res ) {
        $c->log->debug( $self->_authen_typekey->errstr ) if $c->debug;
        return;
    }

    my $user =  $realm->find_user( { email => $auth_info->{email}, }, $c );
    unless ( $user ) {
        $c->log->error("Authenticated user, but could not locate in our Store!");
        return;
    }
    return $user;
}

=head1 NAME

Catalyst::Authentication::Credential::TypeKey - TypeKey authentication

=head1 VERSION

Version 0.001

=head1 SYNOPSIS

Authenticate Catalyst apps with TypeKey system.

Uses the Catalyst::Plugin::Authentication system.
  In MyApp.pm

  use Catalyst qw(
    ...
    Authentication
    ...
  );

  __PACKAGE__->config(
    'authentication' => {
      typekey => {
        credential => {
              class             => 'TypeKey',
              #Config below relies heavly on Authen::TypeKey
              key_cache         => '/var/cache/webapp/myapp/',
              version           => '1',
              skip_expiry_check => '1',
              key_url           => 'http://www.typekey.com/extras/regkeys.txt',
        },
        ...
      },
    },
  );


  In your controller

  sub login : Local {
    # body...
     if ( $c->authenticate( { email => $c->req->param('email') }, 'typekey') ) {
        # SUCCESS
     } else {
        # FAILED
     }
  }


=head1 TODO

=head1 METHODS

=cut

=head1 SEE ALSO

L<Authen::TypeKey>, L<Catalyst>, L<Catalyst::Plugin::Authentication>.

=head1 AUTHOR

zdk ( Warachet Samtalee )

=head1 LICENSE

This library is free software . You can redistribute it and/or modify it under
the same terms as perl itself.

=cut

__PACKAGE__->meta->make_immutable;
1;

__END__
