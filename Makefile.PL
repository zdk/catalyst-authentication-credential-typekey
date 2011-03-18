use inc::Module::Install;

name 'Catalyst-Authentication-Credential-TypeKey';
all_from 'lib/Catalyst/Authentication/Credential/TypeKey.pm';

requires 'Catalyst::Exception';
requires 'Authen::TypeKey';
requires 'Moose';
requires 'MooseX::Types::Common::String';
requires 'namespace::autoclean';


test_requires 'Catalyst::Runtime';
test_requires 'Test::More';

if ($Module::Install::AUTHOR) {
    system("pod2text lib/Catalyst/Authentication/Credential/TypeKey.pm > README")
        and die;
}

WriteAll();

