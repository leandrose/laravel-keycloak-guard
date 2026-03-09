<?php

namespace LeandroSe\KeycloakGuard\Tests;

use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use LeandroSe\KeycloakGuard\KeycloakAuthServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    private const PRIVATE_KEY = <<<'PEM'
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJekUW67RD2+fu
LtuUwW6/b147IVflg9V9CMJrSD33hEZ/d1I+1FJKPbHgMXUMER+Oyr5JA6C+fVoA
dg0tuiJWlQ781l7GiuW8L2GE/QPc00tq5Urk0SSHkkRSI5Gn6xtN8IYDxFCHd5TI
05SoswDQys0YnW+ciiyR5RwQQADwoterArNkSigm9LN3iG+/9vPGzMhtTbXKybAc
hQchzdBzOMNQViNKAYI8XVIkljrhcbzTZ2n7NjqzJadbx2feSAcdHllpCe82gb3g
kWTMjWRvvVIb2XtPV5zx3mNugDBRclpZ+Hm3QBX4PpOk2FPDXcez2cW0oCj9ebyx
cvaNQRvRAgMBAAECggEABhDedOPUjfD4XQNP5N0EhbK3jHHy7KPxGOY7PUHj7Lhw
q2yHH0Fi911/ZhuzFZGL6M+Jllbrv2R0gdxMBgcLOt5awMm++X0L0OQ/zEJWXA8H
/6BG5pf14LeKg0sTGvJBBJIT5NfjoUp8QiYdnQ0jnoWmkmHGDxlZYWybkVEt/hCp
XvVDwFCTBEHQf3aMPKIaQkvWTxDwfaApdi+09gek93HnTNJRPRx2OWJrR7NGW0P3
HSw2tPQo2qBNsaXCS9Y55f98DRxb9oFTxaoWoj9BMQDDe1pqNMxKukz++Yw1MrQi
3jlNLUNgv5QoVLrh8qGBSlaAoFEnjgLkNz9f6494qQKBgQDjol/gtO/luiaNeuN1
2/TWzliTRjZTbZkR17PoK8cSlK5fQTXXXlDVGfFXj0KUZUoYDFSTedcjJ6joZJ1T
4mdvB3rlvtlERE8gwt0+Ds3EaYL46nU1aT8/rK6WiCE1BQa0z24OOsoyWty2B06p
4FQPDZ8VExoVX01Omn9ZkObyuQKBgQDilXzDyV9fsBU7HYMixM9AYyvxcG3VqkEA
1CEKPHrD5AoCqE4zoq72XLTn3llV4GvGTGQfH6z+0vjBX0HUEqT2cZv8NReRrg+c
pZRTVFSLzLFK7Bb0V/pK/zGMcbU+zxwe7y7yimrDGnu+t/YjdGfHfi5/rR2VvsdQ
cQOlr93F2QKBgDgxMx3TTI0XIME4HsJPY+dK1M62PF7n5StkZgLgG6pYjZryDAp4
O9f/KXaF5NehEWNSV+Z340XIWofTnorAjuv3mrzwGc4iVq4trFPPb7gWm8A6kGh4
7KYZSJfcTuY5sWgc9HwKwzMe/vDoaODCgb2djTG0n3G7LuhCd0Fy5a/xAoGBANsQ
cDnSfXVEBqLK27hH06CKwTeC3Y4QNxyX+wGsi3zNAqijFEhz5villPoATRrsCQcF
YF9+/oC4dGxwrnJdPERQfuEOa6UbRljK9WbDR6KJ2nd3XpIKZSERLVR9sx/wmV2H
Hjq8fI/5EN7JeR26M4P6iPZD5zCZ7JXnTgFo0N+xAoGAPoMFe/v+QktYyrKg6po+
ZaOHyN9Wr2d8ZhB3BZn5AxqXS7Vgosoy60mtReEqkkK4q1uAh8ouf3rCBcXObzrM
7bFa4ErgFzkzXFn9KChYUXlhcxffFKDaRtvNZ/ln0v56m37J+grOQoAeBez4L/iO
8kjdLYckqalB7UpeFUt99LM=
-----END PRIVATE KEY-----
PEM;

    private static ?string $publicKey = null;

    protected function getPackageProviders($app): array
    {
        return [KeycloakAuthServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('cache.default', 'array');
        $app['config']->set('keycloak.cache.enabled', true);
        $app['config']->set('keycloak.cache.store', 'default');
        $app['config']->set('keycloak.cache.prefix', 'keycloak_guard_tests');
        $app['config']->set('keycloak.keycloak.public_key', static::publicKey());
        $app['config']->set('keycloak.keycloak.token_encryption_algorithm', 'RS256');
        $app['config']->set('keycloak.keycloak.leeway', 0);
        $app['config']->set('keycloak.user_provider.identifier_column', 'keycloak_id');
        $app['config']->set('keycloak.user_provider.token_claim', 'sub');
    }

    protected function makeRequest(?string $token = null): Request
    {
        $server = [];

        if ($token !== null) {
            $server['HTTP_AUTHORIZATION'] = 'Bearer '.$token;
        }

        return Request::create('/', 'GET', server: $server);
    }

    protected function makeToken(array $claims = []): string
    {
        $payload = array_merge([
            'sub' => 'keycloak-user',
            'jti' => 'token-123',
            'exp' => time() + 3600,
        ], $claims);

        return JWT::encode($payload, self::PRIVATE_KEY, 'RS256');
    }

    protected static function publicKey(): string
    {
        if (self::$publicKey !== null) {
            return self::$publicKey;
        }

        $resource = openssl_pkey_get_private(self::PRIVATE_KEY);
        $details = is_resource($resource) || $resource instanceof \OpenSSLAsymmetricKey
            ? openssl_pkey_get_details($resource)
            : false;

        if (!is_array($details) || !isset($details['key'])) {
            throw new \RuntimeException('Unable to derive public key for tests.');
        }

        return self::$publicKey = $details['key'];
    }
}
