<?php

namespace LeandroSe\KeycloakGuard;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use LeandroSe\KeycloakGuard\Exceptions\KeycloakGuardException;
use Throwable;

trait ActingAsKeycloak
{

    public function introspect(string $token): bool
    {
        $client = new Client([
            'base_uri' => rtrim(config('keycloak.keycloak.base_url'), '/') . '/',
            'timeout' => config('keycloak.keycloak.timeout') ?? 5,
        ]);

        try {
            $response = $client->post(sprintf(
                'realms/%s/protocol/openid-connect/token/introspect',
                config('keycloak.keycloak.realm')
            ), [
                'form_params' => [
                    'token' => $token,
                    'client_id' => config('keycloak.keycloak.client_id'),
                    'client_secret' => config('keycloak.keycloak.client_secret'),
                ],
            ]);
        } catch (GuzzleException $e) {
            throw new KeycloakGuardException('Keycloak introspection request failed.', (int) $e->getCode(), $e);
        }

        try {
            $payload = json_decode((string)$response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            throw new KeycloakGuardException('Invalid Keycloak introspection response.', (int) $e->getCode(), $e);
        }

        return (bool)($payload['active'] ?? false);
    }
}
