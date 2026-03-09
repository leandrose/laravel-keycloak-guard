<?php

namespace LeandroSe\KeycloakGuard\Tests\Fixtures\Auth;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

class InMemoryUserProvider implements UserProvider
{
    /**
     * @param  array<int, array<string, mixed>>  $users
     */
    public function __construct(private array $users)
    {
    }

    public function retrieveById($identifier): ?Authenticatable
    {
        foreach ($this->users as $user) {
            if (($user['id'] ?? null) === $identifier) {
                return new GenericUser($user);
            }
        }

        return null;
    }

    public function retrieveByToken($identifier, #[\SensitiveParameter] $token): ?Authenticatable
    {
        return null;
    }

    public function updateRememberToken(Authenticatable $user, #[\SensitiveParameter] $token): void
    {
    }

    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        foreach ($this->users as $user) {
            foreach ($credentials as $key => $value) {
                if (($user[$key] ?? null) !== $value) {
                    continue 2;
                }
            }

            return new GenericUser($user);
        }

        return null;
    }

    public function validateCredentials(Authenticatable $user, #[\SensitiveParameter] array $credentials): bool
    {
        return true;
    }

    public function rehashPasswordIfRequired(Authenticatable $user, #[\SensitiveParameter] array $credentials, bool $force = false): void
    {
    }
}
