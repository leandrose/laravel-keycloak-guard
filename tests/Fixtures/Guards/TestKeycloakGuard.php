<?php

namespace LeandroSe\KeycloakGuard\Tests\Fixtures\Guards;

use LeandroSe\KeycloakGuard\Exceptions\KeycloakGuardException;
use LeandroSe\KeycloakGuard\KeycloakGuard;

class TestKeycloakGuard extends KeycloakGuard
{
    public static int $introspectionCalls = 0;
    public static bool $active = true;
    public static ?KeycloakGuardException $introspectionException = null;

    public static function resetState(): void
    {
        self::$introspectionCalls = 0;
        self::$active = true;
        self::$introspectionException = null;
    }

    public function introspect(string $token): bool
    {
        self::$introspectionCalls++;

        if (self::$introspectionException !== null) {
            throw self::$introspectionException;
        }

        return self::$active;
    }
}
