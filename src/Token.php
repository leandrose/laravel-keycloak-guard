<?php

namespace LeandroSe\KeycloakGuard;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Token
{

    public static function decode(?string $token, string $publicKey, int $leeway = 0, string $algorithm = 'RS256')
    {
        JWT::$leeway = $leeway;
        $publicKey = self::buildPublicKey($publicKey);

        return $token ? JWT::decode($token, new Key($publicKey, $algorithm)) : null;
    }

    private static function buildPublicKey(string $key)
    {
        $key = self::plainPublicKey($key);

        return sprintf(
            "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
            wordwrap($key, 64, "\n", true),
        );
    }

    public static function plainPublicKey(string $key): string
    {
        $string = str_replace('-----BEGIN PUBLIC KEY-----', '', $key);
        $string = str_replace('-----END PUBLIC KEY-----', '', $string);
        $string = str_replace(["\r", "\n"], '', $string);

        return trim($string);
    }
}
