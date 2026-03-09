<?php

namespace LeandroSe\KeycloakGuard;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;

trait ActingAsCache
{
    private ?Repository $store = null;

    private function instance(): Repository
    {
        if (!$this->store) {
            return $this->store = Cache::store($this->resolveStore());
        }

        return $this->store;
    }

    private function resolveStore(): ?string
    {
        $store = config('keycloak.cache.store');

        if (empty($store) || $store === 'default') {
            return null;
        }

        return is_array(config("cache.stores.{$store}")) ? $store : null;
    }

    protected function put(string $token, bool $active = true, ?int $ttl = null): void
    {
        $this->instance()->put(sprintf(
            '%s:%s',
            config('keycloak.cache.prefix'),
            $token,
        ), $active, $ttl ?? config('keycloak.cache.ttl'));
    }

    protected function has(string $token): bool
    {
        return $this->instance()->has(sprintf(
            '%s:%s',
            config('keycloak.cache.prefix'),
            $token,
        ));
    }

    protected function get(string $token): mixed
    {
        return $this->instance()->get(sprintf(
            '%s:%s',
            config('keycloak.cache.prefix'),
            $token,
        ));
    }

    protected function cacheKey(): string
    {
        return $this->decodedToken->jti ?? hash('sha256', (string)$this->token);
    }

    protected function cacheTtl(bool $active): int
    {
        if (!$active) {
            return (int)config('keycloak.cache.negative_ttl', 10);
        }

        $ttl = (int)config('keycloak.cache.ttl', 300);

        if (!config('keycloak.cache.respect_token_exp', true)) {
            return $ttl;
        }

        $exp = $this->decodedToken->exp ?? null;
        if (!is_numeric($exp)) {
            return $ttl;
        }

        $remaining = max(0, (int)$exp - time());

        return $remaining > 0 ? min($ttl, $remaining) : 0;
    }
}
