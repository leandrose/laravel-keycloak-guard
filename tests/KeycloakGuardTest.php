<?php

namespace LeandroSe\KeycloakGuard\Tests;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use LeandroSe\KeycloakGuard\Tests\Fixtures\Auth\InMemoryUserProvider;
use LeandroSe\KeycloakGuard\Tests\Fixtures\Guards\TestKeycloakGuard;

class KeycloakGuardTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Cache::store()->flush();
        TestKeycloakGuard::resetState();
    }

    public function test_user_returns_null_without_bearer_token(): void
    {
        $guard = $this->makeGuard();

        $this->assertNull($guard->user());
        $this->assertSame(0, TestKeycloakGuard::$introspectionCalls);
    }

    public function test_user_returns_authenticated_user_for_valid_token(): void
    {
        $guard = $this->makeGuard(
            token: $this->makeToken(['sub' => 'kc-1', 'jti' => 'token-valid'])
        );

        $user = $guard->user();

        $this->assertNotNull($user);
        $this->assertSame('kc-1', $user->keycloak_id);
        $this->assertSame(1, TestKeycloakGuard::$introspectionCalls);
    }

    public function test_role_and_scope_helpers_trigger_lazy_authentication(): void
    {
        $token = $this->makeToken([
            'sub' => 'kc-1',
            'jti' => 'token-role-scope',
            'scope' => 'read write',
            'resource_access' => [
                'portal' => [
                    'roles' => ['admin', 'viewer'],
                ],
            ],
        ]);

        $guard = $this->makeGuard(token: $token);

        $this->assertTrue($guard->hasRole('portal', 'admin'));
        $this->assertTrue($guard->hasAnyRole('portal', ['editor', 'viewer']));
        $this->assertSame(['read', 'write'], $guard->scopes());
        $this->assertTrue($guard->hasScope('read'));
        $this->assertTrue($guard->hasAnyScope(['delete', 'write']));
        $this->assertSame(1, TestKeycloakGuard::$introspectionCalls);
    }

    public function test_inactive_token_returns_null_user(): void
    {
        TestKeycloakGuard::$active = false;

        $guard = $this->makeGuard(
            token: $this->makeToken(['sub' => 'kc-1', 'jti' => 'token-inactive'])
        );

        $this->assertNull($guard->user());
        $this->assertFalse($guard->check());
        $this->assertSame(1, TestKeycloakGuard::$introspectionCalls);
    }

    public function test_missing_public_key_logs_warning_and_returns_null(): void
    {
        Log::spy();
        config()->set('keycloak.keycloak.public_key', null);

        $guard = $this->makeGuard(
            token: $this->makeToken(['sub' => 'kc-1', 'jti' => 'token-missing-key'])
        );

        $this->assertNull($guard->user());
        Log::shouldHaveReceived('warning')->once()->with('Keycloak public key is not configured.');
    }

    public function test_cache_falls_back_to_default_store_and_skips_second_introspection(): void
    {
        config()->set('keycloak.cache.store', 'missing-store');
        $token = $this->makeToken(['sub' => 'kc-1', 'jti' => 'shared-cache-key']);

        $firstGuard = $this->makeGuard(token: $token);
        $this->assertNotNull($firstGuard->user());
        $this->assertSame(1, TestKeycloakGuard::$introspectionCalls);

        TestKeycloakGuard::$active = false;

        $secondGuard = $this->makeGuard(token: $token);

        $this->assertNotNull($secondGuard->user());
        $this->assertSame(1, TestKeycloakGuard::$introspectionCalls);
        $this->assertTrue(Cache::store()->has('keycloak_guard_tests:shared-cache-key'));
    }

    private function makeGuard(?string $token = null): TestKeycloakGuard
    {
        return new TestKeycloakGuard(
            $this->makeProvider(),
            $this->makeRequest($token),
        );
    }

    private function makeProvider(): InMemoryUserProvider
    {
        return new InMemoryUserProvider([
            [
                'id' => 1,
                'name' => 'Test User',
                'email' => 'test@example.com',
                'keycloak_id' => 'kc-1',
            ],
        ]);
    }
}
