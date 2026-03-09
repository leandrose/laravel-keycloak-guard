<?php

namespace LeandroSe\KeycloakGuard\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use LeandroSe\KeycloakGuard\Tests\Fixtures\Guards\TestKeycloakGuard;
use LeandroSe\KeycloakGuard\Tests\Fixtures\Models\User;

class KeycloakGuardDatabaseTest extends DatabaseTestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            $this->markTestSkipped('pdo_sqlite is required for database integration tests.');
        }

        parent::setUp();

        TestKeycloakGuard::resetState();
    }

    public function test_user_can_be_loaded_from_eloquent_provider(): void
    {
        $user = User::factory()->create([
            'keycloak_id' => 'kc-eloquent',
        ]);

        $guard = new TestKeycloakGuard(
            auth()->createUserProvider('users'),
            $this->makeRequest(
                $this->makeToken(['sub' => 'kc-eloquent', 'jti' => 'db-user-token'])
            ),
        );

        $resolved = $guard->user();

        $this->assertInstanceOf(User::class, $resolved);
        $this->assertSame($user->id, $resolved->id);
    }
}
