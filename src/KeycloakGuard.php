<?php

namespace LeandroSe\KeycloakGuard;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use LeandroSe\KeycloakGuard\Exceptions\KeycloakGuardException;
use LeandroSe\KeycloakGuard\Exceptions\TokenException;
use LeandroSe\KeycloakGuard\Exceptions\UnauthenticatedException;
use stdClass;
use Throwable;

class KeycloakGuard implements Guard
{
    use ActingAsCache;
    use ActingAsKeycloak;

    protected Authenticatable|null $user = null;
    protected bool $authenticationAttempted = false;
    protected UserProvider $provider;
    protected ?string $token = null;
    protected ?stdClass $decodedToken = null;
    protected Request $request;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Decode token, validate and authenticate user
     *
     * @throws TokenException
     * @throws UnauthenticatedException
     * @throws KeycloakGuardException
     */
    protected function authenticate()
    {
        if (!is_null($this->decodedToken)) {
            return;
        }

        $publicKey = config('keycloak.keycloak.public_key');

        if (!is_string($publicKey) || trim($publicKey) === '') {
            Log::warning('Keycloak public key is not configured.');

            throw new KeycloakGuardException('Keycloak public key is not configured.');
        }

        try {
            $decodedToken = Token::decode(
                $this->token = $this->getTokenForRequest(),
                $publicKey,
                config('keycloak.keycloak.leeway') ?? 0,
                config('keycloak.keycloak.token_encryption_algorithm') ?? 'RS256'
            );
            if (empty($decodedToken)) {
                throw new UnauthenticatedException('Unauthorized');
            }
        } catch (ExpiredException|BeforeValidException|SignatureInvalidException|\UnexpectedValueException $e) {
            throw new UnauthenticatedException('Unauthorized', (int) $e->getCode(), $e);
        } catch (UnauthenticatedException|KeycloakGuardException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new TokenException($e->getMessage(), $e->getCode(), $e);
        }

        $this->decodedToken = $decodedToken;
        $tokenClaim = config('keycloak.user_provider.token_claim', 'sub');
        $identifierColumn = config('keycloak.user_provider.identifier_column', 'keycloak_id');

        if (!isset($this->decodedToken->{$tokenClaim})) {
            throw new UnauthenticatedException('Unauthorized');
        }

        $this->validate([
            $identifierColumn => $this->decodedToken->{$tokenClaim},
        ]);
    }

    protected function ensureAuthenticated(): bool
    {
        if (!is_null($this->decodedToken)) {
            return true;
        }

        if ($this->authenticationAttempted) {
            return false;
        }

        $this->authenticationAttempted = true;

        if (!$this->getTokenForRequest()) {
            return false;
        }

        try {
            $this->authenticate();
        } catch (UnauthenticatedException $e) {
            return false;
        } catch (TokenException|KeycloakGuardException $e) {
            report($e);
            return false;
        }

        return !is_null($this->decodedToken);
    }

    /**
     * Get the token for the current request.
     *
     * @return string
     */
    public function getTokenForRequest()
    {
        return $this->request->bearerToken();
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the guard has a user instance.
     *
     * @return bool
     */
    public function hasUser()
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return !$this->check();
    }

    /**
     * Set the current user.
     *
     * @param Authenticatable $user
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return Authenticatable|null
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        if (!$this->ensureAuthenticated()) {
            return null;
        }

        return $this->user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|null
     */
    public function id()
    {
        if ($user = $this->user()) {
            return $user->getAuthIdentifier();
        }
        return null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     * @throws UnauthenticatedException
     * @throws KeycloakGuardException
     */
    public function validate(array $credentials = []): bool
    {
        if (!$this->token || !$this->decodedToken) {
            return false;
        }

        $cacheKey = $this->cacheKey();
        $cacheEnabled = config('keycloak.cache.enabled', true);

        if ($cacheEnabled && $this->has($cacheKey)) {
            if (!$this->get($cacheKey)) {
                return false;
            }
        } else {
            $active = $this->introspect($this->token);

            if ($cacheEnabled) {
                $this->put($cacheKey, $active, $this->cacheTtl($active));
            }

            if (!$active) {
                return false;
            }
        }

        $user = $this->provider->retrieveByCredentials($credentials);
        if (!$user) {
            return false;
        }

        $this->setUser($user);

        return true;
    }

    /**
     * Check if authenticated user has a especific role into resource
     * @param string $resource
     * @param string $role
     * @return bool
     */
    public function hasRole($resource, $role)
    {
        if (!$this->ensureAuthenticated()) {
            return false;
        }

        $token_resource_access = (array)($this->decodedToken->resource_access ?? []);

        if (array_key_exists($resource, $token_resource_access)) {
            $token_resource_values = (array)$token_resource_access[$resource];

            if (array_key_exists('roles', $token_resource_values) &&
                in_array($role, $token_resource_values['roles'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if authenticated user has a any role into resource
     * @param string $resource
     * @param string $role
     * @return bool
     */
    public function hasAnyRole($resource, array $roles)
    {
        if (!$this->ensureAuthenticated()) {
            return false;
        }

        $token_resource_access = (array)($this->decodedToken->resource_access ?? []);

        if (array_key_exists($resource, $token_resource_access)) {
            $token_resource_values = (array)$token_resource_access[$resource];

            if (array_key_exists('roles', $token_resource_values)) {
                foreach ($roles as $role) {
                    if (in_array($role, $token_resource_values['roles'])) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get scope(s)
     * @return array
     */
    public function scopes(): array
    {
        if (!$this->ensureAuthenticated()) {
            return [];
        }

        $scopes = $this->decodedToken->scope ?? null;

        if ($scopes) {
            return explode(' ', $scopes);
        }

        return [];
    }

    /**
     * Check if authenticated user has a especific scope
     * @param string $scope
     * @return bool
     */
    public function hasScope(string $scope): bool
    {
        $scopes = $this->scopes();

        if (in_array($scope, $scopes)) {
            return true;
        }

        return false;
    }

    /**
     * Check if authenticated user has a any scope
     * @param array $scopes
     * @return bool
     */
    public function hasAnyScope(array $scopes): bool
    {
        return count(array_intersect(
                $this->scopes(),
                $scopes
            )) > 0;
    }
}
