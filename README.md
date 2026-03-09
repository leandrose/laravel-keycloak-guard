# Laravel Keycloak Guard

A lightweight **Laravel authentication guard** for applications acting as **OAuth2 / OpenID Connect resource servers using Keycloak**.

This package validates **Bearer tokens issued by Keycloak** by first verifying the JWT signature locally with the realm public key and then confirming the token through the **token introspection endpoint**.

It also provides **optional caching of introspection responses** to reduce load on the Keycloak server and improve API performance.

---

## Features

- Stateless **Bearer Token authentication**
- **Keycloak OAuth2 / OpenID Connect** integration
- Token validation via **local JWT verification** plus **introspection endpoint**
- Optional **introspection caching**
- Cache TTL automatically respecting token expiration (`exp`)
- Custom Laravel **Guard**
- Works with **Laravel 10, 11 and 12**

---

## Requirements

- PHP 8.2+
- Laravel 10 / 11 / 12
- Keycloak server with OAuth2 / OpenID Connect enabled
- Keycloak realm public key available to the application

---

## Installation

Install the package via Composer:

```bash
composer require leandrose/laravel-keycloak-guard
```

Publish the configuration file:

```bash
php artisan vendor:publish --provider="LeandroSe\\KeycloakGuard\\KeycloakAuthServiceProvider"
```

Add this to the `guards` array in `config/auth.php`:

```php
'guards' => [
    'keycloak' => [
        'driver' => 'keycloak',
        'provider' => 'users',
    ],
],
```

Configure the Keycloak connection in your environment:

```env
KEYCLOAK_BASE_URL=https://keycloak.example.com
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-client-id
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_REALM_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----"
```

`KEYCLOAK_REALM_PUBLIC_KEY` can be provided either as a full PEM or as the raw base64 body of the public key.
