<?php

namespace LeandroSe\KeycloakGuard;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class KeycloakAuthServiceProvider extends ServiceProvider
{

    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/keycloak.php', 'keycloak');
    }

    public function boot()
    {
        $this->publishes([
            __DIR__ . '/../config/keycloak.php' => config_path('keycloak.php'),
        ]);

        Auth::extend('keycloak', function ($app, $name, array $config) {
            return new KeycloakGuard(Auth::createUserProvider($config['provider']), $app->request);
        });
    }
}