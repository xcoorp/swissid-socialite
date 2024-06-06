<p align="center">
    <a href="https://www.xcoorp.com" target="_blank">
        <img src="https://www.xcoorp.com/wp-content/uploads/2021/05/logo_xcoorp_340-300x56.png" width="400" alt="XCoorp Logo">
    </a>
</p>

<p align="center">
    Swiss ID Socialite Plugin for Laravel
</p>


```bash
composer require xcoorp/swissid-socialite
```

## Installation & Basic Usage

Please see the [Base Installation Guide](https://socialiteproviders.com/usage/), then follow the provider specific instructions below.

### Add configuration to `config/services.php`

```php
'swissid' => [
    'client_id' => env('SWISSID_CLIENT_ID'),
    'client_secret' => env('SWISSID_CLIENT_SECRET'),
    'redirect' => env('SWISSID_REDIRECT_URL'),
    'base_url' => env('SWISSID_BASE_URL'),
    'issuer' => env('SWISSID_ISSUER'),
    'requested_authentication' => 'qoa2', // qoa1 = single factor authentication (username, password), qoa2 = two factor authentication required (username, password, sms code)
    'claims' => [                         // OPTIONAL: Specify additional claims to be requested
        'urn:swissid:qor' => [
            'value' => 'qor2',
        ],
    ],
],
```

### Add provider event listener

#### Laravel 11+

In Laravel 11, the default `EventServiceProvider` provider was removed. Instead, add the listener using the `listen` method on the `Event` facade, in your `AppServiceProvider` `boot` method.

* Note: You do not need to add anything for the built-in socialite providers unless you override them with your own providers.

```php
Event::listen(function (\SocialiteProviders\Manager\SocialiteWasCalled $event) {
    $event->extendSocialite('swissid', \XCoorp\SwissIDSocialite\Provider::class);
});
```
<details>
<summary>
Laravel 10 or below
</summary>
Configure the package's listener to listen for `SocialiteWasCalled` events.

Add the event to your `listen[]` array in `app/Providers/EventServiceProvider`. See the [Base Installation Guide](https://socialiteproviders.com/usage/) for detailed instructions.

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        \XCoorp\SwissIDSocialite\SwissIDExtendSocialite::class.'@handle',
    ],
];
```
</details>

### Usage

You should now be able to use the provider like you would regularly use Socialite (assuming you have the facade installed):

```php
return Socialite::driver('swissid')->redirect();
```
