[![License](https://poser.pugx.org/sivin/ntlm-http-auth/license)](https://packagist.org/packages/sivin/simple-http-auth)
[![Total Downloads](https://poser.pugx.org/sivin/ntlm-http-auth/downloads)](https://packagist.org/packages/sivin/ntlm-http-auth)

NtlmHttpAuth
============

1. Install via composer
```yaml
composer require sivin/ntlm-http-auth
```

2. Register extension in `config.neon`:
```php
extensions:
	ntlmHttpAuth: SiViN\NtlmHttpAuth\DI\NtlmHttpAuthExtension
```

3, Tell which presenters should not be secured (in case no presenter name given, all presenters are secured). Format - `Module:Presenter`:
```php
ntlmHttpAuth:
	excludedPresenters: [Front:Nonsecured] # Exlude presenter class App\FrontModule\Presenters\NonsecuredPresenter
```

4, Implement `SiViN\NtlmHttpAuth\INtlmAuthenticator` to your authenticator
In`config.neon`:
```php
services:
	authenticator: NtlmAuthenticator
```
File `NtlmAuthenticator.php`:
```php
class NtlmAuthenticator implements \Nette\Security\IAuthenticator, \SiViN\NtlmHttpAuth\INtlmAuthenticator
{
    function authenticate(array $credentials)
    {
        ...
    }

    function ntlmAuthenticate(\SiViN\NtlmHttpAuth\AuthenticateResult $authenticateResult)
    {
        if($this->LdapOrDbOrSomething($authenticateResult->username, $authenticateResult->domain, $authenticateResult->workstation))
        {
            return new \Nette\Security\Identity(...);
        }
        else
        {
            throw new \Nette\Security\AuthenticationException('User not found', self::IDENTITY_NOT_FOUND);
        }
    }
}
```