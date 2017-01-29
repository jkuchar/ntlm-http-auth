<?php
namespace SiViN\NtlmHttpAuth;

use Nette\Security\IIdentity;

interface INtlmAuthenticator
{
    /**
     * @param AuthenticateResult $authenticateResult
     * @return IIdentity
     */
    public function ntlmAuthenticate(AuthenticateResult $authenticateResult);
}