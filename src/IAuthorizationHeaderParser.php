<?php
namespace SiViN\NtlmHttpAuth;

interface IAuthorizationHeaderParser
{
    /**
     * @param string $authHeader
     * @return AuthenticateResult
     * @throws HeaderRecognisedException
     */
    function parse($authHeader);
}