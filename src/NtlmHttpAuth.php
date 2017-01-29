<?php
namespace SiViN\NtlmHttpAuth;

use Nette\Application\IRouter;
use Nette\DI\CompilerExtension;
use Nette\Http\IRequest;
use Nette\Http\IResponse;
use Nette\Http\Session;
use Nette\Http\SessionSection;
use Nette\Security\IAuthenticator;
use Nette\Security\User;
use SiViN\NtlmHttpAuth\Parsers\NtlmParser;

class NtlmHttpAuth extends CompilerExtension
{
    /** @var  IRequest */
    protected $httpRequest;

    /** @var  IResponse */
    protected $httpReponse;

    /** @var  NtlmParser */
    protected $ntlmParser;

    /** @var  SessionSection */
    protected $sessionSection;

    /** @var IAuthenticator */
    protected $authenticator;

    /** @var  User */
    protected $user;

    /**
     * NtlmHttpAuth constructor.
     * @param array $excludedPresenters
     * @param IRouter $router
     * @param IRequest $httpRequest
     * @param IResponse $httpResponse
     * @param NtlmParser $ntlmParser
     * @param Session $session
     * @param IAuthenticator $authenticator
     * @param User $user
     * @internal param SessionSection $sessionSection
     */
    public function __construct(
        array $excludedPresenters,
        IRouter $router,
        IRequest $httpRequest,
        IResponse $httpResponse,
        NtlmParser $ntlmParser,
        Session $session,
        IAuthenticator $authenticator,
        User $user
    )
    {
        $this->httpRequest = $httpRequest;
        $this->httpReponse = $httpResponse;
        $this->ntlmParser = $ntlmParser;
        $this->sessionSection = $session->getSection("authenticate");
        $this->sessionSection->setExpiration(0);
        $this->authenticator = $authenticator;
        $this->user = $user;

        if (!($this->authenticator instanceof INtlmAuthenticator)) {
            throw new NotImplementedException("Authenticator does not implement an interface INtlmAuthenticator");
        }

        try {
            $request = $router->match($httpRequest);
        } catch (\exception $ex) {
            return;
        }

        if (!in_array($request->getPresenterName(), $excludedPresenters)) {
            $authorizationHeader = $this->httpRequest->getHeader("authorization");
            if ($authorizationHeader !== null) {
                $this->user->logout(true);
                if (substr($authorizationHeader, 0, 5) === 'NTLM ') {
                    $this->authenticate($this->ntlmParser, $authorizationHeader);
                } else {
                    $this->unknownExit();
                }
            } else {
                if ($this->sessionSection->offsetExists("authenticate")) {
                    /** @noinspection PhpUndefinedFieldInspection */
                    //return $this->sessionSection->authenticate;
                    return;
                }
                $this->authExit();
            }
        }
    }

    /**
     * @param IAuthorizationHeaderParser $parser
     * @param string $authorizationHeader
     */
    private function authenticate(IAuthorizationHeaderParser $parser, $authorizationHeader)
    {
        try {
            $authRes = $parser->parse($authorizationHeader);
            /** @var INtlmAuthenticator $ntlmAuth */
            $ntlmAuth = $this->authenticator;
            $identity = $ntlmAuth->ntlmAuthenticate($authRes);
            /** @noinspection PhpUndefinedFieldInspection */
            $this->sessionSection->authenticate = $authRes->toArray();
            $this->user->login($identity);
            $this->user->setExpiration(0, true, true);
        } catch (\Exception $ex) {
            $this->unknownExit($ex);
        }
    }

    /**
     * @param \Exception $ex
     */
    private function unknownExit(\Exception $ex = null)
    {
        $this->httpReponse->setCode(IResponse::S401_UNAUTHORIZED);
        echo '<h1>Unknown authorization</h1>';
        if ($ex !== null) {
            echo '<p>' . $ex->getMessage() . '</p>';
        }
        die;
    }

    private function authExit()
    {
        $this->httpReponse->setHeader('WWW-Authenticate', 'NTLM');
        $this->httpReponse->setCode(IResponse::S401_UNAUTHORIZED);
        echo '<h1>Authentication failed</h1>';
        die;
    }
}