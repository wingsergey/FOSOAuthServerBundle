<?php

declare(strict_types=1);

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Security\Authentication\Provider;

use FOS\OAuthServerBundle\Security\Authentication\Token\OAuthToken;
use OAuth2\OAuth2;
use OAuth2\OAuth2AuthenticateException;
use OAuth2\OAuth2ServerException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * OAuthProvider class.
 *
 * @author  Arnaud Le Blanc <arnaud.lb@gmail.com>
 */
class OAuthProvider extends AbstractAuthenticator
{
    protected UserProviderInterface $userProvider;

    protected OAuth2 $serverService;

    protected UserCheckerInterface $userChecker;

    /**
     * @param UserProviderInterface $userProvider  the user provider
     * @param OAuth2                $serverService the OAuth2 server service
     * @param UserCheckerInterface  $userChecker   The Symfony User Checker for Pre and Post auth checks
     */
    public function __construct(
        UserProviderInterface $userProvider,
        OAuth2 $serverService,
        UserCheckerInterface $userChecker
    ) {
        $this->userProvider = $userProvider;
        $this->serverService = $serverService;
        $this->userChecker = $userChecker;
    }

    public function authenticate(Request $request): Passport
    {
        $token = $this->createTokenFromRequest($request);

        try {
            $tokenString = $token->getToken();

            $accessToken = $this->serverService->verifyAccessToken($tokenString);
            $user = $accessToken->getUser();

            if (null !== $user) {
                try {
                    $this->userChecker->checkPreAuth($user);
                } catch (AccountStatusException $e) {
                    throw new OAuth2AuthenticateException(Response::HTTP_UNAUTHORIZED, OAuth2::TOKEN_TYPE_BEARER, $this->serverService->getVariable(OAuth2::CONFIG_WWW_REALM), 'access_denied', $e->getMessage());
                }
            }

            if (null !== $user) {
                try {
                    $this->userChecker->checkPostAuth($user);
                } catch (AccountStatusException $e) {
                    throw new OAuth2AuthenticateException(Response::HTTP_UNAUTHORIZED, OAuth2::TOKEN_TYPE_BEARER, $this->serverService->getVariable(OAuth2::CONFIG_WWW_REALM), 'access_denied', $e->getMessage());
                }
            }

            $userIdentifier = $user->getUserIdentifier();
            $userBadge = new UserBadge($userIdentifier, function () use ($user) {
                return $user;
            });

            return new SelfValidatingPassport($userBadge);
        } catch (OAuth2ServerException $e) {
            throw new AuthenticationException('OAuth2 authentication failed', 0, $e);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function supports(Request $request): bool
    {
        return $this->createTokenFromRequest($request) instanceof OAuthToken;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return null;
    }

    protected function createTokenFromRequest(Request $request): OAuthToken
    {
        $tokenString = $request->get(OAuth2::TOKEN_PARAM_NAME);
        $token = new OAuthToken();
        $token->setToken($tokenString);

        return $token;
    }
}
