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

namespace FOS\OAuthServerBundle\Storage;

use FOS\OAuthServerBundle\Model\AccessTokenManagerInterface;
use FOS\OAuthServerBundle\Model\AuthCodeInterface;
use FOS\OAuthServerBundle\Model\AuthCodeManagerInterface;
use FOS\OAuthServerBundle\Model\ClientInterface;
use FOS\OAuthServerBundle\Model\ClientManagerInterface;
use FOS\OAuthServerBundle\Model\RefreshTokenManagerInterface;
use OAuth2\IOAuth2GrantClient;
use OAuth2\IOAuth2GrantCode;
use OAuth2\IOAuth2GrantExtension;
use OAuth2\IOAuth2GrantImplicit;
use OAuth2\IOAuth2GrantUser;
use OAuth2\IOAuth2RefreshTokens;
use OAuth2\Model\IOAuth2AccessToken;
use OAuth2\Model\IOAuth2AuthCode;
use OAuth2\Model\IOAuth2Client;
use OAuth2\Model\IOAuth2RefreshToken;
use OAuth2\Model\IOAuth2Token;
use OAuth2\OAuth2;
use OAuth2\OAuth2ServerException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class OAuthStorage implements IOAuth2RefreshTokens, IOAuth2GrantUser, IOAuth2GrantCode, IOAuth2GrantImplicit, IOAuth2GrantClient, IOAuth2GrantExtension, GrantExtensionDispatcherInterface
{
    protected ClientManagerInterface $clientManager;
    protected AccessTokenManagerInterface $accessTokenManager;
    protected RefreshTokenManagerInterface $refreshTokenManager;
    protected AuthCodeManagerInterface $authCodeManager;
    protected ?UserProviderInterface $userProvider;
    protected PasswordHasherFactoryInterface $passwordHasherFactory;

    /**
     * @var array [uri] => GrantExtensionInterface
     */
    protected array $grantExtensions;

    public function __construct(
        ClientManagerInterface $clientManager,
        AccessTokenManagerInterface $accessTokenManager,
        RefreshTokenManagerInterface $refreshTokenManager,
        AuthCodeManagerInterface $authCodeManager,
        ?UserProviderInterface $userProvider = null,
        PasswordHasherFactoryInterface $passwordHasherFactory = null
    ) {
        $this->clientManager = $clientManager;
        $this->accessTokenManager = $accessTokenManager;
        $this->refreshTokenManager = $refreshTokenManager;
        $this->authCodeManager = $authCodeManager;
        $this->userProvider = $userProvider;
        $this->passwordHasherFactory = $passwordHasherFactory;

        $this->grantExtensions = [];
    }

    /**
     * {@inheritdoc}
     */
    public function setGrantExtension(string $uri, GrantExtensionInterface $grantExtension): void
    {
        $this->grantExtensions[$uri] = $grantExtension;
    }

    public function getClient(string $clientId): ?IOAuth2Client
    {
        return $this->clientManager->findClientByPublicId($clientId);
    }

    public function checkClientCredentials(IOAuth2Client $client, string $clientSecret = null): bool
    {
        if (!$client instanceof ClientInterface) {
            throw new \InvalidArgumentException('Client has to implement the ClientInterface');
        }

        return $client->checkSecret($clientSecret);
    }

    public function checkClientCredentialsGrant(IOAuth2Client $client, string $clientSecret): bool
    {
        return $this->checkClientCredentials($client, $clientSecret);
    }

    public function getAccessToken(string $oauthToken): ?IOAuth2AccessToken
    {
        return $this->accessTokenManager->findTokenByToken($oauthToken);
    }

    public function createAccessToken(
        string $oauth_token,
        IOAuth2Client $client,
        mixed $data,
        int $expires,
        string $scope = null
    ): IOAuth2AccessToken {
        if (!$client instanceof ClientInterface) {
            throw new \InvalidArgumentException('Client has to implement the ClientInterface');
        }

        $token = $this->accessTokenManager->createToken();
        $token->setToken($oauth_token);
        $token->setClient($client);
        $token->setExpiresAt($expires);
        $token->setScope($scope);

        if (null !== $data) {
            $token->setUser($data);
        }

        $this->accessTokenManager->updateToken($token);

        return $token;
    }

    public function checkRestrictedGrantType(IOAuth2Client $client, string $grantType): bool
    {
        if (!$client instanceof ClientInterface) {
            throw new \InvalidArgumentException('Client has to implement the ClientInterface');
        }

        return in_array($grantType, $client->getAllowedGrantTypes(), true);
    }

    public function checkUserCredentials(IOAuth2Client $client, string $username, string $password): array|bool
    {
        if (!$client instanceof ClientInterface) {
            throw new \InvalidArgumentException('Client has to implement the ClientInterface');
        }

        try {
            $user = $this->userProvider->loadUserByUsername($username);
        } catch (AuthenticationException $e) {
            return false;
        }

        /** @var PasswordHasherInterface $passwordHasher */
        $passwordHasher = $this->passwordHasherFactory->getPasswordHasher($user);
        if ($passwordHasher->verify($user->getPassword(), $password)) {
            return [
                'data' => $user,
            ];
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthCode(string $code): ?IOAuth2AuthCode
    {
        return $this->authCodeManager->findAuthCodeByToken($code);
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthCode(
        string        $code,
        IOAuth2Client $client,
        mixed         $data,
        string        $redirectUri,
        int           $expires,
        string        $scope = null
    ): AuthCodeInterface {
        if (!$client instanceof ClientInterface) {
            throw new \InvalidArgumentException('Client has to implement the ClientInterface');
        }

        $authCode = $this->authCodeManager->createAuthCode();
        $authCode->setToken($code);
        $authCode->setClient($client);
        $authCode->setUser($data);
        $authCode->setRedirectUri($redirectUri);
        $authCode->setExpiresAt($expires);
        $authCode->setScope($scope);
        $this->authCodeManager->updateAuthCode($authCode);

        return $authCode;
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshToken(string $refreshToken): ?IOAuth2RefreshToken
    {
        return $this->refreshTokenManager->findTokenByToken($refreshToken);
    }

    /**
     * {@inheritdoc}
     */
    public function createRefreshToken(
        string $refreshToken,
        IOAuth2Client $client,
        mixed $data,
        int $expires,
        string $scope = null
    ): IOAuth2RefreshToken {
        if (!$client instanceof ClientInterface) {
            throw new \InvalidArgumentException('Client has to implement the ClientInterface');
        }

        $token = $this->refreshTokenManager->createToken();
        $token->setToken($refreshToken);
        $token->setClient($client);
        $token->setExpiresAt($expires);
        $token->setScope($scope);

        if (null !== $data) {
            $token->setUser($data);
        }

        $this->refreshTokenManager->updateToken($token);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function unsetRefreshToken(string $refreshToken): void
    {
        $token = $this->refreshTokenManager->findTokenByToken($refreshToken);

        if (null !== $token) {
            $this->refreshTokenManager->deleteToken($token);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkGrantExtension(IOAuth2Client $client, string $uri, array $inputData, array $authHeaders): bool|array
    {
        $grantExtension = $this->grantExtensions[$uri];

        if (!isset($this->grantExtensions[$uri])) {
            throw new OAuth2ServerException(Response::HTTP_BAD_REQUEST, OAuth2::ERROR_UNSUPPORTED_GRANT_TYPE);
        }


        return $grantExtension->checkGrantExtension($client, $inputData, $authHeaders);
    }

    /**
     * {@inheritdoc}
     */
    public function markAuthCodeAsUsed(string $code): void
    {
        $authCode = $this->authCodeManager->findAuthCodeByToken($code);
        if (null !== $authCode) {
            $this->authCodeManager->deleteAuthCode($authCode);
        }
    }
}
