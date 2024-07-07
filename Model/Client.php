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

namespace FOS\OAuthServerBundle\Model;

use FOS\OAuthServerBundle\Util\Random;
use OAuth2\OAuth2;

abstract class Client implements ClientInterface
{
    protected $id;

    protected string $randomId;

    protected string $secret;

    protected array $redirectUris = [];

    protected array $allowedGrantTypes = [];

    public function __construct()
    {
        $this->allowedGrantTypes[] = OAuth2::GRANT_TYPE_AUTH_CODE;

        $this->setRandomId(Random::generateToken());
        $this->setSecret(Random::generateToken());
    }

    public function getId()
    {
        return $this->id;
    }

    public function setRandomId(string $randomId): void
    {
        $this->randomId = $randomId;
    }

    public function getRandomId(): string
    {
        return $this->randomId;
    }

    public function getPublicId(): string
    {
        return sprintf('%s_%s', $this->getId(), $this->getRandomId());
    }

    public function setSecret(string $secret): void
    {
        $this->secret = $secret;
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    public function checkSecret(string $secret): bool
    {
        return null === $this->secret || $secret === $this->secret;
    }

    public function setRedirectUris(array $redirectUris): void
    {
        $this->redirectUris = $redirectUris;
    }

    public function getRedirectUris(): array
    {
        return $this->redirectUris;
    }

    public function setAllowedGrantTypes(array $grantTypes): void
    {
        $this->allowedGrantTypes = $grantTypes;
    }

    public function getAllowedGrantTypes(): array
    {
        return $this->allowedGrantTypes;
    }
}
