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

use Symfony\Component\Security\Core\User\UserInterface;

class Token implements TokenInterface
{
    protected int $id;
    
    protected ClientInterface $client;
    
    protected string $token;
    
    protected int $expiresAt;
    
    protected ?string $scope;
    
    protected UserInterface $user;

    public function getId(): int
    {
        return $this->id;
    }

    public function getClientId(): string
    {
        return $this->getClient()->getPublicId();
    }

    public function setExpiresAt(int $timestamp): void
    {
        $this->expiresAt = $timestamp;
    }

    public function getExpiresAt(): int
    {
        return $this->expiresAt;
    }

    public function getExpiresIn(): int
    {
        if ($this->expiresAt) {
            return $this->expiresAt - time();
        }

        return PHP_INT_MAX;
    }

    public function hasExpired(): bool
    {
        if ($this->expiresAt) {
            return time() > $this->expiresAt;
        }

        return false;
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function setScope(?string $scope): void
    {
        $this->scope = $scope;
    }

    public function getScope(): string|null
    {
        return $this->scope;
    }

    public function setUser(UserInterface $user): void
    {
        $this->user = $user;
    }

    public function getUser(): UserInterface
    {
        return $this->user;
    }

    public function getData(): mixed
    {
        return $this->getUser();
    }

    public function setClient(ClientInterface $client): void
    {
        $this->client = $client;
    }

    public function getClient(): ClientInterface
    {
        return $this->client;
    }
}
