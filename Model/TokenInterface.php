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

use OAuth2\Model\IOAuth2Token;
use Symfony\Component\Security\Core\User\UserInterface;

interface TokenInterface extends IOAuth2Token
{
    public function setExpiresAt(int $timestamp): void;

    public function getExpiresAt(): int;

    public function setToken(string $token): void;

    public function setScope(?string $scope): void;

    public function setUser(UserInterface $user): void;

    public function getUser(): UserInterface;

    public function setClient(ClientInterface $client): void;
}
