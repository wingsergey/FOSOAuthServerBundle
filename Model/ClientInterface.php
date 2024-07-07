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

use OAuth2\Model\IOAuth2Client;

interface ClientInterface extends IOAuth2Client
{
    public function setRandomId(string $randomId): void;

    public function getRandomId(): string;

    public function setSecret(string $secret): void;

    public function checkSecret(string $secret): bool;

    public function getSecret(): string;

    public function setRedirectUris(array $redirectUris): void;

    public function setAllowedGrantTypes(array $grantTypes): void;

    public function getAllowedGrantTypes(): array;
}
