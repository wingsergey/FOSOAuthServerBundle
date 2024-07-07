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

interface TokenManagerInterface
{
    /**
     * Create a new TokenInterface.
     */
    public function createToken(): TokenInterface;

    /**
     * Return the class name of the Token.
     */
    public function getClass(): string;

    /**
     * Retrieve a token using a set of criteria.
     */
    public function findTokenBy(array $criteria): ?TokenInterface;

    /**
     * Retrieve a token (object) by its token string.
     */
    public function findTokenByToken(string $token): ?TokenInterface;

    /**
     * Save or update a given token.
     *
     * @param TokenInterface $token the token to save or update
     */
    public function updateToken(TokenInterface $token): void;

    /**
     * Delete a given token.
     *
     * @param TokenInterface $token the token to delete
     */
    public function deleteToken(TokenInterface $token): void;

    /**
     * Delete expired tokens.
     *
     * @return int the number of tokens deleted
     */
    public function deleteExpired(): int;
}
