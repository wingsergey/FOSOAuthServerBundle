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

/**
 * @author Richard Fullmer <richard.fullmer@opensoftdev.com>
 */
interface AuthCodeManagerInterface
{
    public function createAuthCode(): AuthCodeInterface;

    /**
     * Return the class name.
     */
    public function getClass(): string;

    /**
     * Retrieve an auth code using a set of criteria.
     */
    public function findAuthCodeBy(array $criteria): ?AuthCodeInterface;

    /**
     * Retrieve an auth code by its token.
     *
     * @param string $token
     *
     * @return AuthCodeInterface|null
     */
    public function findAuthCodeByToken(string $token): ?AuthCodeInterface;

    /**
     * Update a given auth code.
     */
    public function updateAuthCode(AuthCodeInterface $authCode): void;

    /**
     * Delete a given auth code.
     */
    public function deleteAuthCode(AuthCodeInterface $authCode): void;

    /**
     * Delete expired auth codes.
     *
     * @return int the number of auth codes deleted
     */
    public function deleteExpired(): int;
}
