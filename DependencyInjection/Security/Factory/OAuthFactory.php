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

namespace FOS\OAuthServerBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AuthenticatorFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * OAuthFactory class.
 *
 * @author Arnaud Le Blanc <arnaud.lb@gmail.com>
 */
class OAuthFactory implements AuthenticatorFactoryInterface
{
    public function getPosition(): string
    {
        return 'pre_auth';
    }

    public function getPriority(): int
    {
        return 0;
    }

    /**
     * {@inheritdoc}
     */
    public function getKey(): string
    {
        return 'fos_oauth';
    }

    /**
     * {@inheritdoc}
     */
    public function addConfiguration(NodeDefinition $node): void
    {
    }

    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): array|string
    {
        $providerId = 'security.authentication.provider.fos_oauth_server.'.$firewallName;
        $container
            ->setDefinition($providerId, new ChildDefinition('fos_oauth_server.security.authentication.provider'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(2, new Reference('security.user_checker.'.$firewallName))
        ;

        $listenerId = 'security.authentication.listener.fos_oauth_server.'.$firewallName;
        $container->setDefinition($listenerId, new ChildDefinition('fos_oauth_server.security.authentication.listener'));

        return [$providerId, $listenerId, 'fos_oauth_server.security.entry_point'];
    }
}
