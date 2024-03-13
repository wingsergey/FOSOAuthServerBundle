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

namespace FOS\OAuthServerBundle\Entity;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use FOS\OAuthServerBundle\Model\ClientInterface;
use FOS\OAuthServerBundle\Model\ClientManager as BaseClientManager;

class ClientManager extends BaseClientManager
{
    protected EntityManagerInterface $em;
    
    protected EntityRepository $repository;
    
    protected string $class;

    public function __construct(EntityManagerInterface $em, string $class)
    {
        // NOTE: bug in Doctrine, hinting EntityRepository|ObjectRepository when only EntityRepository is expected
        /** @var EntityRepository $repository */
        $repository = $em->getRepository($class);

        $this->em = $em;
        $this->repository = $repository;
        $this->class = $class;
    }

    public function getClass(): string
    {
        return $this->class;
    }

    public function findClientBy(array $criteria): ?ClientInterface
    {
        return $this->repository->findOneBy($criteria);
    }

    public function updateClient(ClientInterface $client): void
    {
        $this->em->persist($client);
        $this->em->flush();
    }

    public function deleteClient(ClientInterface $client): void
    {
        $this->em->remove($client);
        $this->em->flush();
    }
}
