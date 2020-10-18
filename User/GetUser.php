<?php


namespace Nomess\Component\Security\User;


use Nomess\Component\Orm\EntityManagerInterface;
use Nomess\Component\Security\Provider\UserProviderInterface;

class GetUser implements UserInterface
{
    
    private UserProviderInterface  $userProvider;
    private EntityManagerInterface $entityManager;
    
    
    public function __construct(
        UserProviderInterface $userProvider,
        EntityManagerInterface $entityManager )
    {
        $this->userProvider  = $userProvider;
        $this->entityManager = $entityManager;
    }
    
    
    public function getUser(): ?SecurityUser
    {
        return $this->entityManager->find( $this->userProvider->getClassname(), $this->userProvider->getIdentifier() );
    }
}
