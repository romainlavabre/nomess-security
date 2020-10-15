<?php


namespace Nomess\Component\Security\User;


use Nomess\Component\Orm\EntityManagerInterface;
use Nomess\Http\HttpSession;

class GetUser implements UserInterface
{
    
    private const INDEX_SESSION = 'security_user';
    private HttpSession            $session;
    private EntityManagerInterface $entityManager;
    
    
    public function __construct(
        HttpSession $session,
        EntityManagerInterface $entityManager )
    {
        $this->session       = $session;
        $this->entityManager = $entityManager;
    }
    
    
    public function getUser( bool $reload = TRUE ): ?SecurityUser
    {
        if( $this->session->has( self::INDEX_SESSION ) ) {
            
            /** @var SecurityUser $securityUser */
            $securityUser = $this->session->get( self::INDEX_SESSION );
            
            if( $reload ) {
                $this->entityManager->find( get_class( $securityUser ), 'username = :username', [
                    'username' => $securityUser->getUsername()
                ] );
            }
            
            return $securityUser;
        }
        
        return NULL;
    }
}
