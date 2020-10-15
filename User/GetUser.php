<?php


namespace Nomess\Component\Security\User;


use App\Repository\SectionRepository;
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
    
    
    public function getUser(bool $realod = TRUE): ?SecurityUser
    {
        if( $this->session->has( self::INDEX_SESSION ) ) {
    
            /** @var SecurityUser $secuityUser */
            $secuityUser = $this->session->get( self::INDEX_SESSION);
            
            if($realod){
                $this->entityManager->find( get_class($secuityUser), 'username = :username', [
                   'username' => $secuityUser->getUsername()
                ]);
            }
            
            return $secuityUser;
        }
        
        return NULL;
    }
}
