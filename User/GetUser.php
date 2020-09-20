<?php


namespace Nomess\Component\Security\User;


use Nomess\Http\HttpSession;

class GetUser implements UserInterface
{
    
    private HttpSession $session;
    
    
    public function __construct( HttpSession $session )
    {
        $this->session = $session;
    }
    
    
    public function getUser(): ?SecurityUser
    {
        if( $this->session->has( 'security_user' ) ) {
            return $this->session->get( 'security_user' );
        }
        
        return NULL;
    }
}
