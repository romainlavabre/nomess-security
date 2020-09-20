<?php


namespace Nomess\Component\Security\Validator;


use Nomess\Component\Security\User\SecurityUser;

interface PasswordHandlerInterface
{
    
    public function isValidPassword( string $password, SecurityUser $securityUser ): bool;
    
    
    public function encode( $password, SecurityUser $securityUser ): bool;
}
