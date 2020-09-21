<?php


namespace Nomess\Component\Security\Validator;


use Nomess\Component\Security\User\SecurityUser;

interface CredentialsValidatorInterface
{
    
    /**
     * Return last error.
     *
     * @return string|null
     */
    public function getError(): ?string;
    
    
    /**
     * Control the valid credentials of user,
     * If true, push in session
     * If false, the error is automatically added in request
     *
     * @param string $classname
     * @return bool
     */
    public function isValidCredential( string $classname ): bool;
    
    
    /**
     * Add user in session without passed by credentials
     *
     * @param SecurityUser $securityUser
     * @return $this
     */
    public function addUser( SecurityUser $securityUser ): self;
}
