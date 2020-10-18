<?php


namespace Nomess\Component\Security\Provider;


use Nomess\Component\Security\Exception\SecurityException;
use Nomess\Component\Security\User\SecurityUser;

/**
 * @author Romain Lavabre <webmaster@newwebsouth.fr>
 */
interface UserProviderInterface
{
    
    /**
     * Return id of user
     *
     * @return int
     * @throws SecurityException
     */
    public function getIdentifier(): int;
    
    
    /**
     * Return a array of roles (containing child roles)
     *
     * @return array
     * @throws SecurityException
     */
    public function getRoles(): array;
    
    
    /**
     * Return classname of security user
     *
     * @return string
     * @throws SecurityException
     */
    public function getClassname(): string;
    
    
    /**
     * Return true if a user is connected
     *
     * @return bool
     */
    public function hasSecurityUser(): bool;
    
    
    /**
     * Register of client
     *
     * @param SecurityUser $securityUser
     */
    public function clientRegister( SecurityUser $securityUser ): void;
}
