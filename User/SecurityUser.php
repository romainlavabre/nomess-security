<?php


namespace Nomess\Component\Security\User;


abstract class SecurityUser
{
    
    protected string $username;
    protected string $password;
    protected array  $roles = [];
    
    
    
    /**
     * Return the username
     *
     * @return string
     */
    abstract public function getUsername(): string;
    
    
    /**
     * Return a array with her roles
     *
     * @return array
     */
    abstract public function getRoles(): array;
    
    
    /**
     * Return a encoded password
     *
     * @return string
     */
    abstract public function getPassword(): string;
    
    
    /**
     * Update the username
     *
     * @param string $username
     * @return $this
     */
    abstract public function setUsername( string $username ): self;
    
    
    /**
     * Add new role
     *
     * @param string $role
     * @return $this
     */
    abstract public function addRoles( string $role ): self;
    
    
    /**
     * Remove a role
     *
     * @param string $role
     * @return $this
     */
    abstract public function removeRoles( string $role ): self;
    
    
    /**
     * Update the password (with encoded password)
     *
     * @param string $password
     * @return $this
     */
    abstract public function setPassword( string $password ): self;
}
