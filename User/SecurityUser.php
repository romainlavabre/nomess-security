<?php


namespace Nomess\Component\Security\User;


abstract class SecurityUser
{
    
    protected string $username;
    protected string $password;
    protected array  $roles;
    
    
    abstract public function getUsername(): string;
    
    
    abstract public function getRoles(): array;
    
    
    abstract public function getPassword(): string;
    
    
    abstract public function setUsername( string $username ): self;
    
    
    abstract public function addRoles( string $role ): self;
    
    
    abstract public function removeRoles( string $role ): self;
    
    
    abstract public function setPassword( string $password ): self;
}
