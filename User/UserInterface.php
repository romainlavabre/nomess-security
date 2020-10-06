<?php


namespace Nomess\Component\Security\User;


interface UserInterface
{
    
    /**
     * Return the user connected or null
     *
     * @return SecurityUser|null
     */
    public function getUser(): ?SecurityUser;
}
