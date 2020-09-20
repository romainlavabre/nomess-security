<?php


namespace Nomess\Component\Security\User;


interface UserInterface
{
    
    public function getUser(): ?SecurityUser;
}
