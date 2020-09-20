<?php


namespace Nomess\Component\Security\Validator;


interface CredentialsValidatorInterface
{
    
    public function getError(): ?string;
    
    
    public function isValidCredential( string $classname ): bool;
}
