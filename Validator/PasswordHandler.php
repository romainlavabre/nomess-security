<?php


namespace Nomess\Component\Security\Validator;


use Nomess\Component\Config\ConfigStoreInterface;
use Nomess\Component\Security\User\SecurityUser;

class PasswordHandler implements PasswordHandlerInterface
{
    
    private const CONF_NAME = 'security';
    private const ALGORITHM = [
        'default'  => PASSWORD_DEFAULT,
        'bcrypt'   => PASSWORD_BCRYPT,
        'argon2i'  => PASSWORD_ARGON2I,
        'argon2id' => PASSWORD_ARGON2ID
    ];
    private ConfigStoreInterface $configStore;
    
    
    public function __construct( ConfigStoreInterface $configStore )
    {
        $this->configStore = $configStore;
    }
    
    
    /**
     * @inheritDoc
     */
    public function isValidPassword( string $password, SecurityUser $securityUser ): bool
    {
        return password_verify( $password, $securityUser->getPassword() );
    }
    
    
    /**
     * @inheritDoc
     */
    public function encode( $password, SecurityUser $securityUser ): bool
    {
        $securityUser->setPassword( password_hash( $password, $this->getAlgorithm( $securityUser ) ) );
        
        return TRUE;
    }
    
    
    private function getAlgorithm( SecurityUser $securityUser ): string
    {
        $configuration = $this->configStore->get( self::CONF_NAME );
        
        if( array_key_exists( get_class( $securityUser ), $configuration['users'] ) ) {
            return self::ALGORITHM[$configuration['users'][get_class( $securityUser )]['algorithm']];
        }
        
        return PASSWORD_DEFAULT;
    }
}
