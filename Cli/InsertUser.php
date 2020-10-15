<?php


namespace Nomess\Component\Security\Cli;


use Nomess\Component\Cli\Interactive\InteractiveInterface;
use Nomess\Component\Config\ConfigStoreInterface;
use Nomess\Component\Orm\Cache\CacheHandlerInterface;
use Nomess\Component\Orm\EntityManagerInterface;
use Nomess\Component\Security\User\SecurityUser;
use Nomess\Component\Security\Validator\PasswordHandlerInterface;

/**
 * @author Romain Lavabre <webmaster@newwebsouth.fr>
 */
class InsertUser implements \Nomess\Component\Cli\Executable\ExecutableInterface
{
    
    private const CONFIG_NAME   = 'security';
    private const PROP_USERNAME = 'username';
    private const PROP_PASSWORD = 'password';
    private const PROP_ROLES    = 'roles';
    private InteractiveInterface     $interactive;
    private ConfigStoreInterface     $configStore;
    private PasswordHandlerInterface $passwordHandler;
    private CacheHandlerInterface    $cacheHandler;
    private EntityManagerInterface   $entityManager;
    
    
    public function __construct(
        InteractiveInterface $interactive,
        ConfigStoreInterface $configStore,
        PasswordHandlerInterface $passwordHandler,
        EntityManagerInterface $entityManager,
        CacheHandlerInterface $cacheHandler )
    {
        $this->interactive     = $interactive;
        $this->configStore     = $configStore;
        $this->passwordHandler = $passwordHandler;
        $this->cacheHandler    = $cacheHandler;
        $this->entityManager   = $entityManager;
    }
    
    
    public function exec( array $command ): void
    {
        $securityUser = $this->getUserWithPassword();
        
        if( $securityUser === NULL ) {
            return;
        }
        
        $roles = $this->configStore->get( self::CONFIG_NAME )['roles'];
        
        if( !is_array( $roles ) ) {
            $this->interactive->writeColorRed( 'Not role found' );
            
            return;
        }
        
        do {
            $continue = TRUE;
            
            $role = $this->interactive->readWithCompletion( 'Role: ', array_keys( $roles ) );
            
            if( empty( $role ) ) {
                $continue = FALSE;
            } elseif( !array_key_exists( $role, $roles ) ) {
                $this->interactive->writeColorRed( 'Invalid role' );
            } else {
                $securityUser->addRoles( $role );
            }
        } while( $continue );
        
        $this->completeEntity( $securityUser );
        
        try {
            $this->entityManager->persist( $securityUser )
                                ->save();
        } catch( \Throwable $throwable ) {
            $this->interactive->writeColorRed( $throwable->getMessage() );
            
            return;
        }
        
        $this->interactive->writeColorGreen( 'Entity inserted' );
    }
    
    
    private function getUserWithPassword(): ?SecurityUser
    {
        $entities = $this->configStore->get( self::CONFIG_NAME )['users'];
        
        if( !is_array( $entities ) ) {
            $this->interactive->writeColorRed( 'Not entity found' );
            
            return NULL;
        }
        
        $classname = $this->interactive->readWithCompletion( 'For which entity? ', array_keys( $entities ) );
        
        if( !class_exists( $classname ) ) {
            $this->interactive->writeColorRed( 'Invalid entity' );
        }
        
        if( !( new \ReflectionClass( $classname ) )->isSubclassOf( SecurityUser::class ) ) {
            $this->interactive->writeColorRed( 'Your entity must extends of SecurityUser' );
        }
        
        /** @var SecurityUser $securityUser */
        $securityUser = new $classname();
        
        
        do {
            $username = $this->interactive->read( 'Username: ' );
            
            if( !empty( $username ) ) {
                $securityUser->setUsername( $username );
            }
        } while( empty( $username ) );
        
        $password = $this->interactive->read( 'Password: ' );
        
        /** @var SecurityUser $securityUser */
        $this->passwordHandler->encode( $password, $securityUser );
        
        return $securityUser;
    }
    
    
    private function completeEntity( SecurityUser $securityUser ): void
    {
        foreach( $cache = $this->cacheHandler->getCache( get_class( $securityUser ) )[CacheHandlerInterface::ENTITY_METADATA] as $propertyName => $array ) {
            
            $reflectionProperty = new \ReflectionProperty( get_class( $securityUser ), $propertyName );
            
            if( $reflectionProperty->getName() === self::PROP_USERNAME
                || $reflectionProperty->getName() === self::PROP_PASSWORD
                || $reflectionProperty->getName() === self::PROP_ROLES
                || $reflectionProperty->getName() === 'id' ) {
                
                continue;
            }
            
            do {
                $continue = FALSE;
                
                if( $array[CacheHandlerInterface::ENTITY_RELATION] === NULL ) {
                    $value = $this->interactive->read( ucfirst( $reflectionProperty->getName() ) . ': ' );
                    
                    try {
                        $reflectionProperty->setValue( $securityUser, $value );
                    } catch( \Throwable $throwable ) {
                        $this->interactive->writeColorRed( $throwable->getMessage() );
                        $continue = TRUE;
                    }
                } else {
                    if( $array[CacheHandlerInterface::ENTITY_IS_NULLABLE] ) {
                        $continue = FALSE;
                    } else {
                        $this->interactive->writeColorRed( 'You must set manually the property "' . $reflectionProperty->getName() . '", continue...' );
                    }
                }
            } while( $continue );
        }
    }
}
