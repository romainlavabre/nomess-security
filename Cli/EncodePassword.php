<?php


namespace Nomess\Component\Security\Cli;


use Nomess\Component\Cli\Interactive\InteractiveInterface;
use Nomess\Component\Config\ConfigStoreInterface;
use Nomess\Component\Security\User\SecurityUser;
use Nomess\Component\Security\Validator\PasswordHandlerInterface;

/**
 * @author Romain Lavabre <webmaster@newwebsouth.fr>
 */
class EncodePassword implements \Nomess\Component\Cli\Executable\ExecutableInterface
{
    private const CONFIG_NAME = 'security';
    private InteractiveInterface     $interactive;
    private ConfigStoreInterface     $configStore;
    private PasswordHandlerInterface $passwordHandler;
    
    public function __construct(
        InteractiveInterface $interactive,
        ConfigStoreInterface $configStore,
        PasswordHandlerInterface $passwordHandler )
    {
        $this->interactive     = $interactive;
        $this->configStore     = $configStore;
        $this->passwordHandler = $passwordHandler;
    }
    
    
    public function exec( array $command ): void
    {
        $entities = $this->configStore->get( self::CONFIG_NAME )['users'];
    
        if( !is_array( $entities ) ) {
            $this->interactive->writeColorRed( 'Not entity found' );
        
            return;
        }
    
        $classname = $this->interactive->readWithCompletion( 'For which entity? ', array_keys( $entities ) );
    
        if( !class_exists( $classname ) ) {
            $this->interactive->writeColorRed( 'Invalid entity' );
        }
    
        if( !( new \ReflectionClass( $classname ) )->isSubclassOf( SecurityUser::class ) ) {
            $this->interactive->writeColorRed( 'Your entity must extends of SecurityUser' );
        }
    
        $password = $this->interactive->read( 'Password: ' );
    
        /** @var SecurityUser $securityUser */
        $this->passwordHandler->encode( $password, $securityUser = new $classname() );
    
        $this->interactive->writeColorGreen( $securityUser->getPassword() );
    }
}
