<?php


namespace Nomess\Component\Security\Cli;


use Nomess\Component\Cli\Interactive\InteractiveInterface;
use Nomess\Component\Config\ConfigStoreInterface;

/**
 * @author Romain Lavabre <webmaster@newwebsouth.fr>
 */
class EncodeRole implements \Nomess\Component\Cli\Executable\ExecutableInterface
{
    private const CONFIG_NAME = 'security';
    private ConfigStoreInterface $configStore;
    private InteractiveInterface $interactive;
    
    public function __construct(
        ConfigStoreInterface $configStore,
InteractiveInterface $interactive)
    {
        $this->configStore = $configStore;
        $this->interactive = $interactive;
    }
    
    
    public function exec( array $command ): void
    {
        $roles = $this->configStore->get( self::CONFIG_NAME)['roles'];
        
        if(!is_array( $roles)){
            $this->interactive->writeColorRed( 'Not role found');
            return;
        }
        
        $encodeRoles = [];
        
        do{
            $continue = TRUE;
            
            $role = $this->interactive->readWithCompletion( 'Role: ', array_keys( $roles));
            
            if(empty( $role)){
                $continue = FALSE;
            }elseif(!array_key_exists( $role, $roles)){
                $this->interactive->writeColorRed( 'Invalid role');
            }else{
                $encodeRoles[] = $role;
            }
        }while($continue);
        
        
        $this->interactive->writeColorGreen( serialize( $encodeRoles));
    }
}
