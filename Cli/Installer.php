<?php

namespace Nomess\Component\Security\Cli;

use Nomess\Component\Config\ConfigStoreInterface;


/**
 * @author Romain Lavabre <webmaster@newwebsouth.fr>
 */
class Installer implements \Nomess\Installer\ExecuteInstallInterface
{
    private const FILENAME = ROOT . 'config/components/security.yaml';
    private ConfigStoreInterface $configStore;
    
    public function __construct(ConfigStoreInterface $configStore)
    {
        $this->configStore = $configStore;
    }
    
    
    /**
     * @inheritDoc
     */
    public function exec(): void
    {
        copy( __DIR__ . '/security.yaml', self::FILENAME);
        chown( self::FILENAME, $this->configStore->get( ConfigStoreInterface::DEFAULT_NOMESS)['server']['user']);
    }
}
