<?php


namespace Nomess\Component\Security;


use Nomess\Component\Cli\Executable\ExecutableInterface;
use Nomess\Component\Config\ConfigStoreInterface;
use Nomess\Component\Security\Cli\EncodePassword;
use Nomess\Component\Security\Cli\EncodeRole;
use Nomess\Component\Security\Cli\InsertUser;
use Nomess\Component\Security\Cli\Installer;
use Nomess\Component\Security\Intercepter\IntercepterHandler;
use Nomess\Component\Security\User\GetUser;
use Nomess\Component\Security\User\UserInterface;
use Nomess\Component\Security\Validator\CredentialsValidatorInterface;
use Nomess\Component\Security\Validator\PasswordHandler;
use Nomess\Component\Security\Validator\PasswordHandlerInterface;
use Nomess\Component\Security\Validator\SecurityValidator;
use Nomess\Event\EventSubscriberInterface;

/**
 * @author Romain Lavabre <webmaster@newwebsouth.fr>
 */
class NomessInstaller implements \Nomess\Installer\NomessInstallerInterface
{
    
    public function __construct( ConfigStoreInterface $configStore )
    {
    }
    
    
    /**
     * @inheritDoc
     */
    public function container(): array
    {
        return [
            UserInterface::class => GetUser::class,
            CredentialsValidatorInterface::class => SecurityValidator::class,
            PasswordHandlerInterface::class => PasswordHandler::class,
            EventSubscriberInterface::class => IntercepterHandler::class
        ];
    }
    
    
    /**
     * @inheritDoc
     */
    public function controller(): array
    {
        return [];
    }
    
    
    /**
     * @inheritDoc
     */
    public function cli(): array
    {
        return [
            'nomess/security' => NULL,
            'encode:password' => [
                ExecutableInterface::COMMENT => 'Encode a password',
                ExecutableInterface::CLASSNAME => EncodePassword::class
            ],
            'encode:roles' => [
                ExecutableInterface::COMMENT => 'Encode a roles',
                ExecutableInterface::CLASSNAME => EncodeRole::class
            ],
            'insert:user' => [
                ExecutableInterface::COMMENT => 'Manually create a user',
                ExecutableInterface::CLASSNAME => InsertUser::class
            ]
        ];
    }
    
    
    /**
     * @inheritDoc
     */
    public function exec(): ?string
    {
        return Installer::class;
    }
}
