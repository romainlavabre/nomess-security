<?php


namespace Nomess\Component\Security\Validator;


use Nomess\Component\Config\ConfigStoreInterface;
use Nomess\Component\Orm\EntityManagerInterface;
use Nomess\Component\Parameter\ParameterStoreInterface;
use Nomess\Component\Security\User\SecurityUser;
use Nomess\Http\HttpRequest;
use Nomess\Http\HttpSession;

class SecurityValidator implements CredentialsValidatorInterface
{
    
    private const PARAM_USERNAME                         = 'username';
    private const PARAM_PASSWORD                         = 'password';
    private const DEFAULT_ERROR_MESSAGE_PARAMETERS       = 'missing_parameter';
    private const DEFAULT_ERROR_MESSAGE_USER_NOT_FOUND   = 'user_not_found';
    private const DEFAULT_ERROR_MESSAGE_INVALID_PASSWORD = 'invalid_password';
    private const CONFIG_NAME                            = 'security';
    private EntityManagerInterface   $entityManager;
    private ConfigStoreInterface     $configStore;
    private ParameterStoreInterface  $parameterStore;
    private PasswordHandlerInterface $passwordHandler;
    private HttpRequest              $request;
    private HttpSession              $session;
    private ?string                  $error = NULL;
    
    
    public function __construct(
        EntityManagerInterface $entityManager,
        ConfigStoreInterface $configStore,
        ParameterStoreInterface $parameterStore,
        PasswordHandlerInterface $passwordHandler,
        HttpRequest $request,
        HttpSession $session
    )
    {
        $this->entityManager   = $entityManager;
        $this->configStore     = $configStore;
        $this->parameterStore  = $parameterStore;
        $this->passwordHandler = $passwordHandler;
        $this->request         = $request;
        $this->session         = $session;
    }
    
    
    public function isValidCredential( string $classname ): bool
    {
        $username      = $this->request->getParameter( self::PARAM_USERNAME, HttpRequest::STRING_NULL );
        $password      = $this->request->getParameter( self::PARAM_PASSWORD, HttpRequest::STRING_NULL );
        $configuration = $this->configStore->get( self::CONFIG_NAME );
        
        if( $this->isValidParameters( $username, $password ) ) {
            $this->error = $configuration['security']['messages'][self::DEFAULT_ERROR_MESSAGE_PARAMETERS];
            
            return FALSE;
        }
        
        $user = $this->getUser( $classname, $username );
        
        if( empty( $user ) ) {
            $this->error = $configuration['security']['messages'][self::DEFAULT_ERROR_MESSAGE_USER_NOT_FOUND];
            
            return FALSE;
        }
        
        if( !$this->passwordHandler->isValidPassword( $password, $user ) ) {
            $this->error = $configuration['security']['messages'][self::DEFAULT_ERROR_MESSAGE_INVALID_PASSWORD];
        }
        
        $this->persist( $user );
        
        return TRUE;
    }
    
    
    public function getError(): ?string
    {
        return $this->error;
    }
    
    
    private function getUser( string $classname, string $username ): ?SecurityUser
    {
        return $this->entityManager->find( $classname, 'username = :username', [
            'username' => $username
        ] );
    }
    
    
    private function isValidParameters( string $username, string $password ): bool
    {
        return !empty( $username ) && !empty( $password );
    }
    
    
    private function persist( SecurityUser $securityUser ): void
    {
        $this->session->installSecurityModules( TRUE, TRUE, FALSE )
                      ->set( 'security_user', $securityUser );
    }
}
