<?php


namespace Nomess\Component\Security\Validator;


use Nomess\Component\Config\ConfigStoreInterface;
use Nomess\Component\Orm\EntityManagerInterface;
use Nomess\Component\Parameter\ParameterStoreInterface;
use Nomess\Component\Security\User\SecurityUser;
use Nomess\Exception\MissingConfigurationException;
use Nomess\Http\HttpRequest;
use Nomess\Http\HttpSession;

class SecurityValidator implements CredentialsValidatorInterface
{
    
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
    
    
    /**
     * @inheritDoc
     */
    public function isValidCredential( string $classname ): bool
    {
        $configuration = $this->configStore->get( self::CONFIG_NAME );
        $this->validUserSupported( $classname, $configuration );
        
        $username = $this->request->getParameter( $configuration['users'][$classname]['request']['identifier'], HttpRequest::STRING_NULL );
        $password = $this->request->getParameter( $configuration['users'][$classname]['request']['password'], HttpRequest::STRING_NULL );
        
        if( !$this->isValidParameters( $username, $password ) ) {
            $this->error = $configuration['security']['messages'][self::DEFAULT_ERROR_MESSAGE_PARAMETERS];
            $this->request->setError( $this->error );
            
            return FALSE;
        }
        
        $user = $this->getUser( $classname, $username );
        
        if( empty( $user ) ) {
            $this->error = $configuration['security']['messages'][self::DEFAULT_ERROR_MESSAGE_USER_NOT_FOUND];
            $this->request->setError( $this->error );
            
            return FALSE;
        }
        
        if( !$this->passwordHandler->isValidPassword( $password, $user ) ) {
            $this->error = $configuration['security']['messages'][self::DEFAULT_ERROR_MESSAGE_INVALID_PASSWORD];
            $this->request->setError( $this->error );
            
            return FALSE;
        }
        
        $this->persist( $user );
        
        return TRUE;
    }
    
    
    /**
     * @inheritDoc
     */
    public function getError(): ?string
    {
        return $this->error;
    }
    
    
    /**
     * @inheritDoc
     */
    public function addUser( SecurityUser $securityUser ): self
    {
        $this->persist( $securityUser );
        
        return $this;
    }
    
    
    /**
     * Return the good user
     *
     * @param string $classname
     * @param string $username
     * @return SecurityUser|null
     */
    private function getUser( string $classname, string $username ): ?SecurityUser
    {
        $result = $this->entityManager->find( $classname, 'username = :username', [
            'username' => $username
        ] );
        
        return is_array( $result ) ? $result[0] : NULL;
    }
    
    
    private function isValidParameters( ?string $username, ?string $password ): bool
    {
        return !empty( $username ) && !empty( $password );
    }
    
    
    /**
     * Persist the user in session.
     * Use the useragent module and ticket system
     * 
     * @param SecurityUser $securityUser
     * @throws \Nomess\Exception\InvalidParamException
     */
    private function persist( SecurityUser $securityUser ): void
    {
        $this->session->installSecurityModules( TRUE, TRUE, FALSE )
                      ->set( 'security_user', $securityUser );
    }
    
    
    private function validUserSupported( string $classname, array $configuration ): void
    {
        if( !array_key_exists( $classname, $configuration['users'] ) ) {
            throw new MissingConfigurationException( 'The user ' . $classname . '::class is not configured in security component' );
        }
    }
}
