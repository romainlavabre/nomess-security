<?php


namespace Nomess\Component\Security\Intercepter;


use Nomess\Annotations\Inject;
use Nomess\Component\Config\ConfigStoreInterface;
use Nomess\Component\Config\Exception\ConfigurationNotFoundException;
use Nomess\Component\Parser\AnnotationParserInterface;
use Nomess\Component\Security\Exception\SecurityException;
use Nomess\Component\Security\Provider\UserProviderInterface;
use Nomess\Container\Container;
use Nomess\Event\EventListenerInterface;
use Nomess\Event\EventSubscriberInterface;
use Nomess\Exception\MissingConfigurationException;
use Nomess\Exception\NotFoundException;
use NoMess\Exception\UnsupportedEventException;
use Nomess\Http\HttpHeader;
use Nomess\Http\HttpResponse;
use Nomess\Http\HttpSession;
use Nomess\Initiator\Route\RouteHandlerInterface;

class IntercepterHandler implements EventSubscriberInterface
{
    
    private const CONF_NAME       = 'security';
    private const ANNOTATION_NAME = 'IsGranted';
    private AnnotationParserInterface $annotationParser;
    private ConfigStoreInterface      $configStore;
    private HttpResponse              $response;
    private UserProviderInterface     $userProvider;
    
    
    public function __construct(
        AnnotationParserInterface $annotationParser,
        ConfigStoreInterface $configStore,
        HttpResponse $response,
        UserProviderInterface $userProvider
    )
    {
        $this->annotationParser = $annotationParser;
        $this->configStore      = $configStore;
        $this->response         = $response;
        $this->userProvider     = $userProvider;
    }
    
    
    /**
     * @Inject()
     * @param EventListenerInterface $eventListener
     * @throws UnsupportedEventException
     */
    public function subscribe( EventListenerInterface $eventListener ): void
    {
        $eventListener->follow( $this, EventListenerInterface::AFTER_ROUTE_RESOLVER );
    }
    
    
    /**
     * @param string $event
     * @param $value
     * @throws MissingConfigurationException
     * @throws ConfigurationNotFoundException
     * @throws NotFoundException
     */
    public function notified( string $event, $value ): void
    {
        $confName     = $this->getRouteConfiguration();
        $roleRequired = $this->configStore->get( self::CONF_NAME )['route'][$confName]['role'] ?? NULL;
        $isGranted    = $this->getRouteByController( $value );
        
        if( $roleRequired === NULL && $isGranted === NULL ) {
            return;
        }
        
        if( !$this->userProvider->hasSecurityUser() ) {
            if( $confName !== NULL ) {
                $this->response->redirectToLocal(
                    $this->configStore->get( self::CONF_NAME )['route'][$confName]['redirect_to_route'],
                    [],
                    HttpHeader::HTTP_UNAUTHORIZED
                )->stop();
            }
            
            $this->response->response_code( HttpHeader::HTTP_UNAUTHORIZED )
                           ->stop();
        }
        
        
        if( ( $roleRequired !== NULL && !$this->userHasRole( $roleRequired ) )
            || ( $isGranted !== NULL && !$this->userHasRole( $isGranted ) ) ) {
            
            $this->response->response_code( HttpHeader::HTTP_UNAUTHORIZED )
                           ->stop();
        }
    }
    
    
    /**
     * @param array|null $entryPoint
     * @return string|null
     * @throws ConfigurationNotFoundException
     * @throws SecurityException
     * @throws \ReflectionException
     */
    private function getRouteByController( ?array $entryPoint ): ?string
    {
        if( !empty( $entryPoint ) ) {
            $reflectionMethod = new \ReflectionMethod( $entryPoint[RouteHandlerInterface::CONTROLLER], $entryPoint[RouteHandlerInterface::METHOD] );
            
            if( $this->annotationParser->has( self::ANNOTATION_NAME, $reflectionMethod ) ) {
                $value = $this->annotationParser->getValue( self::ANNOTATION_NAME, $reflectionMethod );
                
                $role = current( $value );
                
                if( !array_key_exists( $role, $this->configStore->get( self::CONF_NAME )['roles'] ) ) {
                    throw new SecurityException( 'The role required for "' . $reflectionMethod->getDeclaringClass()->getName() . '::' . $reflectionMethod->getName() . '" has not found is configuration' );
                }
            }
        }
        
        return NULL;
    }
    
    
    private function userHasRole( string $role ): bool
    {
        return in_array( $role, $this->userProvider->getRoles(), TRUE );
    }
    
    
    private function getRouteConfiguration(): ?string
    {
        foreach( $this->configStore->get( self::CONF_NAME )['route'] as $name => $configuration ) {
            if( ( !isset( $configuration['exclude'] ) || !preg_match( '/' . str_replace( '/', '\/', $configuration['exclude'] ) . '/', $_SERVER['REQUEST_URI'] ) )
                && ( ( NOMESS_CONTEXT === 'DEV' && $configuration['security_dev'] )
                     || ( NOMESS_CONTEXT === 'PROD' && $configuration['security_prod'] ) )
                && preg_match( '/' . str_replace('/', '\/', $configuration['path']) . '/', $_SERVER['REQUEST_URI'] ) ) {
                
                return $name;
            }
        }
        
        return NULL;
    }
}
