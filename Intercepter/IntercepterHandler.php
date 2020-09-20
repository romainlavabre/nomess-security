<?php


namespace Nomess\Component\Security\Intercepter;


use Nomess\Component\Cache\Exception\InvalidSendException;
use Nomess\Component\Config\ConfigStoreInterface;
use Nomess\Component\Config\Exception\ConfigurationNotFoundException;
use Nomess\Component\Parser\AnnotationParserInterface;
use Nomess\Component\Security\User\SecurityUser;
use Nomess\Component\Security\User\UserInterface;
use Nomess\Event\EventListenerInterface;
use Nomess\Event\EventSubscriberInterface;
use Nomess\Exception\MissingConfigurationException;
use Nomess\Exception\NotFoundException;
use NoMess\Exception\UnsupportedEventException;
use Nomess\Http\HttpResponse;

class IntercepterHandler implements EventSubscriberInterface
{
    
    private const CONF_NAME = 'security';
    private AnnotationParserInterface $annotationParser;
    private ConfigStoreInterface      $configStore;
    private UserInterface             $user;
    private HttpResponse              $response;
    
    
    public function __construct(
        AnnotationParserInterface $annotationParser,
        ConfigStoreInterface $configStore,
        UserInterface $user,
        HttpResponse $response
    )
    {
        $this->annotationParser = $annotationParser;
        $this->configStore      = $configStore;
        $this->user             = $user;
        $this->response         = $response;
    }
    
    
    /**
     * @Inject
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
     * @throws InvalidSendException
     * @throws ConfigurationNotFoundException
     * @throws NotFoundException
     */
    public function notified( string $event, $value ): void
    {
        $roles     = $this->getRouteRoleByConfig();
        $isGranted = $this->getRouteByController( $value );
        
        if( !empty( $isGranted ) ) {
            $roles[] = $isGranted;
        }
        
        foreach( $roles as $role ) {
            if( $this->hasRole( $this->user->getUser(), $role ) ) {
                return;
            }
        }
        
        $this->response->redirectToLocal(
            $this->configStore->get( self::CONF_NAME )['security']['redirect_to_route']
        );
        die();
    }
    
    
    private function getRouteRoleByConfig(): array
    {
        $result = [];
        foreach( $this->configStore->get( self::CONF_NAME )['roles'] as $role => $configuration ) {
            if( preg_match( '/' . $configuration['route'] . '/', $_GET['p'] ) ) {
                $result[] = $role;
            }
        }
        
        return $result;
    }
    
    
    private function getRouteByController( array $entryPoint ): ?string
    {
        if( !empty( $entryPoint ) ) {
            $reflectionMethod = new \ReflectionMethod( $entryPoint['controller'], $entryPoint['method'] );
            
            if( $this->annotationParser->has( 'isGranted', $reflectionMethod ) ) {
                $value = $this->annotationParser->getValue( 'isGranted', $reflectionMethod );
                
                return current( $value );
            }
        }
        
        return NULL;
    }
    
    
    private function hasRole( SecurityUser $securityUser, string $role ): bool
    {
        
        if( in_array( $role, $securityUser->getRoles() ) ) {
            return TRUE;
        }
        
        $supported = FALSE;
        foreach( $securityUser->getRoles() as $userRole ) {
            foreach( $this->configStore->get( self::CONF_NAME )['roles'] as $key => $configuration ) {
                if( $userRole === $key ) {
                    if( in_array( $role, $configuration['extends'] ) ) {
                        return TRUE;
                    }
                }
                
                if( $key === $role ) {
                    $supported = TRUE;
                }
            }
        }
        
        if( !$supported ) {
            throw new MissingConfigurationException( 'The role ' . $role . ' was not found in configuration' );
        }
        
        return FALSE;
    }
}