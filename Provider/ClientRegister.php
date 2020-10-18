<?php


namespace Nomess\Component\Security\Provider;


use Firebase\JWT\JWT;
use Nomess\Component\Security\User\SecurityUser;
use Nomess\Container\Container;
use Nomess\Http\HttpRequest;
use Nomess\Http\HttpSession;

/**
 * @author Romain Lavabre <webmaster@newwebsouth.fr>
 */
class ClientRegister
{
    
    private HttpRequest $request;
    
    
    public function __construct( HttpRequest $request )
    {
        $this->request = $request;
    }
    
    
    public function register( SecurityUser $securityUser, array $configuration ): void
    {
        $payload = [
            UserProvider::KEY_CLASSNAME  => get_class( $securityUser ),
            UserProvider::KEY_ROLE       => $securityUser->getRoles(),
            UserProvider::KEY_IDENTIFIER => $securityUser->getId(),
            UserProvider::KEY_EXPIRES    => time() + $configuration['token']['ttl']
        ];
        
        $token = JWT::encode( $payload, file_get_contents($configuration['token']['private_key']), UserProvider::ALGORITHME );
        
        $this->persist( $token, $configuration );
    }
    
    
    private function persist( string $token, array $configuration ): void
    {
        $onStateless  = 0;
        $offStateless = 0;
        
        foreach( $configuration['route'] as $name => $array ) {
            if( preg_match( '/' . str_replace('/', '\/', $array['path']) . '/', $_SERVER['REQUEST_URI'] ) ) {
                if( !$array['stateless'] ) {
                    Container::getInstance()->get( HttpSession::class )->set( UserProvider::SESSION_SECURITY_TOKEN, $token );
                }
                $this->request->setParameter( 'token', $token );
                
                return;
            }
            
            if( $array['stateless'] ) {
                $onStateless++;
            } else {
                $offStateless++;
            }
        }
        
        if( strpos( $_SERVER['REQUEST_URI'], 'api' ) !== FALSE || $onStateless >= $offStateless ) {
            $this->request->setParameter( 'token', $token );
            
            return;
        }
        
        Container::getInstance()->get( HttpSession::class )->set( UserProvider::SESSION_SECURITY_TOKEN, $token );
    }
}
