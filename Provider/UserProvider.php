<?php


namespace Nomess\Component\Security\Provider;


use Firebase\JWT\JWT;
use Nomess\Component\Config\ConfigStoreInterface;
use Nomess\Component\Security\Exception\SecurityException;
use Nomess\Component\Security\User\SecurityUser;
use Nomess\Container\Container;
use Nomess\Http\HttpHeader;
use Nomess\Http\HttpRequest;
use Nomess\Http\HttpSession;

/**
 * @author Romain Lavabre <webmaster@newwebsouth.fr>
 */
class UserProvider implements UserProviderInterface
{
    
    private const CONF_NAME              = 'security';
    public const  SESSION_SECURITY_TOKEN = 'security_token';
    public const  KEY_ROLE               = 'role';
    public const  KEY_IDENTIFIER         = 'identifier';
    public const  KEY_CLASSNAME          = 'classname';
    public const  KEY_EXPIRES            = 'exp';
    public const  ALGORITHME             = 'RS512';
    private ConfigStoreInterface $configStore;
    private HttpRequest          $request;
    private ?array               $data = NULL;
    
    
    public function __construct(
        ConfigStoreInterface $configStore,
        HttpRequest $request )
    {
        $this->configStore = $configStore;
        $this->request     = $request;
        $this->hydrateData();
    }
    
    
    /**
     * @inheritDoc
     */
    public function getIdentifier(): int
    {
        if( isset( $this->data[self::KEY_IDENTIFIER] ) ) {
            return $this->data[self::KEY_IDENTIFIER];
        }
        
        throw new SecurityException( 'The key "' . self::KEY_IDENTIFIER . '" doesn\'t exist in JWT' );
    }
    
    
    /**
     * @inheritDoc
     */
    public function getRoles(): array
    {
        if( isset( $this->data[self::KEY_ROLE] ) ) {
            return $this->data[self::KEY_ROLE];
        }
        
        throw new SecurityException( 'The key "' . self::KEY_ROLE . '" doesn\'t exist in JWT' );
    }
    
    
    /**
     * @inheritDoc
     */
    public function getClassname(): string
    {
        if( isset( $this->data[self::KEY_CLASSNAME] ) ) {
            return $this->data[self::KEY_CLASSNAME];
        }
        
        throw new SecurityException( 'The key "' . self::KEY_CLASSNAME . '" doesn\'t exist in JWT' );
    }
    
    
    /**
     * @inheritDoc
     */
    public function hasSecurityUser(): bool
    {
        return !empty( $this->data );
    }
    
    
    /**
     * @inheritDoc
     */
    public function clientRegister( SecurityUser $securityUser ): void
    {
        ( new ClientRegister( $this->request ) )->register( $securityUser, $this->configStore->get( self::CONF_NAME ) );
    }
    
    
    private function hydrateData(): void
    {
        $token = $this->request->getHeaders()->getRequestHeader( HttpHeader::AUTHORIZATION );
        
        if( $token === NULL && ( $session = Container::getInstance()->get( HttpSession::class ) )->has( self::SESSION_SECURITY_TOKEN ) ) {
            $token = $session->get( self::SESSION_SECURITY_TOKEN );
        }
        
        if( $token === NULL ) {
            return;
        }
        
        try {
            $this->data = (array)JWT::decode( $token, file_get_contents($this->configStore->get( self::CONF_NAME )['token']['public_key']), [ self::ALGORITHME ] );
        } catch( \Throwable $e ) {
        }
    }
}
