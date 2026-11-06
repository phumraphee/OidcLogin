<?php
namespace OidcLogin\Service\Controller;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use OidcLogin\Controller\Admin\IndexController;
use OidcLogin\Stdlib\Directory;
use OidcLogin\Stdlib\Links;

class AdminControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        $config = $services->get('Config');
        return new IndexController(
            $services->get('Omeka\Connection'),
            new Links($services->get('Omeka\Connection')),
            new Directory(
                $services->get('Omeka\Connection'),
                $services->get('Omeka\HttpClient'),
                (string) $services->get('Omeka\Settings')->get('oidclogin_issuer', ''),
                (string) ($config['oidclogin']['api_key'] ?? '')
            )
        );
    }
}
