<?php
namespace OidcLogin\Service\Controller;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use OidcLogin\Controller\LoginController;
use OidcLogin\Stdlib\Links;

class LoginControllerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new LoginController(
            $services->get('Omeka\EntityManager'),
            $services->get('Omeka\AuthenticationService'),
            $services->get('Omeka\HttpClient'),
            \OidcLogin\Module::clientConfig($services->get('Config')),
            new Links($services->get('Omeka\Connection'))
        );
    }
}
