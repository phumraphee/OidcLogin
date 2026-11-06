<?php
namespace OidcLogin;

return [
    'controllers' => [
        'factories' => [
            Controller\LoginController::class => Service\Controller\LoginControllerFactory::class,
            Controller\Admin\IndexController::class => Service\Controller\AdminControllerFactory::class,
        ],
    ],
    'view_manager' => [
        /* Also holds omeka/login/login.phtml: Omeka's login page plus one link. */
        'template_path_stack' => [dirname(__DIR__) . '/view'],
    ],
    'router' => [
        'routes' => [
            'oidc-login' => [
                'type' => \Laminas\Router\Http\Segment::class,
                'options' => [
                    'route' => '/oidc/:action',
                    'constraints' => ['action' => 'login|callback|link|unlink'],
                    'defaults' => [
                        '__NAMESPACE__' => 'OidcLogin\Controller',
                        'controller' => Controller\LoginController::class,
                    ],
                ],
            ],
            'admin' => [
                'child_routes' => [
                    'oidc-login' => [
                        'type' => \Laminas\Router\Http\Literal::class,
                        'options' => [
                            'route' => '/oidc-login',
                            'defaults' => [
                                '__NAMESPACE__' => 'OidcLogin\Controller\Admin',
                                'controller' => Controller\Admin\IndexController::class,
                                'action' => 'index',
                            ],
                        ],
                    ],
                ],
            ],
        ],
    ],
    'navigation' => [
        'AdminModule' => [
            [
                'label' => 'Log-in accounts', // @translate
                'route' => 'admin/oidc-login',
                'resource' => Controller\Admin\IndexController::class,
                'privilege' => 'index',
                'class' => 'o-icon- fa-key',
            ],
        ],
    ],
    /* The secret never goes in the database or the settings form. Put it in Omeka's
       config/local.config.php:
           'oidclogin' => ['client_id' => '…', 'client_secret' => '…'], */
    'oidclogin' => [
        'client_id' => '',
        'client_secret' => '',
    ],
];
