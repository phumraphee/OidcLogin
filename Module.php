<?php
namespace OidcLogin;

use Laminas\EventManager\Event;
use Laminas\EventManager\SharedEventManagerInterface;
use Laminas\Form\Element;
use Laminas\Form\Form;
use Laminas\Mvc\Controller\AbstractController;
use Laminas\Mvc\MvcEvent;
use Laminas\Session\Container;
use Laminas\ServiceManager\ServiceLocatorInterface;
use Laminas\Validator\Csrf;
use Laminas\View\Renderer\PhpRenderer;
use OidcLogin\Stdlib\Links;
use OidcLogin\Stdlib\ProviderLogout;
use OidcLogin\Stdlib\Rules;
use Omeka\Module\AbstractModule;
use Omeka\Stdlib\Message;

/**
 * LOG IN WITH AN OPENID CONNECT PROVIDER, NEXT TO THE PASSWORD.
 *
 * Adds /oidc/login, /oidc/callback, /oidc/link, /oidc/unlink, one link on Omeka's login
 * page, a box named after the account (e.g. "Example account") on each user's admin
 * page, and /admin/oidc-login where a global admin sees every user and types the provider
 * username each will use. The password log-in is never touched, so it is always there
 * when the provider is not.
 *
 * Logout: Omeka's own, then — for a provider log-in only — the provider's "log out?" page
 * (Stdlib\ProviderLogout, README "Logout").
 *
 * Settings (this page): issuer, redirect URI, which provider groups may log in, the
 * account name and the button text (English and Thai). On /admin/oidc-login (1.1.0):
 * accounts from provider groups — off by default — and the table "provider group → Omeka
 * role" it uses (oidclogin_auto, oidclogin_group_roles; user setting oidclogin_managed). The client id and secret live in
 * config/local.config.php under 'oidclogin'.
 *
 * Uninstalling removes this module's settings and links only.
 */
class Module extends AbstractModule
{
    const SETTINGS = [
        'oidclogin_issuer' => '',
        'oidclogin_redirect_uri' => '',
        'oidclogin_groups' => '',
        'oidclogin_button' => '',
        'oidclogin_button_th' => '',
        'oidclogin_account' => '',
        'oidclogin_account_th' => '',
    ];

    /** The client id and secret: 'oidclogin' in local.config.php. */
    public static function clientConfig(array $config): array
    {
        return $config['oidclogin'] ?? [];
    }

    /** The account's name for this visitor (Accept-Language), from the settings. */
    public static function accountName($settings): string
    {
        return Rules::accountName(
            (string) ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''),
            (string) $settings->get('oidclogin_account', ''),
            (string) $settings->get('oidclogin_account_th', '')
        );
    }

    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }

    public function onBootstrap(MvcEvent $event)
    {
        parent::onBootstrap($event);
        /* Anyone may start or finish a log-in; who gets in is decided in the controller.
           The admin page is for global admins only (checked again in its controller). */
        $acl = $this->getServiceLocator()->get('Omeka\Acl');
        $acl->allow(null, Controller\LoginController::class);
    }

    public function attachListeners(SharedEventManagerInterface $shared)
    {
        foreach (['view.edit.after', 'view.show.after'] as $name) {
            $shared->attach('Omeka\Controller\Admin\User', $name, [$this, 'userPanel']);
        }
        /* After a password log-in, a gentle reminder for people not linked yet. Our own
           log-in triggers user.login from OidcLogin's controller, not this one. */
        $shared->attach('Omeka\Controller\LoginController', 'user.login', [$this, 'nudge']);
        /* Logout: Omeka's own logout runs as always; for a
           person who logged in with the provider, its redirect then goes to the provider's
           "log out?" page instead of Omeka's login page (ProviderLogout). The redirect is
           changed when the response is finished (an action's Response ends its dispatch). */
        $shared->attach('Omeka\Controller\LoginController', 'user.login', [$this, 'forgetProvider'], 100);
        $shared->attach('Omeka\Controller\LoginController', 'user.logout', [$this, 'rememberLogout']);
        $shared->attach('Laminas\Mvc\Application', MvcEvent::EVENT_FINISH, [$this, 'toProvider'], 100);
    }

    /** Where the browser goes after this logout ('' = Omeka's login page). */
    private $providerLogout = '';
    /** What to ask the provider first: its authorization endpoint, client and callback. */
    private $providerProbe = [];
    /** Where to come back to when the provider has no log-in left (?redirect_url= on /logout). */
    private $logoutBack = '';

    /** A password log-in: this session's log-in is no longer the provider's. */
    public function forgetProvider(Event $event)
    {
        try {
            $store = new Container(Controller\LoginController::SESSION);
            unset($store->via, $store->idToken, $store->endSession, $store->probe);
        } catch (\Throwable $e) {
        }
    }

    /** Before Omeka ends the session: was this log-in the provider's? (Never stops a logout.) */
    public function rememberLogout(Event $event)
    {
        $this->providerLogout = '';
        try {
            $store = new Container(Controller\LoginController::SESSION);
            if (($store->via ?? '') !== 'oidc') {
                return;
            }
            $issuer = (string) $this->getServiceLocator()->get('Omeka\Settings')->get('oidclogin_issuer', '');
            $this->providerLogout = ProviderLogout::url($issuer, (string) ($store->endSession ?? ''), (string) ($store->idToken ?? ''));
            $this->providerProbe = is_array($store->probe ?? null) ? $store->probe + ['issuer' => $issuer] : [];
            /* The public page sends the whole browser to /logout?redirect_url=<its page> (a fetch
               cannot follow the provider's pages): when the provider has nothing left to end, the
               person comes back there rather than to Omeka's login page. A path of this site only. */
            $this->logoutBack = Rules::safeRedirect(isset($_GET['redirect_url']) && is_string($_GET['redirect_url']) ? $_GET['redirect_url'] : null, '');
        } catch (\Throwable $e) {
            error_log('OidcLogin logout: ' . $e->getMessage());
        }
    }

    /** After Omeka's logout (its session ended): its redirect goes to the provider instead. */
    public function toProvider(MvcEvent $event)
    {
        if ($this->providerLogout === '') {
            return;
        }
        $response = $event->getResponse();
        if (!$response instanceof \Laminas\Http\Response || !$response->isRedirect()) {
            return;
        }
        /* Asked first (prompt=none): a browser whose provider log-in has ended already would
           only meet the provider's sign-in page. The answer comes back to
           LoginController::callbackAction, which goes on to $to or to Omeka's "logged out". */
        $to = $this->providerLogout;
        $p = $this->providerProbe;
        if ($p) {
            try {
                $state = Rules::randomToken();
                $probe = ProviderLogout::probeUrl((string) $p['issuer'], (string) ($p['auth'] ?? ''), (string) ($p['client'] ?? ''),
                    (string) ($p['redirect'] ?? ''), $state, Rules::pkceChallenge(Rules::randomToken(48)));
                $key = (string) (self::clientConfig($this->getServiceLocator()->get('Config'))['client_secret'] ?? '');
                if ($probe !== '' && $key !== '') {
                    // Omeka's session is gone (Logout ended it): the question rides in a short cookie
                    $secure = stripos((string) ($p['redirect'] ?? ''), 'https://') === 0 ? '; Secure' : '';
                    $response->getHeaders()->addHeaderLine('Set-Cookie', ProviderLogout::COOKIE . '='
                        . ProviderLogout::seal(['state' => $state, 'end' => $to, 'at' => time(), 'back' => $this->logoutBack], $key)
                        . '; Path=/oidc/; Max-Age=600; HttpOnly; SameSite=Lax' . $secure);
                    $to = $probe;
                }
            } catch (\Throwable $e) {
                error_log('OidcLogin logout probe: ' . $e->getMessage());
            }
        }
        $headers = $response->getHeaders();
        if ($headers->has('Location')) {
            $headers->removeHeader($headers->get('Location'));
        }
        $headers->addHeaderLine('Location', $to);
        $this->providerLogout = '';
        $this->providerProbe = [];
        $this->logoutBack = '';
    }

    public function userPanel(Event $event)
    {
        $view = $event->getTarget();
        $services = $this->getServiceLocator();
        if ((string) $services->get('Omeka\Settings')->get('oidclogin_issuer', '') === '') {
            return;
        }
        $user = $view->vars('user') ?: ($view->vars('resource') ?? null);
        $me = $services->get('Omeka\AuthenticationService')->getIdentity();
        if (!$user || !$me) {
            return;
        }
        $userId = method_exists($user, 'id') ? (int) $user->id() : (int) $user->getId();
        $links = new Links($services->get('Omeka\Connection'));
        echo $view->partial('oidc-login/user-panel', [
            'subject' => $links->get(Links::SUBJECT, $userId),
            'username' => $links->get(Links::USERNAME, $userId),
            'own' => (int) $me->getId() === $userId,
            'isAdmin' => $me->getRole() === 'global_admin',
            'account' => self::accountName($services->get('Omeka\Settings')),
            'csrf' => (new Csrf(['name' => 'oidclogin_unlink']))->getHash(),
            'back' => $view->url('admin/id', ['controller' => 'user', 'id' => $userId, 'action' => 'edit']),
        ]);
    }

    public function nudge(Event $event)
    {
        try {
            $services = $this->getServiceLocator();
            if ((string) $services->get('Omeka\Settings')->get('oidclogin_issuer', '') === '') {
                return;
            }
            $user = $event->getParams();
            $user = is_object($user) ? $user : $services->get('Omeka\AuthenticationService')->getIdentity();
            if (!$user) {
                return;
            }
            $links = new Links($services->get('Omeka\Connection'));
            if ($links->get(Links::SUBJECT, (int) $user->getId()) !== null) {
                return;
            }
            $url = $services->get('ViewHelperManager')->get('url');
            $account = htmlspecialchars(self::accountName($services->get('Omeka\Settings')), ENT_QUOTES);
            $message = new Message(
                'Tip: link your %1$s and log in with one touch next time — %2$sLink %1$s%3$s.', // @translate
                $account, '<a href="' . htmlspecialchars($url('oidc-login', ['action' => 'link']), ENT_QUOTES) . '">', '</a>'
            );
            $message->setEscapeHtml(false);
            $services->get('ControllerPluginManager')->get('messenger')->addNotice($message);
        } catch (\Throwable $t) {
            error_log('OidcLogin nudge: ' . $t->getMessage());
        }
    }

    /** This module's own settings and links only. */
    public function uninstall(ServiceLocatorInterface $services)
    {
        $this->loadOwnClasses();
        $settings = $services->get('Omeka\Settings');
        foreach (array_merge(array_keys(self::SETTINGS), [Links::SEEN, 'oidclogin_auto', 'oidclogin_group_roles', 'oidclogin_selfedit_off']) as $id) {
            $settings->delete($id);
        }
        $services->get('Omeka\Connection')->executeStatement(
            'DELETE FROM user_setting WHERE id IN (?, ?, ?)', [Links::SUBJECT, Links::USERNAME, Links::MANAGED]
        );
    }

    /* While a module is being installed, upgraded or uninstalled Omeka does not load its
       src/ classes, so the ones these steps use are loaded by hand. */
    protected function loadOwnClasses(): void
    {
        require_once __DIR__ . '/src/Stdlib/Rules.php';
        require_once __DIR__ . '/src/Stdlib/Links.php';
    }

    public function getConfigForm(PhpRenderer $renderer)
    {
        $settings = $this->getServiceLocator()->get('Omeka\Settings');
        $config = self::clientConfig($this->getServiceLocator()->get('Config'));
        $form = $this->form();
        $data = [];
        foreach (self::SETTINGS as $id => $default) {
            $data[$id] = $settings->get($id, $default);
        }
        $form->setData($data);
        $secretSet = !empty($config['client_id']) && !empty($config['client_secret']);
        $note = $secretSet
            ? $renderer->translate('Client id and secret are set in local.config.php.')
            : $renderer->translate('Client id and secret are NOT set: add them to config/local.config.php under "oidclogin" (client_id, client_secret).');
        $admin = $renderer->hyperlink($renderer->translate('Linked accounts'), $renderer->url('admin/oidc-login'));
        return '<p>' . $renderer->escapeHtml($note) . '</p><p>' . $admin . '</p>' . $renderer->formCollection($form, false);
    }

    public function handleConfigForm(AbstractController $controller)
    {
        $form = $this->form();
        $form->setData($controller->params()->fromPost());
        if (!$form->isValid()) {
            $controller->messenger()->addFormErrors($form);
            return false;
        }
        $data = $form->getData();
        $issuer = rtrim(trim((string) $data['oidclogin_issuer']), '/');
        $redirect = trim((string) $data['oidclogin_redirect_uri']);
        if ($issuer !== '' && parse_url($issuer, PHP_URL_SCHEME) !== 'https') {
            $controller->messenger()->addError('The issuer must start with https://'); // @translate
            return false;
        }
        if ($redirect !== '' && !Rules::redirectUriOk($redirect)) {
            $controller->messenger()->addError('The redirect URI must start with https:// (http:// only for localhost)'); // @translate
            return false;
        }
        $settings = $this->getServiceLocator()->get('Omeka\Settings');
        $settings->set('oidclogin_issuer', $issuer);
        $settings->set('oidclogin_redirect_uri', $redirect);
        $settings->set('oidclogin_groups', implode(' ', Rules::parseList((string) $data['oidclogin_groups'])));
        $settings->set('oidclogin_button', trim((string) $data['oidclogin_button']));
        $settings->set('oidclogin_button_th', trim((string) $data['oidclogin_button_th']));
        $settings->set('oidclogin_account', trim((string) $data['oidclogin_account']));
        $settings->set('oidclogin_account_th', trim((string) $data['oidclogin_account_th']));
        return true;
    }

    protected function form(): Form
    {
        $form = new Form('oidclogin');
        $form->add([
            'name' => 'oidclogin_issuer',
            'type' => Element\Url::class,
            'options' => [
                'label' => 'Issuer', // @translate
                'info' => 'Exactly as the provider publishes it, e.g. https://id.example.org (no /.well-known part). Empty = this log-in switched off (button hidden).', // @translate
            ],
        ]);
        $form->add([
            'name' => 'oidclogin_redirect_uri',
            'type' => Element\Text::class,
            'options' => [
                'label' => 'Redirect URI', // @translate
                'info' => 'This site\'s https address followed by /oidc/callback. Register the same address at the provider.', // @translate
            ],
        ]);
        $form->add([
            'name' => 'oidclogin_groups',
            'type' => Element\Text::class,
            'options' => [
                'label' => 'Allowed groups', // @translate
                'info' => 'Provider groups that may log in here, separated by spaces. Empty = no group check.', // @translate
            ],
        ]);
        $form->add([
            'name' => 'oidclogin_account',
            'type' => Element\Text::class,
            'options' => ['label' => 'Account name (English)', 'info' => 'What people call their account at the provider, e.g. "Example account". Used in the button and every message. Empty = "OpenID Connect account".'], // @translate
        ]);
        $form->add([
            'name' => 'oidclogin_account_th',
            'type' => Element\Text::class,
            'options' => ['label' => 'Account name (Thai)', 'info' => 'Shown to browsers that ask for Thai first. Empty = the English name.'], // @translate
        ]);
        $form->add([
            'name' => 'oidclogin_button',
            'type' => Element\Text::class,
            'options' => ['label' => 'Button text (English)', 'info' => 'Empty = "Log in with" and the account name.'], // @translate
        ]);
        $form->add([
            'name' => 'oidclogin_button_th',
            'type' => Element\Text::class,
            'options' => ['label' => 'Button text (Thai)', 'info' => 'Shown to browsers that ask for Thai first. Empty = the English text, else "Log in with" and the account name.'], // @translate
        ]);
        foreach (array_keys(self::SETTINGS) as $id) {
            $form->getInputFilter()->get($id)->setRequired(false);
        }
        return $form;
    }
}
