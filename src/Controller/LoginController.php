<?php
namespace OidcLogin\Controller;

use Doctrine\ORM\EntityManager;
use Laminas\Authentication\AuthenticationService;
use Laminas\Http\Client as HttpClient;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\Session\Container;
use Laminas\View\Model\ViewModel;
use OidcLogin\Stdlib\Links;
use OidcLogin\Stdlib\Rules;
use Omeka\Entity\User;

/**
 * LOG IN THROUGH AN OPENID CONNECT PROVIDER, NEXT TO THE PASSWORD — NEVER INSTEAD OF IT.
 *
 * /oidc/login     sends the browser to the provider (authorization code + PKCE S256,
 *                 state and nonce kept in this visitor's session for ten minutes).
 * /oidc/callback  checks state, trades the code for tokens on the server side, checks the
 *                 ID token and the userinfo answer, finds the Omeka user the administrator
 *                 linked to that username, and logs in exactly as Omeka's own /login does:
 *                 new session id, identity written through Omeka's authentication storage,
 *                 'user.login' event. So every page that reads Omeka's session sees an
 *                 ordinary log-in.
 *
 * Nobody is created here and nobody's role changes — unless the administrator turned on
 * "accounts from provider groups" (1.1.0, off by default): then someone nobody is linked to,
 * in a group the admin page maps to an Omeka role, is linked to the one user with their
 * email address or gets a new user, and the role of everyone made or linked that way follows
 * their groups at every log-in (autoAccount below). A user Omeka has deactivated never comes
 * in this way and is never turned back on. Anything that does not check out ends on a page
 * that says why and offers the password log-in.
 */
class LoginController extends AbstractActionController
{
    const SESSION = 'OidcLogin';
    const TTL = 600;

    protected $entityManager;
    protected $auth;
    protected $http;
    protected $config;
    protected $links;

    public function __construct(EntityManager $entityManager, AuthenticationService $auth, HttpClient $http, array $config, Links $links)
    {
        $this->entityManager = $entityManager;
        $this->auth = $auth;
        $this->http = $http;
        $this->config = $config;
        $this->links = $links;
    }

    public function loginAction()
    {
        $back = Rules::safeRedirect($this->params()->fromQuery('redirect_url'), '');
        if ($this->auth->hasIdentity()) {
            return $this->redirect()->toUrl($back !== '' ? $back : $this->url()->fromRoute('top'));
        }
        return $this->start('login', $back);
    }

    /** A user logged in with the password links their own provider account. */
    public function linkAction()
    {
        if (!$this->auth->hasIdentity()) {
            return $this->redirect()->toRoute('login');
        }
        return $this->start('link', Rules::safeRedirect($this->params()->fromQuery('redirect_url'), ''));
    }

    /** A user removes their own link (POST with the form's CSRF token). */
    public function unlinkAction()
    {
        $user = $this->auth->getIdentity();
        $request = $this->getRequest();
        if (!$user || !$request->isPost()) {
            return $this->redirect()->toRoute('login');
        }
        $csrf = new \Laminas\Validator\Csrf(['name' => 'oidclogin_unlink']);
        if (!$csrf->isValid((string) $request->getPost('oidclogin_unlink'))) {
            $this->messenger()->addError('The form has expired. Please try again.'); // @translate
        } else {
            $this->links->log('unlink', (int) $user->getId(), (string) $this->links->get(\OidcLogin\Stdlib\Links::USERNAME, (int) $user->getId()), 'self');
            $this->links->unlink((int) $user->getId());
            $this->messenger()->addSuccess(sprintf('Your %s is no longer linked.', $this->account())); // @translate
        }
        return $this->redirect()->toUrl(Rules::safeRedirect((string) $request->getPost('redirect_url'), $this->url()->fromRoute('admin/id', ['controller' => 'user', 'id' => $user->getId(), 'action' => 'edit'])));
    }

    protected function start(string $mode, string $back)
    {
        try {
            $meta = $this->discovery();
            $state = Rules::randomToken();
            $nonce = Rules::randomToken();
            $verifier = Rules::randomToken(48);
            $store = new Container(self::SESSION);
            $store->pending = [
                'mode' => $mode,
                'user' => $mode === 'link' ? (int) $this->auth->getIdentity()->getId() : 0,
                'state' => $state,
                'nonce' => $nonce,
                'verifier' => $verifier,
                'back' => $back,
                'at' => time(),
            ];
            $query = http_build_query([
                'response_type' => 'code',
                'client_id' => $this->clientId(),
                'redirect_uri' => $this->redirectUri(),
                'scope' => 'openid profile email groups',
                'state' => $state,
                'nonce' => $nonce,
                'code_challenge' => Rules::pkceChallenge($verifier),
                'code_challenge_method' => 'S256',
            ], '', '&', PHP_QUERY_RFC3986);
            $url = $meta['authorization_endpoint'];
            return $this->redirect()->toUrl($url . (strpos($url, '?') === false ? '?' : '&') . $query);
        } catch (\Throwable $e) {
            return $this->refuse('The log-in service is not available', $e->getMessage());
        }
    }

    public function callbackAction()
    {
        $store = new Container(self::SESSION);
        /* The answer to Logout's question (Module::toProvider): does this browser still have a
           log-in at the provider? A code = yes: on to its "log out?" page. An error
           (login_required) = no: nothing to end there, Omeka's own "logged out". The code is
           never used. */
        $probe = \OidcLogin\Stdlib\ProviderLogout::open((string) ($_COOKIE[\OidcLogin\Stdlib\ProviderLogout::COOKIE] ?? ''),
            (string) ($this->config['client_secret'] ?? ''), time(), self::TTL);
        if ($probe && hash_equals($probe['state'], (string) $this->params()->fromQuery('state', ''))) {
            $this->getResponse()->getHeaders()->addHeaderLine('Set-Cookie', \OidcLogin\Stdlib\ProviderLogout::COOKIE . '=; Path=/oidc/; Max-Age=0; HttpOnly; SameSite=Lax');
            $code = (string) $this->params()->fromQuery('code', '');
            if ($code !== '' && !$this->params()->fromQuery('error') && $probe['end'] !== '') {
                return $this->redirect()->toUrl($probe['end']);
            }
            // nothing to end at the provider: back to the page Log out was pressed on, when it said
            if (($probe['back'] ?? '') !== '') {
                return $this->redirect()->toUrl($probe['back']);
            }
            $this->messenger()->addSuccess('Successfully logged out'); // @translate
            return $this->redirect()->toRoute('login');
        }
        $pending = $store->pending;
        /* One use only: whatever happens next, this attempt is spent. */
        unset($store->pending);

        if ($this->params()->fromQuery('error')) {
            return $this->refuse('Log-in was cancelled or refused', (string) $this->params()->fromQuery('error'));
        }
        $state = $this->params()->fromQuery('state');
        $code = $this->params()->fromQuery('code');
        if (!is_array($pending) || !is_string($state) || !hash_equals((string) ($pending['state'] ?? ''), $state)) {
            return $this->refuse('This log-in link has expired', 'state missing or does not match');
        }
        if (time() - (int) ($pending['at'] ?? 0) > self::TTL) {
            return $this->refuse('This log-in link has expired', 'state older than ' . self::TTL . ' s');
        }
        if (!is_string($code) || $code === '') {
            return $this->refuse('Log-in failed', 'no code');
        }

        try {
            $meta = $this->discovery();
            $tokens = $this->postForm($meta['token_endpoint'], [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->redirectUri(),
                'code_verifier' => (string) $pending['verifier'],
            ]);
            $claims = Rules::jwtPayload((string) ($tokens['id_token'] ?? ''));
            if (!$claims) {
                return $this->refuse('Log-in failed', 'no ID token');
            }
            $why = Rules::checkIdToken($claims, $this->issuer(), $this->clientId(), (string) $pending['nonce'], time());
            if ($why !== '') {
                return $this->refuse('Log-in failed', $why);
            }
            $info = $this->getJson($meta['userinfo_endpoint'], (string) ($tokens['access_token'] ?? ''));
        } catch (\Throwable $e) {
            return $this->refuse('The log-in service is not available', $e->getMessage());
        }

        [$username, $why] = Rules::checkInfo(
            $info,
            (string) $claims['sub'],
            Rules::parseList((string) $this->settings()->get('oidclogin_groups', ''))
        );
        if ($why !== '') {
            return $this->refuse('This account cannot log in here', $why);
        }
        $subject = (string) $claims['sub'];
        $owner = $this->links->subjectOwner($subject);

        if (($pending['mode'] ?? 'login') === 'link') {
            $me = $this->auth->getIdentity();
            $meId = $me ? (int) $me->getId() : 0;
            if ($meId !== (int) ($pending['user'] ?? -1)) {
                return $this->refuse('Linking failed', 'logged-in user changed during linking');
            }
            $why = Rules::checkSelfLink($meId, $owner, $this->links->get(Links::SUBJECT, $meId), $subject);
            if ($why !== '') {
                return $this->refuse('This account cannot be linked', $why);
            }
            $this->links->link($meId, $subject, $username);
            $this->links->forget($username);
            $this->links->log('self-link', $meId, $username, 'self');
            $this->messenger()->addSuccess(sprintf('Linked to %1$s. You can now log in with your %2$s.', $username, $this->account())); // @translate
            $back = (string) ($pending['back'] ?? '');
            return $this->redirect()->toUrl($back !== '' ? $back : $this->url()->fromRoute('admin/id', ['controller' => 'user', 'id' => $meId, 'action' => 'edit']));
        }

        [$userId, $linkNow, $why] = Rules::pickUser($owner, $this->links->waitingFor($username));
        /* Accounts from provider groups (1.1.0): off = exactly 1.0.0. */
        $auto = (bool) $this->settings()->get('oidclogin_auto', false);
        $role = $auto ? Rules::roleFor($info['groups'] ?? null, $this->groupRoles()) : null;
        $made = '';
        if (!$userId && $auto) {
            [$do, $found, $why] = Rules::autoAccount($role, $info, $username, $this->links->usersWithEmail((string) ($info['email'] ?? '')));
            if ($do === 'refuse') {
                $this->links->remember($info);
                return $this->refuse($role === null ? 'This account is not in a group that may log in here' : 'This account cannot log in here', $why);
            }
            if ($do === 'create') {
                $user = new User();
                $user->setEmail((string) $info['email']);
                $user->setName(Rules::displayName($info, $username));
                $user->setRole((string) $role);
                $user->setIsActive(true);
                $this->entityManager->persist($user);
                $this->entityManager->flush();
                $userId = (int) $user->getId();
                $made = 'created by groups as ' . $role;
            } else {
                $userId = $found;
                $made = 'linked by groups (same email)';
            }
            $linkNow = true;
        }
        if (!$userId) {
            $this->links->remember($info);
            return $this->refuse('This account is not linked yet', $why);
        }
        /** @var User|null $user */
        $user = $this->entityManager->find(User::class, $userId);
        if (!$user || !$user->isActive()) {
            return $this->refuse('This account cannot log in here', 'user ' . $userId . ' does not exist or is deactivated');
        }
        if ($linkNow) {
            $this->links->link($userId, $subject, $username);
            $this->links->forget($username);
            $this->links->log($made !== '' ? $made : 'first log-in', $userId, $username, $made !== '' ? 'groups' : 'self');
            if ($made !== '') {
                $this->links->setManaged($userId);
                error_log('OidcLogin: ' . $made . ': user ' . $userId . ' (' . $username . ')');
            }
        }
        /* The role of a user the groups made or linked follows the groups, before Omeka hears
           of the log-in (the session's length is decided by the role then). Out of every
           mapped group: no way in; the account stays. Users linked by hand: never touched. */
        if ($auto && $this->links->isManaged($userId)) {
            if ($role === null) {
                return $this->refuse('This account is not in a group that may log in here', 'user ' . $userId . ' is in no mapped group any more');
            }
            $was = (string) $user->getRole();
            if ($was !== $role) {
                $user->setRole($role);
                $this->entityManager->flush();
                $this->links->log('role ' . $was . ' → ' . $role . ' (groups)', $userId, $username, 'groups');
                error_log('OidcLogin: role of user ' . $userId . ' (' . $username . ') ' . $was . ' → ' . $role . ' by groups');
            }
        }

        /* The same steps as Omeka's own LoginController after a good password. */
        $sessionManager = Container::getDefaultManager();
        $sessionManager->regenerateId();
        $this->auth->getStorage()->write($user);
        /* Remembered for Logout (Module::toProvider): this log-in was the provider's, its ID
           token and the provider's end-session endpoint. A password log-in has none. */
        $store->via = 'oidc';
        $store->idToken = (string) ($tokens['id_token'] ?? '');
        $store->endSession = (string) ($meta['end_session_endpoint'] ?? '');
        $store->probe = ['auth' => (string) ($meta['authorization_endpoint'] ?? ''), 'client' => $this->clientId(), 'redirect' => $this->redirectUri()];
        $this->getEventManager()->trigger('user.login', $user);
        $this->messenger()->addSuccess('Successfully logged in'); // @translate

        $back = (string) ($pending['back'] ?? '');
        if ($back === '') {
            $redirect = $sessionManager->getStorage()->offsetGet('redirect_url');
            $back = Rules::safeRedirect(is_string($redirect) ? $redirect : null, '');
        }
        if ($back !== '') {
            return $this->redirect()->toUrl($back);
        }
        if ($this->userIsAllowed('Omeka\Controller\Admin\Index', 'browse')) {
            return $this->redirect()->toRoute('admin');
        }
        return $this->redirect()->toRoute('top');
    }

    /** Show why, log the detail, offer the password page. Never says more than needed. */
    protected function refuse(string $message, string $detail)
    {
        error_log('OidcLogin: ' . $message . ': ' . $detail);
        $this->getResponse()->setStatusCode(403);
        $view = new ViewModel(['message' => $message, 'account' => $this->account()]);
        $view->setTemplate('oidc-login/refused');
        return $view;
    }

    /** The admin page's "provider group → Omeka role" table, kept to roles Omeka has now. */
    protected function groupRoles(): array
    {
        $acl = $this->getEvent()->getApplication()->getServiceManager()->get('Omeka\Acl');
        $rows = [];
        foreach ((array) $this->settings()->get('oidclogin_group_roles', []) as $g => $r) {
            $rows[] = ['group' => $g, 'role' => $r];
        }
        return Rules::groupRoles($rows, array_map('strval', $acl->getRoles()));
    }

    /** "Example account" — what this site calls the provider account (settings). */
    protected function account(): string
    {
        return \OidcLogin\Module::accountName($this->settings());
    }

    protected function issuer(): string
    {
        return rtrim((string) $this->settings()->get('oidclogin_issuer', ''), '/');
    }

    protected function clientId(): string
    {
        $id = (string) ($this->config['client_id'] ?? '');
        if ($id === '') {
            throw new \RuntimeException('client_id is not set in local.config.php');
        }
        return $id;
    }

    protected function redirectUri(): string
    {
        /* Written out in full in the settings — never built from the request, because
           behind a TLS proxy the request says http and port 80. */
        $uri = (string) $this->settings()->get('oidclogin_redirect_uri', '');
        if (!Rules::redirectUriOk($uri)) {
            throw new \RuntimeException('redirect URI must be https (or http on localhost)');
        }
        return $uri;
    }

    /** @return array<string,mixed> */
    protected function discovery(): array
    {
        $issuer = $this->issuer();
        if ($issuer === '') {
            throw new \RuntimeException('issuer is not set');
        }
        $meta = $this->getJson($issuer . '/.well-known/openid-configuration', '');
        $why = Rules::checkDiscovery($meta, $issuer);
        if ($why !== '') {
            throw new \RuntimeException($why);
        }
        return $meta;
    }

    /** @return array<string,mixed> */
    protected function getJson(string $url, string $bearer): array
    {
        $http = clone $this->http;
        $http->reset();
        $http->setUri($url)->setMethod('GET')->setOptions(['timeout' => 10]);
        if ($bearer !== '') {
            $http->setHeaders(['Authorization' => 'Bearer ' . $bearer, 'Accept' => 'application/json']);
        }
        return $this->decode($http->send(), $url);
    }

    /** @return array<string,mixed> */
    protected function postForm(string $url, array $form): array
    {
        $secret = (string) ($this->config['client_secret'] ?? '');
        if ($secret === '') {
            throw new \RuntimeException('client_secret is not set in local.config.php');
        }
        $http = clone $this->http;
        $http->reset();
        $http->setUri($url)->setMethod('POST')->setOptions(['timeout' => 10]);
        $http->setHeaders([
            'Authorization' => 'Basic ' . base64_encode(rawurlencode($this->clientId()) . ':' . rawurlencode($secret)),
            'Accept' => 'application/json',
        ]);
        $http->setParameterPost($form);
        return $this->decode($http->send(), $url);
    }

    /** @return array<string,mixed> */
    protected function decode($response, string $url): array
    {
        if (!$response->isSuccess()) {
            throw new \RuntimeException(parse_url($url, PHP_URL_PATH) . ' answered ' . $response->getStatusCode());
        }
        $data = json_decode($response->getBody(), true);
        if (!is_array($data)) {
            throw new \RuntimeException(parse_url($url, PHP_URL_PATH) . ' did not answer JSON');
        }
        return $data;
    }
}
