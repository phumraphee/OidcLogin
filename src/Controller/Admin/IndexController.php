<?php
namespace OidcLogin\Controller\Admin;

use Doctrine\DBAL\Connection;
use Laminas\Mvc\Controller\AbstractActionController;
use Laminas\Validator\Csrf;
use Laminas\View\Model\ViewModel;
use OidcLogin\Stdlib\Directory;
use OidcLogin\Stdlib\Links;
use OidcLogin\Stdlib\Rules;

/**
 * /admin/oidc-login — every Omeka user, whether they are linked, and which account at the
 * provider is theirs. Names are checked against the provider's real list (Directory: an
 * API key, or a list pasted here); a username that is not in that list is not saved. When
 * the list cannot be had, the page still works as before and says it could not check.
 * Nobody is created here; global admin only.
 *
 * Accounts from provider groups (1.1.0): a switch, off by default, and a table "provider group
 * → Omeka role" (oidclogin_auto, oidclogin_group_roles). What they do at log-in is
 * LoginController's; this page only keeps them, each change in the history.
 */
class IndexController extends AbstractActionController
{
    protected $db;
    protected $links;
    protected $directory;

    public function __construct(Connection $db, Links $links, Directory $directory)
    {
        $this->db = $db;
        $this->links = $links;
        $this->directory = $directory;
    }

    public function indexAction()
    {
        $me = $this->identity();
        if (!$me || $me->getRole() !== 'global_admin') {
            $this->getResponse()->setStatusCode(403);
            return (new ViewModel())->setTemplate('oidc-login/admin/index/forbidden');
        }
        $by = $me->getName() . ' (#' . $me->getId() . ')';
        $request = $this->getRequest();
        $dir = $this->directory->people((bool) $this->params()->fromQuery('refresh'));
        $users = $this->db->fetchAllAssociative('SELECT id, name, email, role, is_active FROM user ORDER BY is_active DESC, name');

        if ($request->isPost()) {
            $csrf = new Csrf(['name' => 'oidclogin_admin']);
            if (!$csrf->isValid((string) $request->getPost('oidclogin_admin'))) {
                $this->messenger()->addError('The form has expired. Please try again.'); // @translate
                return $this->redirect()->toRoute('admin/oidc-login');
            }
            $action = (string) $request->getPost('do', 'save');
            if ($action === 'groups') {
                $rows = [];
                foreach ((array) $request->getPost('grp', []) as $i => $g) {
                    $rows[] = ['group' => $g, 'role' => ((array) $request->getPost('grprole', []))[$i] ?? ''];
                }
                $map = Rules::groupRoles($rows, array_keys($this->roleLabels()));
                $auto = (bool) $request->getPost('auto');
                $before = [(bool) $this->settings()->get('oidclogin_auto', false), (array) $this->settings()->get('oidclogin_group_roles', [])];
                $this->settings()->set('oidclogin_group_roles', $map);
                $this->settings()->set('oidclogin_auto', $auto);
                /* the person's word that self-account editing is off at the provider (when the
                   provider cannot be asked): a quiet line instead of the box */
                $this->settings()->set('oidclogin_selfedit_off', (bool) $request->getPost('selfedit_off'));
                if ($before !== [$auto, $map]) {
                    $said = [];
                    foreach ($map as $g => $r) {
                        $said[] = $g . '→' . $r;
                    }
                    $this->links->log(($auto ? 'groups on: ' : 'groups off: ') . ($said ? implode(', ', $said) : 'no groups'), 0, '', $by);
                }
                $this->messenger()->addSuccess($auto ? 'Accounts from provider groups: on.' : 'Accounts from provider groups: off.'); // @translate
                return $this->redirect()->toRoute('admin/oidc-login');
            }
            if ($action === 'paste') {
                $this->directory->savePaste((string) $request->getPost('paste', ''));
                $this->messenger()->addSuccess(sprintf('List saved: %d people.', count(Rules::parsePasted((string) $request->getPost('paste', ''))))); // @translate
                return $this->redirect()->toRoute('admin/oidc-login');
            }
            if ($action === 'bulk-preview' || $action === 'bulk-apply') {
                $plan = $this->emailMatches($users, $dir);
                if ($action === 'bulk-preview') {
                    $view = new ViewModel(['plan' => $plan, 'csrf' => (new Csrf(['name' => 'oidclogin_admin']))->getHash(),
                        'account' => \OidcLogin\Module::accountName($this->settings())]);
                    return $view->setTemplate('oidc-login/admin/index/confirm');
                }
                foreach ($plan as $p) {
                    $this->links->setWaiting($p['id'], $p['username']);
                    $this->links->log('waiting (email match)', $p['id'], $p['username'], $by);
                }
                $this->messenger()->addSuccess(sprintf('%d people are now waiting for their first log-in.', count($plan))); // @translate
                return $this->redirect()->toRoute('admin/oidc-login');
            }
            $changed = 0;
            foreach ((array) $request->getPost('waiting', []) as $userId => $username) {
                $username = trim((string) $username);
                if ($username !== '' && !preg_match('/^[A-Za-z0-9][A-Za-z0-9_.@-]{0,99}$/', $username)) {
                    $this->messenger()->addError(sprintf('"%s" is not a valid username.', $username)); // @translate
                    continue;
                }
                $before = $this->links->get(Links::USERNAME, (int) $userId) ?? '';
                if ($before === $username) {
                    continue;
                }
                if ($username !== '' && $dir['ok'] && !Rules::findUsername($dir['people'], $username)) {
                    $this->messenger()->addError(sprintf('"%s" is not an account at the provider — create it there first. Not saved.', $username)); // @translate
                    continue;
                }
                $this->links->setWaiting((int) $userId, $username);
                $this->links->log($username === '' ? 'cleared' : 'waiting', (int) $userId, $username, $by);
                $changed++;
            }
            foreach ((array) $request->getPost('unlink', []) as $userId => $yes) {
                if ($yes) {
                    $this->links->log('unlink', (int) $userId, (string) $this->links->get(Links::USERNAME, (int) $userId), $by);
                    $this->links->unlink((int) $userId);
                    $changed++;
                }
            }
            $this->messenger()->addSuccess(sprintf('%d change(s) saved.', $changed)); // @translate
            return $this->redirect()->toRoute('admin/oidc-login');
        }

        $subjects = $this->links->all(Links::SUBJECT);
        $usernames = $this->links->all(Links::USERNAME);
        $seen = $this->links->seen();
        $rows = [];
        foreach ($users as $u) {
            $id = (int) $u['id'];
            $status = isset($subjects[$id]) ? 'linked' : (isset($usernames[$id]) ? 'waiting' : 'none');
            $row = [
                'id' => $id,
                'name' => (string) $u['name'],
                'email' => (string) $u['email'],
                'role' => (string) $u['role'],
                'active' => (bool) $u['is_active'],
                'status' => $status,
                'username' => $usernames[$id] ?? '',
                'check' => 'unknown',   // found | missing | mismatch | unknown · for linked: ok | gone | renamed
                'match' => null,
                'suggest' => [],
            ];
            if ($dir['ok']) {
                $m = Rules::matchPerson(['name' => $row['name'], 'email' => $row['email']], $dir['people']);
                $row['match'] = $m['person'];
                if ($status === 'linked') {
                    $row['check'] = Rules::checkLinked($dir['people'], $subjects[$id], $row['username']) ?: 'unknown';
                } elseif ($status === 'waiting') {
                    $row['check'] = Rules::findUsername($dir['people'], $row['username']) ? 'found' : 'missing';
                } else {
                    $row['check'] = $m['person'] ? ($m['emailDiffers'] ? 'mismatch' : 'found') : 'missing';
                }
                $row['suggest'] = $m['person'] ? [$m['person']['username']] : [];
            } else {
                /* Could not check: the old guesses, marked as guesses. */
                $row['suggest'] = array_slice(array_keys(Rules::suggest(['name' => $row['name'], 'email' => $row['email']], $seen)), 0, 5);
            }
            $rows[] = $row;
        }
        return new ViewModel([
            'rows' => $rows,
            'seen' => $seen,
            'dir' => $dir,
            'people' => $dir['ok'] ? $dir['people'] : [],
            'emailMatches' => $dir['ok'] ? count($this->emailMatches($users, $dir)) : 0,
            'history' => array_slice($this->links->history(), 0, 20),
            'pasted' => $this->directory->pasteText(),
            'auto' => (bool) $this->settings()->get('oidclogin_auto', false),
            'selfEditSaid' => (bool) $this->settings()->get('oidclogin_selfedit_off', false),
            'selfEditOff' => $this->directory->selfEditOff(),
            'groupRoles' => (array) $this->settings()->get('oidclogin_group_roles', []),
            'roleLabels' => $this->roleLabels(),
            'managed' => $this->links->all(Links::MANAGED),
            'account' => \OidcLogin\Module::accountName($this->settings()),
            'csrf' => (new Csrf(['name' => 'oidclogin_admin']))->getHash(),
        ]);
    }

    /** Omeka's roles, id => label, from its ACL (so a role a module adds is offered too). */
    protected function roleLabels(): array
    {
        $acl = $this->getEvent()->getApplication()->getServiceManager()->get('Omeka\Acl');
        $labels = method_exists($acl, 'getRoleLabels') ? $acl->getRoleLabels() : array_combine($acl->getRoles(), $acl->getRoles());
        $out = [];
        foreach ($labels as $id => $label) {
            $out[(string) $id] = (string) $label;
        }
        return $out;
    }

    /** Active users, not linked or waiting yet, whose verified email is the same at the provider. */
    protected function emailMatches(array $users, array $dir): array
    {
        if (!$dir['ok']) {
            return [];
        }
        $subjects = $this->links->all(Links::SUBJECT);
        $usernames = $this->links->all(Links::USERNAME);
        $taken = array_flip(array_values($usernames));
        $plan = [];
        foreach ($users as $u) {
            $id = (int) $u['id'];
            if (!$u['is_active'] || isset($subjects[$id]) || isset($usernames[$id])) {
                continue;
            }
            $m = Rules::matchPerson(['name' => (string) $u['name'], 'email' => (string) $u['email']], $dir['people']);
            if ($m['by'] === 'email' && !isset($taken[$m['person']['username']])) {
                $plan[] = ['id' => $id, 'name' => (string) $u['name'], 'email' => (string) $u['email'], 'username' => $m['person']['username']];
                $taken[$m['person']['username']] = true;
            }
        }
        return $plan;
    }
}
