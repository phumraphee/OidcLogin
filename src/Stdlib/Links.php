<?php
namespace OidcLogin\Stdlib;

use Doctrine\DBAL\Connection;

/**
 * WHO IS LINKED TO WHICH PROVIDER ACCOUNT — KEPT IN OMEKA'S OWN user_setting TABLE.
 *
 *   oidclogin_subject   the provider's sub, once linked (the only thing that logs anyone in)
 *   oidclogin_username  the provider username: shown on the admin page, and — while there
 *                        is no subject yet — the username an administrator said this user
 *                        will log in with ("waiting"); the first log-in with it links.
 *
 * People who tried to log in but are not linked are remembered (last 50, setting
 * oidclogin_seen) so the admin page can offer their usernames.
 */
class Links
{
    const SUBJECT = 'oidclogin_subject';
    const USERNAME = 'oidclogin_username';
    const SEEN = 'oidclogin_seen';
    const LOG = 'oidclogin_log';
    /** '1' on a user the groups made or linked (1.1.0): their role follows their groups. */
    const MANAGED = 'oidclogin_managed';

    protected $db;

    public function __construct(Connection $db)
    {
        $this->db = $db;
    }

    /** @return array<int,string> user id => decoded value, for one user_setting id */
    public function all(string $id): array
    {
        $out = [];
        foreach ($this->db->fetchAllAssociative('SELECT user_id, value FROM user_setting WHERE id = ?', [$id]) as $row) {
            $v = json_decode((string) $row['value'], true);
            if (is_string($v) && $v !== '') {
                $out[(int) $row['user_id']] = $v;
            }
        }
        return $out;
    }

    public function get(string $id, int $userId): ?string
    {
        $v = $this->db->fetchOne('SELECT value FROM user_setting WHERE id = ? AND user_id = ?', [$id, $userId]);
        $v = $v === false ? null : json_decode((string) $v, true);
        return is_string($v) && $v !== '' ? $v : null;
    }

    /** the user linked to this subject, 0 = none */
    public function subjectOwner(string $subject): int
    {
        foreach ($this->all(self::SUBJECT) as $userId => $v) {
            if (hash_equals($v, $subject)) {
                return $userId;
            }
        }
        return 0;
    }

    /** users waiting for this username (username set, no subject yet) @return int[] */
    public function waitingFor(string $username): array
    {
        $linked = $this->all(self::SUBJECT);
        $out = [];
        foreach ($this->all(self::USERNAME) as $userId => $v) {
            if ($v === $username && !isset($linked[$userId])) {
                $out[] = $userId;
            }
        }
        return $out;
    }

    public function link(int $userId, string $subject, string $username): void
    {
        $this->put(self::SUBJECT, $userId, $subject);
        $this->put(self::USERNAME, $userId, $username);
    }

    /** an administrator says: this user will log in as $username (or '' = clear) */
    public function setWaiting(int $userId, string $username): void
    {
        if ($this->get(self::SUBJECT, $userId) !== null) {
            return;   // already linked — only "unlink" changes that
        }
        if ($username === '') {
            $this->delete(self::USERNAME, $userId);
        } else {
            $this->put(self::USERNAME, $userId, $username);
        }
    }

    public function unlink(int $userId): void
    {
        $this->delete(self::SUBJECT, $userId);
        $this->delete(self::USERNAME, $userId);
        // linked again by hand later, the groups do not take their role over again
        $this->delete(self::MANAGED, $userId);
    }

    public function isManaged(int $userId): bool
    {
        return $this->get(self::MANAGED, $userId) === '1';
    }

    public function setManaged(int $userId): void
    {
        $this->put(self::MANAGED, $userId, '1');
    }

    /**
     * The users whose email address is this one, compared without case, with what this module
     * knows of each.
     *
     * @return array<int,array{id:int,active:bool,subject:?string,waiting:?string}>
     */
    public function usersWithEmail(string $email): array
    {
        if ($email === '') {
            return [];
        }
        $out = [];
        foreach ($this->db->fetchAllAssociative('SELECT id, is_active FROM user WHERE LOWER(email) = LOWER(?)', [$email]) as $u) {
            $id = (int) $u['id'];
            $out[] = ['id' => $id, 'active' => (bool) $u['is_active'], 'subject' => $this->get(self::SUBJECT, $id), 'waiting' => $this->get(self::USERNAME, $id)];
        }
        return $out;
    }

    /** @param array<string,mixed> $info userinfo of someone who is not linked */
    public function remember(array $info): void
    {
        $username = (string) ($info['preferred_username'] ?? '');
        if ($username === '') {
            return;
        }
        $seen = $this->seen();
        $seen = array_values(array_filter($seen, fn($s) => ($s['username'] ?? '') !== $username));
        array_unshift($seen, [
            'username' => mb_substr($username, 0, 100),
            'name' => mb_substr((string) ($info['name'] ?? trim(($info['given_name'] ?? '') . ' ' . ($info['family_name'] ?? ''))), 0, 150),
            'email' => mb_substr((string) ($info['email'] ?? ''), 0, 190),
            'at' => time(),
        ]);
        $this->putSetting(self::SEEN, array_slice($seen, 0, 50));
    }

    /** @return array<int,array{username:string,name:string,email:string,at:int}> */
    public function seen(): array
    {
        $v = $this->db->fetchOne('SELECT value FROM setting WHERE id = ?', [self::SEEN]);
        $v = $v === false ? [] : json_decode((string) $v, true);
        return is_array($v) ? $v : [];
    }

    public function forget(string $username): void
    {
        $this->putSetting(self::SEEN, array_values(array_filter($this->seen(), fn($s) => ($s['username'] ?? '') !== $username)));
    }

    /** Note who linked/unlinked whom (latest 200). Never throws: logging must not stop a log-in. */
    public function log(string $action, int $userId, string $username, string $by): void
    {
        try {
            $log = $this->db->fetchOne('SELECT value FROM setting WHERE id = ?', [self::LOG]);
            $log = $log === false ? [] : (json_decode((string) $log, true) ?: []);
            array_unshift($log, ['at' => time(), 'action' => $action, 'user' => $userId, 'username' => mb_substr($username, 0, 100), 'by' => mb_substr($by, 0, 190)]);
            $this->putSetting(self::LOG, array_slice($log, 0, 200));
        } catch (\Throwable $e) {
            error_log('OidcLogin log: ' . $e->getMessage());
        }
    }

    /** @return array<int,array{at:int,action:string,user:int,username:string,by:string}> */
    public function history(): array
    {
        $v = $this->db->fetchOne('SELECT value FROM setting WHERE id = ?', [self::LOG]);
        $v = $v === false ? [] : json_decode((string) $v, true);
        return is_array($v) ? $v : [];
    }

    protected function put(string $id, int $userId, string $value): void
    {
        $json = json_encode($value);
        $n = $this->db->executeStatement('UPDATE user_setting SET value = ? WHERE id = ? AND user_id = ?', [$json, $id, $userId]);
        if (!$n && $this->get($id, $userId) === null) {
            $this->db->executeStatement('INSERT INTO user_setting (id, user_id, value) VALUES (?, ?, ?)', [$id, $userId, $json]);
        }
    }

    protected function delete(string $id, int $userId): void
    {
        $this->db->executeStatement('DELETE FROM user_setting WHERE id = ? AND user_id = ?', [$id, $userId]);
    }

    protected function putSetting(string $id, $value): void
    {
        $json = json_encode($value);
        if ($this->db->fetchOne('SELECT 1 FROM setting WHERE id = ?', [$id]) === false) {
            $this->db->executeStatement('INSERT INTO setting (id, value) VALUES (?, ?)', [$id, $json]);
        } else {
            $this->db->executeStatement('UPDATE setting SET value = ? WHERE id = ?', [$json, $id]);
        }
    }
}
