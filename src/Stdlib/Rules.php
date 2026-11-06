<?php
namespace OidcLogin\Stdlib;

/**
 * THE DECISIONS, KEPT APART FROM OMEKA SO THEY CAN BE TESTED ON THEIR OWN.
 *
 * Everything here is a plain function of its arguments: no session, no database, no
 * network. The controller gathers the facts (settings, claims, the user row) and asks
 * these functions what to do with them. tests/run.php holds the cases.
 */
class Rules
{
    /**
     * The map an administrator writes in the module settings, one person per line:
     * "username = Omeka user id". Blank lines and lines starting with # are ignored.
     * Usernames are compared exactly as written (the identity provider decides case).
     *
     * @return array<string,int> username => user id; a line that does not parse is left out
     */
    public static function parseMap(string $text): array
    {
        $map = [];
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (!preg_match('/^(\S+)\s*=\s*(\d+)$/', $line, $m)) {
                continue;
            }
            $id = (int) $m[2];
            if ($id > 0) {
                $map[$m[1]] = $id;
            }
        }
        return $map;
    }

    /**
     * A list of group names written with spaces, commas or new lines.
     *
     * @return string[]
     */
    public static function parseList(string $text): array
    {
        $out = [];
        foreach (preg_split('/[\s,]+/', $text) ?: [] as $one) {
            if ($one !== '') {
                $out[$one] = true;
            }
        }
        return array_keys($out);
    }

    /**
     * Where to go after logging in. Only a path on this same site is accepted: it must
     * start with one "/" and not "//" or "/\" (both of which browsers read as another
     * host), and carry no scheme, no control characters and no backslashes.
     */
    public static function safeRedirect(?string $wanted, string $fallback = '/'): string
    {
        if (!is_string($wanted) || $wanted === '' || strlen($wanted) > 2000) {
            return $fallback;
        }
        if ($wanted[0] !== '/' || (isset($wanted[1]) && ($wanted[1] === '/' || $wanted[1] === '\\'))) {
            return $fallback;
        }
        if (preg_match('/[\x00-\x1f\x7f\\\\]/', $wanted)) {
            return $fallback;
        }
        return $wanted;
    }

    /**
     * The middle part of a JWT, decoded. The signature is not checked here: the token
     * comes straight from the provider's token endpoint over TLS in exchange for the code
     * and the client secret (OpenID Connect Core 3.1.3.7, item 6), and it is only used to
     * check iss, aud, nonce and expiry and to compare sub with the userinfo answer.
     *
     * @return array<string,mixed>|null
     */
    public static function jwtPayload(string $jwt): ?array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }
        $b64 = strtr($parts[1], '-_', '+/');
        $b64 .= str_repeat('=', (4 - strlen($b64) % 4) % 4);
        $json = base64_decode($b64, true);
        if ($json === false) {
            return null;
        }
        $data = json_decode($json, true);
        return is_array($data) ? $data : null;
    }

    /**
     * Check the ID token's claims. Returns '' when they are good, or the reason they are not.
     *
     * @param array<string,mixed> $claims
     */
    public static function checkIdToken(array $claims, string $issuer, string $clientId, string $nonce, int $now, int $leeway = 120): string
    {
        if (($claims['iss'] ?? null) !== $issuer) {
            return 'issuer does not match';
        }
        $aud = $claims['aud'] ?? null;
        $auds = is_array($aud) ? $aud : [$aud];
        if (!in_array($clientId, $auds, true)) {
            return 'audience does not match';
        }
        if (count($auds) > 1 && ($claims['azp'] ?? null) !== $clientId) {
            return 'authorized party does not match';
        }
        if (!is_string($claims['nonce'] ?? null) || !hash_equals($nonce, $claims['nonce'])) {
            return 'nonce does not match';
        }
        if (!is_numeric($claims['exp'] ?? null) || (int) $claims['exp'] + $leeway < $now) {
            return 'token has expired';
        }
        if (!is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            return 'no subject';
        }
        return '';
    }

    /**
     * Check the userinfo answer before anything is looked up. Returns [username, ''] or
     * ['', reason]. The username is the provider's preferred_username.
     *
     * @param array<string,mixed> $info    the userinfo answer
     * @param string              $subject sub from the checked ID token
     * @param string[]            $allowedGroups empty = no group check
     */
    public static function checkInfo(array $info, string $subject, array $allowedGroups): array
    {
        if (($info['sub'] ?? null) !== $subject) {
            return ['', 'userinfo is about someone else'];
        }
        if ($allowedGroups) {
            $groups = $info['groups'] ?? [];
            if (!is_array($groups) || !array_intersect($allowedGroups, array_filter($groups, 'is_string'))) {
                return ['', 'not in an allowed group'];
            }
        }
        if (array_key_exists('email_verified', $info) && $info['email_verified'] !== true) {
            return ['', 'email address is not verified'];
        }
        $username = $info['preferred_username'] ?? null;
        if (!is_string($username) || $username === '') {
            return ['', 'no username in the answer'];
        }
        return [$username, ''];
    }

    /**
     * Whom to log in as. A user already linked to this subject wins; otherwise the one
     * user an administrator marked as waiting for this username (and not yet linked) is
     * linked now. Returns [user id, link now?, reason].
     *
     * @param int   $subjectOwner  user already linked to this subject, 0 = none
     * @param int[] $waiting       users waiting for this username with no subject yet
     */
    public static function pickUser(int $subjectOwner, array $waiting): array
    {
        if ($subjectOwner > 0) {
            return [$subjectOwner, false, ''];
        }
        $waiting = array_values(array_unique(array_filter($waiting, fn($id) => $id > 0)));
        if (count($waiting) === 1) {
            return [$waiting[0], true, ''];
        }
        if (count($waiting) > 1) {
            return [0, false, 'this username is waiting on more than one user'];
        }
        return [0, false, 'this account is not linked to a user here'];
    }

    /**
     * Omeka's own roles, highest first. A role a module adds (Guest's "guest") ranks below
     * all of them; two roles of the same rank are told apart by name, so the answer never
     * depends on the order of anything.
     */
    const ROLE_ORDER = ['global_admin', 'site_admin', 'editor', 'reviewer', 'author', 'researcher'];

    /**
     * GROUPS THAT MAKE AN ACCOUNT (1.1.0). The rows of the admin page's table "provider group
     * → Omeka role", cleaned: a group name without spaces or commas (as the provider writes
     * it, case and all), a role Omeka knows ($known). A later row for the same group wins.
     *
     * @param array<int,array{group?:mixed,role?:mixed}> $rows
     * @param string[] $known  the roles Omeka has (its ACL)
     * @return array<string,string> group => role
     */
    public static function groupRoles(array $rows, array $known): array
    {
        $out = [];
        foreach ($rows as $r) {
            $g = trim((string) (is_array($r) ? ($r['group'] ?? '') : ''));
            $role = trim((string) (is_array($r) ? ($r['role'] ?? '') : ''));
            if ($g === '' || $role === '' || !preg_match('/^[^\s,]{1,190}$/u', $g) || !in_array($role, $known, true)) {
                continue;
            }
            $out[$g] = $role;
        }
        return $out;
    }

    /**
     * The role a person's groups give: the highest of the roles their groups are mapped to,
     * null when none of their groups is in the map. global_admin only ever comes from a row
     * that says global_admin.
     *
     * @param mixed $groups  the groups claim (anything that is not a list of strings = none)
     * @param array<string,string> $map  group => role (groupRoles)
     */
    public static function roleFor($groups, array $map): ?string
    {
        if (!is_array($groups)) {
            return null;
        }
        $best = null;
        $bestRank = PHP_INT_MAX;
        foreach ($groups as $g) {
            if (!is_string($g) || !isset($map[$g])) {
                continue;
            }
            $role = $map[$g];
            $rank = array_search($role, self::ROLE_ORDER, true);
            $rank = $rank === false ? count(self::ROLE_ORDER) : $rank;
            if ($rank < $bestRank || ($rank === $bestRank && strcmp($role, (string) $best) < 0)) {
                $best = $role;
                $bestRank = $rank;
            }
        }
        return $best;
    }

    /**
     * Somebody nobody here is linked to (and nobody waits for) logs in while automatic
     * accounts are on. What to do: ['create', 0, ''] a new user · ['link', user id, ''] the
     * one user with the same email address · ['refuse', 0, reason].
     *
     * Matching by email is safe only because people cannot change their own email address at
     * the provider (Pocket ID: "Enable self-account editing" off) — README, admin page.
     *
     * @param string|null $role  roleFor() of their groups
     * @param array<string,mixed> $info  the userinfo answer
     * @param string $username  their provider username
     * @param array<int,array{id:int,active:bool,subject:?string,waiting:?string}> $emailUsers
     *        the users here whose email is theirs (compared without case)
     */
    public static function autoAccount(?string $role, array $info, string $username, array $emailUsers): array
    {
        if ($role === null) {
            return ['refuse', 0, 'not in a group that may log in here'];
        }
        $email = $info['email'] ?? null;
        if (!is_string($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['refuse', 0, 'no email address in the answer'];
        }
        if (($info['email_verified'] ?? null) !== true) {
            return ['refuse', 0, 'email address is not verified'];
        }
        if (count($emailUsers) > 1) {
            return ['refuse', 0, 'more than one user here has this email address'];
        }
        if (!$emailUsers) {
            return ['create', 0, ''];
        }
        $u = $emailUsers[0];
        if (empty($u['active'])) {
            return ['refuse', 0, 'the user here with this email address is deactivated'];
        }
        if ((string) ($u['subject'] ?? '') !== '') {
            return ['refuse', 0, 'the user here with this email address is linked to another account'];
        }
        if ((string) ($u['waiting'] ?? '') !== '' && $u['waiting'] !== $username) {
            return ['refuse', 0, 'the user here with this email address is waiting for another username'];
        }
        return ['link', (int) $u['id'], ''];
    }

    /** The name a new user gets: name, else given + family name, else the username (190 at most). */
    public static function displayName(array $info, string $username): string
    {
        $name = is_string($info['name'] ?? null) ? trim($info['name']) : '';
        if ($name === '') {
            $name = trim((is_string($info['given_name'] ?? null) ? $info['given_name'] : '') . ' '
                . (is_string($info['family_name'] ?? null) ? $info['family_name'] : ''));
        }
        $name = preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $name !== '' ? $name : $username);
        return mb_substr(trim((string) $name), 0, 190);
    }

    /**
     * Linking from a logged-in user's own page: may this subject be linked to user $me?
     * Returns '' when allowed.
     */
    public static function checkSelfLink(int $me, int $subjectOwner, ?string $myStored, string $subject): string
    {
        if ($me <= 0) {
            return 'not logged in';
        }
        if ($subjectOwner > 0 && $subjectOwner !== $me) {
            return 'this provider account is already linked to another user';
        }
        if ($myStored !== null && $myStored !== '' && !hash_equals($myStored, $subject)) {
            return 'this user is linked to another provider account — unlink it first';
        }
        return '';
    }

    /**
     * Suggest provider usernames for an Omeka user, best first. Candidates are people seen
     * at the provider (username, name, email); guesses are built from the user's own email
     * and name for when nobody has been seen yet. Returns username => score (0–100).
     *
     * @param array{name:string,email:string} $user
     * @param array<int,array{username:string,name?:string,email?:string}> $seen
     * @return array<string,int>
     */
    public static function suggest(array $user, array $seen): array
    {
        $email = strtolower(trim($user['email'] ?? ''));
        $local = strstr($email, '@', true) ?: $email;
        $name = self::fold($user['name'] ?? '');
        $out = [];
        foreach ($seen as $c) {
            $u = (string) ($c['username'] ?? '');
            if ($u === '') {
                continue;
            }
            $score = 0;
            $ce = strtolower(trim((string) ($c['email'] ?? '')));
            if ($ce !== '' && $ce === $email) {
                $score = 100;
            } elseif ($name !== '' && self::fold((string) ($c['name'] ?? '')) === $name) {
                $score = 90;
            } elseif ($local !== '' && strtolower($u) === $local) {
                $score = 80;
            } else {
                similar_text(self::fold($u), $name !== '' ? $name : $local, $pct);
                $score = (int) round($pct * 0.6);
            }
            $out[$u] = max($out[$u] ?? 0, $score);
        }
        /* Guesses, lower than anything actually seen with a good match. */
        $parts = preg_split('/\s+/', strtolower(trim($user['name'] ?? ''))) ?: [];
        $guesses = [];
        if ($local !== '') {
            /* A work address's first part is often the username; a free-mail one rarely. */
            $domain = substr(strrchr($email, '@') ?: '', 1);
            $free = in_array($domain, ['gmail.com', 'googlemail.com', 'hotmail.com', 'outlook.com', 'live.com',
                'yahoo.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com'], true);
            $guesses[$local] = $free ? 30 : 50;
        }
        if (count($parts) >= 2 && preg_match('/^[a-z]+$/', $parts[0]) && preg_match('/^[a-z]+/', end($parts), $m)) {
            $guesses[$parts[0] . '.' . substr($m[0], 0, 2)] = max($guesses[$parts[0] . '.' . substr($m[0], 0, 2)] ?? 0, 45);
            $guesses[$parts[0]] = max($guesses[$parts[0]] ?? 0, 40);
        }
        foreach ($guesses as $g => $score) {
            if (!isset($out[$g])) {
                $out[$g] = $score;
            }
        }
        arsort($out);
        return $out;
    }

    /** lower case, letters and digits only */
    public static function fold(string $s): string
    {
        return preg_replace('/[^a-z0-9]+/', '', strtolower($s)) ?? '';
    }

    /** What the provider account is called when nobody has named it (setting "Account name"). */
    const ACCOUNT = 'OpenID Connect account';

    /**
     * The name people know their provider account by ("Example account"), for this
     * visitor: Thai when the browser asks for Thai first, else English; an empty one falls
     * back to the other, then to ACCOUNT.
     */
    public static function accountName(string $acceptLanguage, string $en, string $th): string
    {
        $en = trim($en);
        $th = trim($th);
        $name = self::wantsThai($acceptLanguage) ? ($th !== '' ? $th : $en) : ($en !== '' ? $en : $th);
        return $name !== '' ? $name : self::ACCOUNT;
    }

    /**
     * The button text for this visitor: the Thai text when the browser asks for Thai before
     * English, else the English text, else "Log in with " + the account name for this visitor
     * (accountName()), else the Thai text.
     */
    public static function buttonLabel(string $acceptLanguage, string $en, string $th, string $accountEn = '', string $accountTh = ''): string
    {
        $en = trim($en);
        $th = trim($th);
        $accountEn = trim($accountEn);
        $accountTh = trim($accountTh);
        if ($th !== '' && self::wantsThai($acceptLanguage)) {
            return $th;
        }
        if ($en !== '') {
            return $en;
        }
        if ($accountEn !== '' || $accountTh !== '') {
            return 'Log in with ' . self::accountName($acceptLanguage, $accountEn, $accountTh);
        }
        return $th !== '' ? $th : 'Log in with ' . self::ACCOUNT;
    }

    /** Does this browser ask for Thai before English (Accept-Language, with q values)? */
    public static function wantsThai(string $acceptLanguage): bool
    {
        $wantsThai = false;
        $best = -1.0;
        foreach (explode(',', $acceptLanguage) as $part) {
            $bits = explode(';', trim($part));
            $tag = strtolower(trim($bits[0]));
            $q = 1.0;
            foreach (array_slice($bits, 1) as $b) {
                if (preg_match('/^\s*q=([0-9.]+)/', $b, $m)) {
                    $q = (float) $m[1];
                }
            }
            if ($tag === '' || $q <= $best) {
                continue;
            }
            if (strpos($tag, 'th') === 0) {
                $wantsThai = true;
                $best = $q;
            } elseif (strpos($tag, 'en') === 0 || $tag === '*') {
                $wantsThai = false;
                $best = $q;
            }
        }
        return $wantsThai;
    }

    /**
     * The redirect URI must be https — except on this machine itself (http://localhost,
     * 127.0.0.1, [::1]), which is how a test copy of the site runs.
     */
    public static function redirectUriOk(string $uri): bool
    {
        $scheme = parse_url($uri, PHP_URL_SCHEME);
        $host = parse_url($uri, PHP_URL_HOST);
        if (!$host || parse_url($uri, PHP_URL_PATH) === null) {
            return false;
        }
        if ($scheme === 'https') {
            return true;
        }
        return $scheme === 'http' && in_array(strtolower($host), ['localhost', '127.0.0.1', '[::1]'], true);
    }

    /** A random URL-safe string (state, nonce, PKCE verifier). */
    public static function randomToken(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    /** PKCE S256 challenge for a verifier. */
    public static function pkceChallenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    /**
     * Check discovery metadata: the issuer must be exactly the configured one and every
     * endpoint we use must be https on the same host. Returns '' when good.
     *
     * @param array<string,mixed> $meta
     */
    public static function checkDiscovery(array $meta, string $issuer): string
    {
        if (($meta['issuer'] ?? null) !== $issuer) {
            return 'discovery issuer does not match';
        }
        $host = parse_url($issuer, PHP_URL_HOST);
        if (parse_url($issuer, PHP_URL_SCHEME) !== 'https' || !$host) {
            return 'issuer must be https';
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint'] as $key) {
            $url = $meta[$key] ?? null;
            if (!is_string($url) || parse_url($url, PHP_URL_SCHEME) !== 'https' || parse_url($url, PHP_URL_HOST) !== $host) {
                return $key . ' must be https on the issuer host';
            }
        }
        return '';
    }

    /** One person from the provider's GET /api/users answer (Pocket ID's UserDto). */
    public static function personFromApi(array $u): array
    {
        return [
            'id' => (string) ($u['id'] ?? ''),
            'username' => (string) ($u['username'] ?? ''),
            'email' => strtolower(trim((string) ($u['email'] ?? ''))),
            'emailVerified' => (bool) ($u['emailVerified'] ?? false),
            'name' => trim(((string) ($u['firstName'] ?? '')) . ' ' . ((string) ($u['lastName'] ?? ''))),
            'disabled' => (bool) ($u['disabled'] ?? false),
        ];
    }

    /**
     * A pasted list: one person per line; the word with "@" is the email, the first other
     * word that looks like a username is the username, the rest is the name. Tabs, commas
     * and spaces all separate. A pasted email counts as checked (an administrator typed it).
     */
    public static function parsePasted(string $text): array
    {
        $out = [];
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            $words = preg_split('/[\t,;]+|\s+/u', trim($line)) ?: [];
            $email = '';
            $username = '';
            $name = [];
            foreach ($words as $w) {
                $w = trim($w, " \"'<>");
                if ($w === '') {
                    continue;
                }
                if ($email === '' && strpos($w, '@') !== false && filter_var($w, FILTER_VALIDATE_EMAIL)) {
                    $email = strtolower($w);
                } elseif ($username === '' && preg_match('/^[A-Za-z0-9][A-Za-z0-9_.@-]{0,99}$/', $w) && preg_match('/[a-z0-9]/', $w)) {
                    $username = $w;
                } else {
                    $name[] = $w;
                }
            }
            if ($username !== '' && !in_array(strtolower($username), ['username', 'email', 'name'], true)) {
                $out[] = ['id' => '', 'username' => $username, 'email' => $email, 'emailVerified' => $email !== '',
                    'name' => implode(' ', $name), 'disabled' => false];
            }
        }
        return $out;
    }

    /**
     * Find this Omeka user's account in the provider's list: a verified email that is the
     * same first, then the same name. Returns ['person' => …|null, 'by' => 'email'|'name'|'',
     * 'emailDiffers' => bool].
     */
    public static function matchPerson(array $user, array $people): array
    {
        $email = strtolower(trim((string) ($user['email'] ?? '')));
        $name = self::fold((string) ($user['name'] ?? ''));
        foreach ($people as $p) {
            if ($email !== '' && $p['email'] === $email && $p['emailVerified'] && !$p['disabled']) {
                return ['person' => $p, 'by' => 'email', 'emailDiffers' => false];
            }
        }
        if ($name !== '') {
            foreach ($people as $p) {
                if (!$p['disabled'] && $p['name'] !== '' && self::fold($p['name']) === $name) {
                    return ['person' => $p, 'by' => 'name', 'emailDiffers' => $p['email'] !== $email];
                }
            }
        }
        return ['person' => null, 'by' => '', 'emailDiffers' => false];
    }

    /** the person with this username in the list, or null */
    public static function findUsername(array $people, string $username): ?array
    {
        foreach ($people as $p) {
            if ($p['username'] === $username) {
                return $p;
            }
        }
        return null;
    }

    /**
     * For a linked user: is the link still good? 'ok', 'gone' (that account no longer
     * exists or is disabled), 'renamed' (it exists under another username), or '' when the
     * list has no ids (a pasted list cannot tell).
     */
    public static function checkLinked(array $people, string $subject, string $username): string
    {
        $anyIds = false;
        foreach ($people as $p) {
            if ($p['id'] !== '') {
                $anyIds = true;
                if (hash_equals($p['id'], $subject)) {
                    if ($p['disabled']) {
                        return 'gone';
                    }
                    return $p['username'] === $username ? 'ok' : 'renamed';
                }
            }
        }
        return $anyIds ? 'gone' : '';
    }
}
