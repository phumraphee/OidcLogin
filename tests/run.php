<?php
/* Unit cases for src/Stdlib/Rules.php — no Omeka needed: php tests/run.php */
require __DIR__ . '/../src/Stdlib/Rules.php';
require __DIR__ . '/../src/Stdlib/ProviderLogout.php';
use OidcLogin\Stdlib\ProviderLogout;
use OidcLogin\Stdlib\Rules;

$fail = 0; $n = 0;
function t($name, $got, $want) {
    global $fail, $n; $n++;
    if ($got !== $want) { $fail++; echo "FAIL $name\n  got:  " . var_export($got, true) . "\n  want: " . var_export($want, true) . "\n"; }
}
function jwt(array $claims) {
    $e = fn($a) => rtrim(strtr(base64_encode(json_encode($a)), '+/', '-_'), '=');
    return $e(['alg' => 'RS256']) . '.' . $e($claims) . '.sig';
}

/* parseMap */
t('map basic', Rules::parseMap("jane = 12\n# comment\n\nbob=3\n"), ['jane' => 12, 'bob' => 3]);
t('map keeps dots/case', Rules::parseMap("Sheryl.Gwee = 3\r\njane.do=4"), ['Sheryl.Gwee' => 3, 'jane.do' => 4]);
t('map rejects junk', Rules::parseMap("jane = x\n= 5\njane bob = 6\nzero = 0\nneg = -1"), []);
t('map later line wins', Rules::parseMap("a = 1\na = 2"), ['a' => 2]);

/* parseList */
t('list', Rules::parseList(" admins, staff\nstaff "), ['admins', 'staff']);
t('list empty', Rules::parseList(''), []);

/* safeRedirect */
t('redir path', Rules::safeRedirect('/admin/item?x=1'), '/admin/item?x=1');
t('redir scan', Rules::safeRedirect('/page.html?id=5#p2'), '/page.html?id=5#p2');
t('redir //host', Rules::safeRedirect('//evil.example/x'), '/');
t('redir /\\host', Rules::safeRedirect('/\\evil.example'), '/');
t('redir absolute', Rules::safeRedirect('https://evil.example/'), '/');
t('redir no slash', Rules::safeRedirect('admin'), '/');
t('redir ctrl', Rules::safeRedirect("/a\r\nLocation: x"), '/');
t('redir backslash inside', Rules::safeRedirect('/a\\b'), '/');
t('redir null', Rules::safeRedirect(null, ''), '');
t('redir too long', Rules::safeRedirect('/' . str_repeat('a', 2001)), '/');

/* jwtPayload */
t('jwt ok', Rules::jwtPayload(jwt(['sub' => 'x'])), ['sub' => 'x']);
t('jwt 2 parts', Rules::jwtPayload('a.b'), null);
t('jwt bad json', Rules::jwtPayload('a.' . rtrim(base64_encode('{x'), '=') . '.c'), null);

/* checkIdToken */
$now = 1800000000;
$good = ['iss' => 'https://id.example', 'aud' => 'cid', 'nonce' => 'N', 'exp' => $now + 60, 'sub' => 'S'];
t('idt good', Rules::checkIdToken($good, 'https://id.example', 'cid', 'N', $now), '');
t('idt iss', Rules::checkIdToken(['iss' => 'https://other'] + $good, 'https://id.example', 'cid', 'N', $now), 'issuer does not match');
t('idt aud', Rules::checkIdToken(['aud' => 'x'] + $good, 'https://id.example', 'cid', 'N', $now), 'audience does not match');
t('idt aud array ok', Rules::checkIdToken(['aud' => ['cid', 'x'], 'azp' => 'cid'] + $good, 'https://id.example', 'cid', 'N', $now), '');
t('idt aud array no azp', Rules::checkIdToken(['aud' => ['cid', 'x']] + $good, 'https://id.example', 'cid', 'N', $now), 'authorized party does not match');
t('idt nonce', Rules::checkIdToken(['nonce' => 'M'] + $good, 'https://id.example', 'cid', 'N', $now), 'nonce does not match');
t('idt nonce missing', Rules::checkIdToken(array_diff_key($good, ['nonce' => 1]), 'https://id.example', 'cid', 'N', $now), 'nonce does not match');
t('idt expired', Rules::checkIdToken(['exp' => $now - 121] + $good, 'https://id.example', 'cid', 'N', $now), 'token has expired');
t('idt leeway', Rules::checkIdToken(['exp' => $now - 100] + $good, 'https://id.example', 'cid', 'N', $now), '');
t('idt no sub', Rules::checkIdToken(['sub' => ''] + $good, 'https://id.example', 'cid', 'N', $now), 'no subject');

/* checkInfo */
$info = ['sub' => 'S', 'preferred_username' => 'jane', 'groups' => ['staff'], 'email_verified' => true];
t('info ok', Rules::checkInfo($info, 'S', ['admins', 'staff']), ['jane', '']);
t('info other sub', Rules::checkInfo($info, 'T', []), ['', 'userinfo is about someone else']);
t('info no group', Rules::checkInfo(['groups' => ['guests']] + $info, 'S', ['admins', 'staff']), ['', 'not in an allowed group']);
t('info groups missing', Rules::checkInfo(array_diff_key($info, ['groups' => 1]), 'S', ['staff']), ['', 'not in an allowed group']);
t('info groups not checked', Rules::checkInfo(['groups' => []] + $info, 'S', []), ['jane', '']);
t('info email unverified', Rules::checkInfo(['email_verified' => false] + $info, 'S', []), ['', 'email address is not verified']);
t('info email claim absent', Rules::checkInfo(array_diff_key($info, ['email_verified' => 1]), 'S', []), ['jane', '']);
t('info no username', Rules::checkInfo(array_diff_key($info, ['preferred_username' => 1]), 'S', []), ['', 'no username in the answer']);

/* pickUser */
t('pick linked wins', Rules::pickUser(7, [9]), [7, false, '']);
t('pick waiting links', Rules::pickUser(0, [9]), [9, true, '']);
t('pick waiting dup id', Rules::pickUser(0, [9, 9]), [9, true, '']);
t('pick two waiting', Rules::pickUser(0, [9, 10]), [0, false, 'this username is waiting on more than one user']);
t('pick nobody', Rules::pickUser(0, []), [0, false, 'this account is not linked to a user here']);

/* checkSelfLink */
t('self ok', Rules::checkSelfLink(5, 0, null, 'S'), '');
t('self relink same', Rules::checkSelfLink(5, 5, 'S', 'S'), '');
t('self not signed in', Rules::checkSelfLink(0, 0, null, 'S'), 'not logged in');
t('self owned by other', Rules::checkSelfLink(5, 6, null, 'S'), 'this provider account is already linked to another user');
t('self already other', Rules::checkSelfLink(5, 0, 'OLD', 'S'), 'this user is linked to another provider account — unlink it first');

/* suggest */
$seen = [['username' => 'jane.do', 'name' => 'Jane Doe', 'email' => 'jane@example.org'],
         ['username' => 'sam.ok', 'name' => 'Sam O.', 'email' => 'sam@example.org']];
t('suggest by name', array_key_first(Rules::suggest(['name' => 'Jane Doe', 'email' => 'example1@gmail.com'], $seen)), 'jane.do');
t('suggest by email', Rules::suggest(['name' => 'X', 'email' => 'Sam@example.org'], $seen)['sam.ok'], 100);
t('suggest guess pattern', array_key_exists('priya.na', Rules::suggest(['name' => 'Priya Nair', 'email' => 'example2@gmail.com'], [])), true);
t('suggest guess local', array_key_first(Rules::suggest(['name' => 'Lena Hoffmann', 'email' => 'lena@example.org'], [])), 'lena');
t('suggest gmail prefers name pattern', array_key_first(Rules::suggest(['name' => 'Jane Doe', 'email' => 'example3@gmail.com'], [])), 'jane.do');
t('suggest work mail local first', array_key_first(Rules::suggest(['name' => 'Tomas Silva', 'email' => 'tomas.si@example.org'], [])), 'tomas.si');
t('suggest thai name no dot guess', array_keys(Rules::suggest(['name' => 'สมชาย ใจดี', 'email' => ''], [])), []);

/* buttonLabel */
t('label en default', Rules::buttonLabel('', 'Log in with Pocket ID', 'เข้าด้วย Pocket ID'), 'Log in with Pocket ID');
t('label th first', Rules::buttonLabel('th-TH,th;q=0.9,en;q=0.8', 'EN', 'TH'), 'TH');
t('label en first', Rules::buttonLabel('en-US,en;q=0.9,th;q=0.5', 'EN', 'TH'), 'EN');
t('label th q higher', Rules::buttonLabel('en;q=0.4, th;q=0.8', 'EN', 'TH'), 'TH');
t('label th missing', Rules::buttonLabel('th', 'EN', ''), 'EN');
t('label both empty', Rules::buttonLabel('th', '', ''), 'Log in with OpenID Connect account');
t('label from account en', Rules::buttonLabel('en', '', '', 'Example account', 'บัญชี Example'), 'Log in with Example account');
t('label from account th', Rules::buttonLabel('th,en;q=0.5', '', '', 'Example account', 'บัญชี Example'), 'Log in with บัญชี Example');
t('label th text beats account', Rules::buttonLabel('th', 'EN', 'TH', 'A', 'บ'), 'TH');
t('label en text beats account', Rules::buttonLabel('en', 'EN', 'TH', 'A', 'บ'), 'EN');
t('label th, no th text or name: en text', Rules::buttonLabel('th', 'EN', '', 'A', ''), 'EN');
t('label th, only en name', Rules::buttonLabel('th', '', '', 'A', ''), 'Log in with A');
t('label en, only th name', Rules::buttonLabel('en', '', '', '', 'บ'), 'Log in with บ');
/* accountName */
t('account en', Rules::accountName('en-US', 'Example account', 'บัญชี Example'), 'Example account');
t('account th', Rules::accountName('th-TH,th;q=0.9', 'Example account', 'บัญชี Example'), 'บัญชี Example');
t('account th missing', Rules::accountName('th', 'Example account', ''), 'Example account');
t('account en missing', Rules::accountName('en', '', 'บัญชี Example'), 'บัญชี Example');
t('account none', Rules::accountName('', ' ', ''), 'OpenID Connect account');

/* PKCE: RFC 7636 appendix B */
t('pkce rfc', Rules::pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
t('random urlsafe', (bool) preg_match('/^[A-Za-z0-9_-]{43}$/', Rules::randomToken()), true);

/* redirectUriOk */
t('ru https', Rules::redirectUriOk('https://archive.example/oidc/callback'), true);
t('ru http localhost', Rules::redirectUriOk('http://127.0.0.1:8080/oidc/callback'), true);
t('ru http host', Rules::redirectUriOk('http://archive.example/oidc/callback'), false);
t('ru http localhost.evil', Rules::redirectUriOk('http://localhost.evil.example/x'), false);
t('ru junk', Rules::redirectUriOk('javascript:alert(1)'), false);

/* checkDiscovery */
$meta = ['issuer' => 'https://id.example', 'authorization_endpoint' => 'https://id.example/authorize',
    'token_endpoint' => 'https://id.example/api/oidc/token', 'userinfo_endpoint' => 'https://id.example/api/oidc/userinfo'];
t('disc ok', Rules::checkDiscovery($meta, 'https://id.example'), '');
t('disc issuer', Rules::checkDiscovery($meta, 'https://id.example/'), 'discovery issuer does not match');
t('disc other host', Rules::checkDiscovery(['token_endpoint' => 'https://evil.example/t'] + $meta, 'https://id.example'), 'token_endpoint must be https on the issuer host');
t('disc http', Rules::checkDiscovery(['userinfo_endpoint' => 'http://id.example/u'] + $meta, 'https://id.example'), 'userinfo_endpoint must be https on the issuer host');
t('disc http issuer', Rules::checkDiscovery(['issuer' => 'http://id.example'] + $meta, 'http://id.example'), 'issuer must be https');

/* directory: pasted list, API person, matching */
$pp = Rules::parsePasted("jane.do jane@example.org Jane Doe\nsam.ok, sam@example.org, Sam Okafor\nusername email name\n\nlena\tlena@example.org\tLena Hoffmann");
t('paste 3 people (header skipped)', count($pp), 3);
t('paste fields', [$pp[0]['username'], $pp[0]['email'], $pp[0]['name'], $pp[0]['emailVerified']], ['jane.do', 'jane@example.org', 'Jane Doe', true]);
t('paste tabs', $pp[2]['username'] . ' ' . $pp[2]['email'], 'lena lena@example.org');
$api = Rules::personFromApi(['id' => 'u1', 'username' => 'sam.ok', 'email' => 'Sam@Example.org', 'emailVerified' => true, 'firstName' => 'Sam', 'lastName' => 'Okafor', 'disabled' => false]);
t('api person', [$api['id'], $api['email'], $api['name']], ['u1', 'sam@example.org', 'Sam Okafor']);
$people = [$api, Rules::personFromApi(['id' => 'u2', 'username' => 'jane.do', 'email' => 'jane@example.org', 'emailVerified' => true, 'firstName' => 'Jane', 'lastName' => 'Doe']),
  Rules::personFromApi(['id' => 'u3', 'username' => 'old', 'email' => 'old@example.org', 'emailVerified' => true, 'firstName' => 'Old', 'lastName' => 'One', 'disabled' => true]),
  Rules::personFromApi(['id' => 'u4', 'username' => 'unv', 'email' => 'unv@example.org', 'emailVerified' => false, 'firstName' => 'Un', 'lastName' => 'Verified'])];
$m = Rules::matchPerson(['name' => 'Sam O.', 'email' => 'sam@example.org'], $people);
t('match by verified email', [$m['by'], $m['person']['username']], ['email', 'sam.ok']);
$m = Rules::matchPerson(['name' => 'Jane Doe', 'email' => 'example1@gmail.com'], $people);
t('match by name, email differs', [$m['by'], $m['person']['username'], $m['emailDiffers']], ['name', 'jane.do', true]);
t('no match for unverified email', Rules::matchPerson(['name' => 'X', 'email' => 'unv@example.org'], $people)['person'], null);
t('no match for disabled', Rules::matchPerson(['name' => 'Old One', 'email' => 'old@example.org'], $people)['person'], null);
t('nobody', Rules::matchPerson(['name' => 'Tomas S', 'email' => 'tomas@example.org'], $people)['person'], null);
t('find username', Rules::findUsername($people, 'jane.do')['id'], 'u2');
t('find username missing', Rules::findUsername($people, 'tomas.si'), null);
t('linked ok', Rules::checkLinked($people, 'u1', 'sam.ok'), 'ok');
t('linked renamed', Rules::checkLinked($people, 'u1', 'sam'), 'renamed');
t('linked gone', Rules::checkLinked($people, 'zz', 'x'), 'gone');
t('linked disabled', Rules::checkLinked($people, 'u3', 'old'), 'gone');
t('linked pasted (no ids)', Rules::checkLinked($pp, 'u1', 'sam.ok'), '');

/* ProviderLogout: where Logout sends a provider log-in */
$es = 'https://id.example.org/api/oidc/end-session';
t('logout: end-session with the ID token', ProviderLogout::url('https://id.example.org', $es, 'aa.bb.cc'), $es . '?id_token_hint=aa.bb.cc');
t('logout: never a post_logout_redirect_uri', strpos(ProviderLogout::url('https://id.example.org', $es, 'aa.bb.cc'), 'post_logout') === false, true);
t('logout: no token → the provider\'s /logout', ProviderLogout::url('https://id.example.org/', $es, ''), 'https://id.example.org/logout');
t('logout: no end-session → /logout', ProviderLogout::url('https://id.example.org', '', 'aa.bb.cc'), 'https://id.example.org/logout');
t('logout: end-session on another host → /logout', ProviderLogout::url('https://id.example.org', 'https://evil.example/end', 'aa.bb.cc'), 'https://id.example.org/logout');
t('logout: end-session not https → /logout', ProviderLogout::url('https://id.example.org', 'http://id.example.org/api/oidc/end-session', 'aa.bb.cc'), 'https://id.example.org/logout');
t('logout: a token that is not a JWT → /logout', ProviderLogout::url('https://id.example.org', $es, "a.b.c\r\nX: y"), 'https://id.example.org/logout');
t('logout: end-session with a query keeps it', ProviderLogout::url('https://id.example.org', $es . '?x=1', 'aa.bb.cc'), $es . '?x=1&id_token_hint=aa.bb.cc');
t('logout: no issuer → Omeka\'s own page', ProviderLogout::url('', $es, 'aa.bb.cc'), '');
t('logout: issuer not https → Omeka\'s own page', ProviderLogout::url('http://id.example.org', '', ''), '');
$au = 'https://id.example.org/authorize';
$pu = ProviderLogout::probeUrl('https://id.example.org', $au, 'cid', 'https://omeka.example.org/oidc/callback', 'st', 'ch');
t('probe: prompt=none to our callback', strpos($pu, $au . '?response_type=code&client_id=cid&redirect_uri=https%3A%2F%2Fomeka.example.org%2Foidc%2Fcallback&scope=openid&prompt=none&state=st&code_challenge=ch&code_challenge_method=S256') === 0, true);
t('probe: authorize on another host → none', ProviderLogout::probeUrl('https://id.example.org', 'https://evil.example/authorize', 'cid', 'https://a/cb', 'st', 'ch'), '');
$sealed = ProviderLogout::seal(['state' => 'st', 'end' => 'https://id.example.org/logout', 'at' => 1000], 'k');
t('probe cookie: opens with its key', ProviderLogout::open($sealed, 'k', 1100), ['state' => 'st', 'end' => 'https://id.example.org/logout', 'at' => 1000]);
t('probe cookie: another key → null', ProviderLogout::open($sealed, 'other', 1100), null);
t('probe cookie: changed → null', ProviderLogout::open('x' . $sealed, 'k', 1100), null);
t('probe cookie: older than 10 minutes → null', ProviderLogout::open($sealed, 'k', 1000 + 601), null);
t('probe cookie: no key → null', ProviderLogout::open($sealed, '', 1100), null);
$sb = ProviderLogout::seal(['state' => 'st', 'end' => 'e', 'at' => 1000, 'back' => '/?q=x#y'], 'k');
t('probe cookie: the page to come back to rides along', ProviderLogout::open($sb, 'k', 1100), ['state' => 'st', 'end' => 'e', 'at' => 1000, 'back' => '/?q=x#y']);
$sb2 = ProviderLogout::seal(['state' => 'st', 'end' => 'e', 'at' => 1000, 'back' => '//evil.example/'], 'k');
t('probe cookie: a page on another host is never come back to', ProviderLogout::open($sb2, 'k', 1100), ['state' => 'st', 'end' => 'e', 'at' => 1000]);
t('probe: no client / callback / state → none', [ProviderLogout::probeUrl('https://id.example.org', $au, '', 'https://a/cb', 'st', 'ch'), ProviderLogout::probeUrl('https://id.example.org', $au, 'cid', '', 'st', 'ch'), ProviderLogout::probeUrl('https://id.example.org', $au, 'cid', 'https://a/cb', '', 'ch')], ['', '', '']);

/* 1.1.0: accounts from provider groups */
$known = ['global_admin', 'site_admin', 'editor', 'reviewer', 'author', 'researcher', 'guest'];
t('groups: rows cleaned', Rules::groupRoles([['group' => ' staff ', 'role' => 'editor'], ['group' => 'a b', 'role' => 'editor'], ['group' => 'x', 'role' => 'nobody'], ['group' => '', 'role' => 'author'], ['group' => 'Admins', 'role' => 'global_admin'], 'junk'], $known), ['staff' => 'editor', 'Admins' => 'global_admin']);
t('groups: a later row wins', Rules::groupRoles([['group' => 'g', 'role' => 'author'], ['group' => 'g', 'role' => 'editor']], $known), ['g' => 'editor']);
$map = ['staff' => 'editor', 'readers' => 'researcher', 'boss' => 'global_admin', 'guests' => 'guest'];
t('role: the highest of the groups', Rules::roleFor(['readers', 'staff'], $map), 'editor');
t('role: global_admin only from its own row', Rules::roleFor(['staff', 'other'], $map), 'editor');
t('role: global_admin when mapped', Rules::roleFor(['staff', 'boss'], $map), 'global_admin');
t('role: a module role ranks lowest', Rules::roleFor(['guests', 'readers'], $map), 'researcher');
t('role: no mapped group → null', Rules::roleFor(['other'], $map), null);
t('role: no groups claim → null', Rules::roleFor(null, $map), null);
t('role: group names exact (case)', Rules::roleFor(['Staff'], $map), null);
$info = ['email' => 'jane@example.org', 'email_verified' => true];
t('auto: no role → refuse', Rules::autoAccount(null, $info, 'jane', [])[0], 'refuse');
t('auto: nobody with the email → create', Rules::autoAccount('editor', $info, 'jane', []), ['create', 0, '']);
t('auto: one active user → link', Rules::autoAccount('editor', $info, 'jane', [['id' => 7, 'active' => true, 'subject' => null, 'waiting' => null]]), ['link', 7, '']);
t('auto: waiting for the same username → link', Rules::autoAccount('editor', $info, 'jane', [['id' => 7, 'active' => true, 'subject' => null, 'waiting' => 'jane']]), ['link', 7, '']);
t('auto: two users → refuse', Rules::autoAccount('editor', $info, 'jane', [['id' => 7, 'active' => true, 'subject' => null, 'waiting' => null], ['id' => 8, 'active' => true, 'subject' => null, 'waiting' => null]])[0], 'refuse');
t('auto: deactivated user → refuse (never turned back on)', Rules::autoAccount('editor', $info, 'jane', [['id' => 7, 'active' => false, 'subject' => null, 'waiting' => null]])[0], 'refuse');
t('auto: user linked to another account → refuse', Rules::autoAccount('editor', $info, 'jane', [['id' => 7, 'active' => true, 'subject' => 's-other', 'waiting' => null]])[0], 'refuse');
t('auto: waiting for another username → refuse', Rules::autoAccount('editor', $info, 'jane', [['id' => 7, 'active' => true, 'subject' => null, 'waiting' => 'bob']])[0], 'refuse');
t('auto: email not verified → refuse', Rules::autoAccount('editor', ['email' => 'jane@example.org'], 'jane', [])[0], 'refuse');
t('auto: no email → refuse', Rules::autoAccount('editor', ['email_verified' => true], 'jane', [])[0], 'refuse');
t('name: name claim', Rules::displayName(['name' => ' Jane Doe '], 'jane'), 'Jane Doe');
t('name: given + family', Rules::displayName(['given_name' => 'Jane', 'family_name' => 'Doe'], 'jane'), 'Jane Doe');
t('name: the username at last', Rules::displayName([], 'jane'), 'jane');

echo ($fail ? "FAILED $fail of $n\n" : "ok $n\n");
exit($fail ? 1 : 0);
