<?php
namespace OidcLogin\Stdlib;

/**
 * Where a person who logged in with the provider goes after Omeka's Logout: Omeka's own
 * session is ended first, always; then the browser goes to the provider, so a shared
 * computer does not keep the provider's log-in either. Only this
 * app is left: other apps keep their own sessions until they end by themselves.
 *
 * With the ID token of this log-in and the provider's end_session_endpoint, the provider is
 * told which log-in this was (id_token_hint: it ends this app's tokens there) and, with no
 * Logout Callback URL registered for the client, shows its own "log out?" page. Without
 * them: the provider's /logout page itself (Pocket ID). Pocket ID 2.19.3 and later end the
 * browser's log-in there at once (no "log out?" question any more; its /logout page then only
 * shows its sign-in), so the request also carries post_logout_redirect_uri = our callback
 * (withReturn): with that URL among the client's Logout Callback URLs the person comes back
 * to the app, already logged out of the provider too.
 *
 * Plain PHP (tests/run.php).
 */
class ProviderLogout
{
    /** The provider's URL to send the browser to, or '' (then Omeka's own login page). */
    public static function url(string $issuer, string $endSession, string $idToken): string
    {
        $issuer = rtrim(trim($issuer), '/');
        if (!self::https($issuer)) {
            return '';
        }
        // the end-session endpoint only on the issuer's own host (never somewhere else)
        if ($idToken !== '' && self::https($endSession) && self::host($endSession) === self::host($issuer)
            && preg_match('/^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$/', $idToken)) {
            return $endSession . (strpos($endSession, '?') === false ? '?' : '&') . 'id_token_hint=' . rawurlencode($idToken);
        }
        return $issuer . '/logout';
    }

    /**
     * The end-session URL with the way back: post_logout_redirect_uri (our callback) and state.
     * Only for the end-session endpoint (it carries id_token_hint); the provider's plain /logout
     * page, or a callback that is not https (http on localhost for tests), stays as it is.
     */
    public static function withReturn(string $end, string $redirectUri, string $state): string
    {
        if ($end === '' || strpos($end, 'id_token_hint=') === false || $state === ''
            || !preg_match('~^(https://[^/\s?#]+|http://(localhost|127\.0\.0\.1)(:\d+)?)(/\S*)?$~i', $redirectUri)) {
            return $end;
        }
        return $end . '&' . http_build_query(['post_logout_redirect_uri' => $redirectUri, 'state' => $state], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * The question asked first (otherwise Logout ends on the provider's sign-in page
     * when its own log-in has already ended): an authorization request with prompt=none, which
     * the provider answers at once, back to our callback — a code when this browser still has a
     * log-in there, login_required when not. No page, no CORS, nothing from the server. The
     * authorization endpoint only on the issuer's own host; '' when it cannot be asked.
     */
    public static function probeUrl(string $issuer, string $authEndpoint, string $clientId, string $redirectUri, string $state, string $challenge): string
    {
        $issuer = rtrim(trim($issuer), '/');
        if (!self::https($issuer) || !self::https($authEndpoint) || self::host($authEndpoint) !== self::host($issuer)
            || $clientId === '' || $redirectUri === '' || $state === '' || $challenge === '') {
            return '';
        }
        return $authEndpoint . (strpos($authEndpoint, '?') === false ? '?' : '&') . http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => 'openid',
            'prompt' => 'none',
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /** The cookie that carries the question across Omeka's ended session (none is left after Logout). */
    const COOKIE = 'oidclogin_bye';

    /** state, where to go on and when, signed (HMAC-SHA256 with the client secret): a cookie value.
     *  `back` (optional): the page of this site to return to when the provider has no log-in left
     *  to end (e.g. a public page's Log out) — a path, Rules::safeRedirect. */
    public static function seal(array $probe, string $key): string
    {
        $d = ['s' => (string) ($probe['state'] ?? ''), 'e' => (string) ($probe['end'] ?? ''), 't' => (int) ($probe['at'] ?? 0)];
        if ((string) ($probe['back'] ?? '') !== '') {
            $d['b'] = (string) $probe['back'];
        }
        $body = rtrim(strtr(base64_encode(json_encode($d)), '+/', '-_'), '=');
        return $body . '.' . hash_hmac('sha256', $body, $key);
    }

    /** The probe from its cookie when the signature is right and it is at most $ttl seconds old, else null. */
    public static function open(string $value, string $key, int $now, int $ttl = 600): ?array
    {
        if ($key === '' || !preg_match('/^([A-Za-z0-9_\-]+)\.([0-9a-f]{64})$/', $value, $m) || !hash_equals(hash_hmac('sha256', $m[1], $key), $m[2])) {
            return null;
        }
        $d = json_decode((string) base64_decode(strtr($m[1], '-_', '+/')), true);
        if (!is_array($d) || !is_string($d['s'] ?? null) || $d['s'] === '' || !is_int($d['t'] ?? null) || $now - $d['t'] > $ttl || $d['t'] > $now + 60) {
            return null;
        }
        $out = ['state' => $d['s'], 'end' => (string) ($d['e'] ?? ''), 'at' => $d['t']];
        $back = Rules::safeRedirect(is_string($d['b'] ?? null) ? $d['b'] : null, '');
        if ($back !== '') {
            $out['back'] = $back;
        }
        return $out;
    }

    private static function https(string $url): bool
    {
        return (bool) preg_match('~^https://[^/\s?#]+(/\S*)?$~i', $url);
    }

    private static function host(string $url): string
    {
        return strtolower((string) parse_url($url, PHP_URL_HOST));
    }
}
