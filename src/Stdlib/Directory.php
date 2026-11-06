<?php
namespace OidcLogin\Stdlib;

use Doctrine\DBAL\Connection;
use Laminas\Http\Client as HttpClient;

/**
 * WHO REALLY HAS AN ACCOUNT AT THE PROVIDER — FOR THE ADMIN PAGE ONLY.
 *
 * Two sources, so the page can check names against the real list:
 *   api    — an API key in local.config.php ('oidclogin' => ['api_key' => …]) and the
 *            provider's GET /api/users (Pocket ID). ⚠ In Pocket ID 2.19 an API key carries
 *            every right of the admin who made it (there is no read-only key), so keep it
 *            out of reach (file permissions) or use the pasted list instead.
 *   pasted — a list an administrator pastes on the page: one person per line, "username
 *            email First Last" in any order of email/username (no secret at all).
 * The answer is kept 5 minutes. Log-in itself never calls any of this, so a provider that
 * is down or a wrong key cannot stop anybody logging in.
 */
class Directory
{
    const CACHE = 'oidclogin_directory_cache';
    const PASTE = 'oidclogin_directory_paste';
    const TTL = 300;

    protected $db;
    protected $http;
    protected $issuer;
    protected $apiKey;

    public function __construct(Connection $db, HttpClient $http, string $issuer, string $apiKey)
    {
        $this->db = $db;
        $this->http = $http;
        $this->issuer = rtrim($issuer, '/');
        $this->apiKey = $apiKey;
    }

    public function source(): string
    {
        if ($this->apiKey !== '' && $this->issuer !== '') {
            return 'api';
        }
        return trim($this->setting(self::PASTE, '')) !== '' ? 'pasted' : 'none';
    }

    /**
     * @return array{ok:bool, source:string, at:int, error:string,
     *   people:array<int,array{id:string,username:string,email:string,emailVerified:bool,name:string,disabled:bool}>}
     */
    public function people(bool $refresh = false): array
    {
        $source = $this->source();
        if ($source === 'none') {
            return ['ok' => false, 'source' => 'none', 'at' => 0, 'error' => 'no list', 'people' => []];
        }
        if ($source === 'pasted') {
            return ['ok' => true, 'source' => 'pasted', 'at' => (int) $this->setting(self::PASTE . '_at', 0),
                'error' => '', 'people' => Rules::parsePasted($this->setting(self::PASTE, ''))];
        }
        $cache = $this->setting(self::CACHE, null);
        if (!$refresh && is_array($cache) && (time() - (int) ($cache['at'] ?? 0)) < self::TTL && isset($cache['people'])) {
            return ['ok' => true, 'source' => 'api', 'at' => (int) $cache['at'], 'error' => '', 'people' => $cache['people']];
        }
        try {
            $people = [];
            for ($page = 1; $page <= 20; $page++) {
                $http = clone $this->http;
                $http->reset();
                $http->setUri($this->issuer . '/api/users')->setMethod('GET')->setOptions(['timeout' => 3]);
                $http->setParameterGet(['pagination' => ['page' => $page, 'limit' => 100]]);
                $http->setHeaders(['X-API-Key' => $this->apiKey, 'Accept' => 'application/json']);
                $response = $http->send();
                if (!$response->isSuccess()) {
                    throw new \RuntimeException('the provider answered ' . $response->getStatusCode());
                }
                $data = json_decode($response->getBody(), true);
                if (!is_array($data) || !isset($data['data']) || !is_array($data['data'])) {
                    throw new \RuntimeException('the provider did not answer a user list');
                }
                foreach ($data['data'] as $u) {
                    $people[] = Rules::personFromApi((array) $u);
                }
                $pages = (int) ($data['pagination']['totalPages'] ?? 1);
                if ($page >= $pages || !$data['data']) {
                    break;
                }
            }
            $this->putSetting(self::CACHE, ['at' => time(), 'people' => $people]);
            return ['ok' => true, 'source' => 'api', 'at' => time(), 'error' => '', 'people' => $people];
        } catch (\Throwable $e) {
            return ['ok' => false, 'source' => 'api', 'at' => 0, 'error' => $e->getMessage(), 'people' => []];
        }
    }

    /**
     * Is "Enable self-account editing" off at the provider (Pocket ID)? Asked only with an API
     * key: true = off (safe to match by email), false = on, null = could not tell. Pocket ID
     * lists its settings as [{key, type, value}] at /api/application-configuration/all.
     */
    public function selfEditOff(): ?bool
    {
        if ($this->apiKey === '' || $this->issuer === '') {
            return null;
        }
        try {
            $http = clone $this->http;
            $http->reset();
            $http->setUri($this->issuer . '/api/application-configuration/all')->setMethod('GET')->setOptions(['timeout' => 3]);
            $http->setHeaders(['X-API-Key' => $this->apiKey, 'Accept' => 'application/json']);
            $response = $http->send();
            $data = $response->isSuccess() ? json_decode($response->getBody(), true) : null;
            foreach (is_array($data) ? $data : [] as $row) {
                if (is_array($row) && ($row['key'] ?? '') === 'allowOwnAccountEdit') {
                    $v = strtolower((string) ($row['value'] ?? ''));
                    return $v === 'false' ? true : ($v === 'true' ? false : null);
                }
            }
        } catch (\Throwable $e) {
        }
        return null;
    }

    public function pasteText(): string
    {
        return (string) $this->setting(self::PASTE, '');
    }

    public function savePaste(string $text): void
    {
        $this->putSetting(self::PASTE, mb_substr($text, 0, 100000));
        $this->putSetting(self::PASTE . '_at', time());
    }

    protected function setting(string $id, $default)
    {
        $v = $this->db->fetchOne('SELECT value FROM setting WHERE id = ?', [$id]);
        return $v === false ? $default : json_decode((string) $v, true);
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
