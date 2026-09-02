<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  System.block_access
 *
 * @copyright   (c) 2017-2026 Stefan Herzog
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

declare(strict_types=1);

namespace Joomla\Plugin\System\BlockAccess\Extension;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Ip\IpHelper;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Uri\Uri;
use Joomla\Event\EventInterface;
use Joomla\Event\SubscriberInterface;

final class BlockAccess extends CMSPlugin implements SubscriberInterface
{
    /**
     * Load the plugin language automatically.
     *
     * @var bool
     */
    protected $autoloadLanguage = true;

    /**
     * Maximum age of a signed admin-to-site error hand-off.
     */
    private const BA_THROW_TTL = 30;

    /**
     * Namespaced session key used to remember successful access.
     *
     * The stored value is a SHA-256 digest of the effective key that unlocked access.
     * Changing the configured key therefore invalidates previously authorised
     * sessions automatically.
     */
    private const SESSION_KEY = 'plg_system_block_access.access_hash';

    /**
     * Session key used by plugin versions prior to 2.1.1.
     */
    private const LEGACY_SESSION_KEY = 'block_access';

    /** @var string */
    private $securedArea = '';

    /** @var Uri|null */
    private $currentUri;

    /** @var Uri|null */
    private $redirectUri;

    /**
     * Register proper event listeners. This avoids Joomla's legacy listener
     * argument unwrapping and works on Joomla 4, 5 and 6.
     *
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            'onAfterInitialise' => 'onAfterInitialise',
            'onUserAfterLogout' => 'onUserAfterLogout',
        ];
    }

    /**
     * Redirect to the frontend after a successful administrator logout - but only
     * when the administrator area is actually protected by this plugin. This must
     * not touch the state set up in onAfterInitialise(), because by the time a
     * logout happens the visitor's onAfterInitialise() call already took the
     * early-return "already unlocked" path and never populated $this->securedArea.
     */
    public function onUserAfterLogout(EventInterface $event): void
    {
        $app = Factory::getApplication();

        if (!$app->isClient('administrator')) {
            return;
        }

        $generalKey = trim((string) $this->params->get('securitykey', ''));
        $area       = strtolower((string) $this->params->get('area', 'admin'));

        if ($generalKey === '' || ($area !== 'admin' && $area !== 'all')) {
            return;
        }

        $app->redirect(Uri::root(), 303);
        $app->close();
    }

    /**
     * Apply access protection after Joomla has initialised.
     */
    public function onAfterInitialise(EventInterface $event): void
    {
        $app = Factory::getApplication();

        if ($app->isClient('api') && (bool) $this->params->get('blockApi', 0)) {
            $this->guardApi();

            return;
        }

        // This plugin protects only the normal site and administrator clients.
        // Do not interfere with CLI, API or other Joomla application clients.
        if (!$app->isClient('site') && !$app->isClient('administrator')) {
            return;
        }

        $session = $app->getSession();
        $input   = $app->getInput();

        // Administrator logout must remain reachable even when the backend is protected.
        if ($app->isClient('administrator')) {
            $option = (string) $input->getCmd('option', '');
            $task   = (string) $input->getCmd('task', '');

            if ($option === 'com_login' && $task === 'logout') {
                $session->clear(self::SESSION_KEY);
                $session->clear(self::LEGACY_SESSION_KEY);
                return;
            }
        }

        // Validate a signed administrator -> site error hand-off before applying
        // the site's normal access check.
        if ($app->isClient('site')) {
            $this->handleFrontendThrow($input);
        }

        // Always-allowed IP addresses / CIDR ranges bypass this plugin entirely.
        if ($this->isAllowedIp($this->getClientIp())) {
            return;
        }

        $generalKey = trim((string) $this->params->get('securitykey', ''));

        if ($generalKey === '') {
            return;
        }

        $this->currentUri  = Uri::getInstance();
        $this->securedArea = strtolower((string) $this->params->get('area', 'admin'));

        if ($app->isClient('site')) {
            $area        = 'site';
            $frontendKey = trim((string) $this->params->get('securitykeyFrontend', ''));
            $keyName     = $frontendKey !== '' ? $frontendKey : $generalKey;
        } else {
            $area    = 'admin';
            $keyName = $generalKey;
        }

        if ($this->securedArea !== 'all' && $area !== $this->securedArea) {
            return;
        }

        if ($this->hasSessionAccess($session, $keyName)) {
            return;
        }

        // The secret is intentionally used as the GET/POST parameter name, e.g. ?mySecret.
        // Only GET and POST are consulted (never the generic request bag), so that a
        // cookie of the same name cannot be used to unlock access.
        if ($input->get->get($keyName, null, 'raw') !== null || $input->post->get($keyName, null, 'raw') !== null) {
            $this->grantSessionAccess($session, $keyName);
            return;
        }

        $this->setRedirectUri();
        $this->blockArea();
    }

    /**
     * Blocks a request made against the Joomla Web Services API. There is no
     * per-area distinction here: the API is either fully covered or not at all,
     * since a "site" vs "admin" split does not map onto API endpoints.
     */
    private function guardApi(): void
    {
        $app = Factory::getApplication();

        if ($this->isAllowedIp($this->getClientIp())) {
            return;
        }

        $generalKey = trim((string) $this->params->get('securitykey', ''));

        if ($generalKey === '') {
            return;
        }

        $input = $app->getInput();

        if ($input->get->get($generalKey, null, 'raw') !== null || $input->post->get($generalKey, null, 'raw') !== null) {
            return;
        }

        $app->setHeader('status', 403, true);
        $app->sendHeaders();

        echo json_encode([
            'errors' => [
                [
                    'title' => (string) $this->params->get('message', '401 Unauthorized'),
                    'code'  => 403,
                ],
            ],
        ]);

        $app->close();
    }

    /**
     * Checks whether this session has already been authorised for the given key.
     */
    private function hasSessionAccess($session, string $keyName): bool
    {
        $expectedHash = hash('sha256', $keyName);
        $storedHash   = (string) $session->get(self::SESSION_KEY, '');

        if ($storedHash !== '' && hash_equals($expectedHash, $storedHash)) {
            return true;
        }

        // Seamlessly migrate an already authorised session from versions < 2.1.1.
        if ((bool) $session->get(self::LEGACY_SESSION_KEY, false)) {
            $session->set(self::SESSION_KEY, $expectedHash);
            $session->set(self::LEGACY_SESSION_KEY, false);

            return true;
        }

        return false;
    }

    /**
     * Grants access for the current session.
     */
    private function grantSessionAccess($session, string $keyName): void
    {
        $session->set(self::SESSION_KEY, hash('sha256', $keyName));
        $session->set(self::LEGACY_SESSION_KEY, false);
    }

    /**
     * Validate the short-lived signed hand-off used for administrator 401 pages.
     *
     * @param object $input Joomla input object (Joomla\\Input\\Input on current releases)
     */
    private function handleFrontendThrow($input): void
    {
        if ((int) $input->getInt('ba_throw', 0) !== 1) {
            return;
        }

        $msg   = (string) $input->getString('ba_msg', (string) $this->params->get('message', 'Unauthorized'));
        $code  = (int) $input->getInt('ba_code', 401);
        $ts    = (int) $input->getInt('ba_ts', 0);
        $nonce = (string) $input->getString('ba_n', '');
        $sig   = (string) $input->getString('ba_sig', '');

        if ($ts <= 0 || $nonce === '' || $sig === '') {
            return;
        }

        if (abs(time() - $ts) > self::BA_THROW_TTL) {
            return;
        }

        $app      = Factory::getApplication();
        $secret   = (string) $app->getConfig()->get('secret', '');
        $payload  = $code . '|' . $msg . '|' . $ts . '|' . $nonce;
        $expected = hash_hmac('sha256', $payload, $secret);

        if (!hash_equals($expected, $sig)) {
            return;
        }

        throw new \RuntimeException($msg, $code);
    }

    /**
     * Block the current request either by redirect or by a 401 exception.
     */
    private function blockArea(): void
    {
        $app  = Factory::getApplication();
        $type = (string) $this->params->get('typeOfBlock', 'redirect');

        if (!$this->redirectUri instanceof Uri) {
            return;
        }

        // In redirect mode, if the configured redirect target is itself the current
        // page - most commonly because redirectUrl was left empty and therefore
        // defaults to the site root - redirecting again would either loop forever
        // or, if silently skipped, leave that one page (typically the homepage)
        // completely unprotected. Neither is acceptable, so this request falls back
        // to a plain 401 instead, exactly like "message" mode does.
        $loopingRedirect = $type !== 'message'
            && $this->currentUri instanceof Uri
            && $this->currentUri->toString() === $this->redirectUri->toString();

        if ($type === 'message' || $loopingRedirect) {
            if ($app->isClient('site')) {
                throw new \RuntimeException(
                    (string) $this->params->get('message', '401 Unauthorized'),
                    401
                );
            }

            // Render the error via the frontend instead of an administrator template.
            $this->redirectWithThrow();
            return;
        }

        $app->redirect($this->redirectUri->toString(), 303);
        $app->close();
    }

    /**
     * Redirect an administrator 401 to the site application using a short-lived,
     * HMAC-signed query string. The site listener validates it before throwing.
     */
    private function redirectWithThrow(): void
    {
        $app = Factory::getApplication();

        $msg   = (string) $this->params->get('message', '401 Unauthorized');
        $code  = 401;
        $ts    = time();
        $nonce = bin2hex(random_bytes(16));

        $secret  = (string) $app->getConfig()->get('secret', '');
        $payload = $code . '|' . $msg . '|' . $ts . '|' . $nonce;
        $sig     = hash_hmac('sha256', $payload, $secret);

        $target = $this->redirectUri->toString();
        $sep    = strpos($target, '?') !== false ? '&' : '?';

        $target .= $sep
            . 'ba_throw=1'
            . '&ba_code=' . $code
            . '&ba_msg=' . rawurlencode($msg)
            . '&ba_ts=' . $ts
            . '&ba_n=' . rawurlencode($nonce)
            . '&ba_sig=' . rawurlencode($sig);

        $app->redirect($target, 303);
        $app->close();
    }

    /**
     * Determine the redirect URL from the plugin configuration.
     */
    private function setRedirectUri(): void
    {
        $redirect = trim((string) $this->params->get('redirectUrl', ''));

        if ($redirect !== '' && preg_match('#^https?://#i', $redirect)) {
            $this->redirectUri = Uri::getInstance($redirect);
            return;
        }

        if ($redirect !== '' && substr($redirect, 0, 1) === '/') {
            $this->redirectUri = Uri::getInstance(Uri::root() . ltrim($redirect, '/'));
            return;
        }

        $this->redirectUri = Uri::getInstance(Uri::root());
    }

    /**
     * Returns the client's IP address, honouring Joomla's trusted-proxy configuration.
     */
    private function getClientIp(): string
    {
        if (class_exists(IpHelper::class)) {
            return (string) IpHelper::getIp();
        }

        return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    }

    /**
     * Checks whether the given IP address is covered by the configured allow list.
     */
    private function isAllowedIp(string $ip): bool
    {
        if ($ip === '') {
            return false;
        }

        $list = trim((string) $this->params->get('allowedIPs', ''));

        if ($list === '') {
            return false;
        }

        foreach (preg_split('/[\r\n,]+/', $list, -1, PREG_SPLIT_NO_EMPTY) as $entry) {
            if ($this->ipMatches($ip, trim($entry))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks whether an IP address matches a single allow-list entry (exact address or CIDR range).
     */
    private function ipMatches(string $ip, string $pattern): bool
    {
        if ($pattern === '') {
            return false;
        }

        if (strpos($pattern, '/') === false) {
            return strcasecmp($ip, $pattern) === 0;
        }

        [$subnet, $prefix] = explode('/', $pattern, 2);

        $ipBin     = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $prefix = (int) $prefix;
        $bytes  = intdiv($prefix, 8);
        $bits   = $prefix % 8;

        if ($bytes > 0 && strncmp($ipBin, $subnetBin, $bytes) !== 0) {
            return false;
        }

        if ($bits === 0) {
            return true;
        }

        $mask = chr((0xFF << (8 - $bits)) & 0xFF);

        return (ord($ipBin[$bytes]) & ord($mask)) === (ord($subnetBin[$bytes]) & ord($mask));
    }
}
