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
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Uri\Uri;

final class BlockAccess extends CMSPlugin
{
    protected $autoloadLanguage = true;

    private const BA_THROW_TTL = 30; // Sekunden

    private string $securedArea = '';
    private bool $correctKey = false;
    private ?Uri $currentUri = null;
    private ?Uri $redirectUri = null;

    /* ---------------------------------------------------------------------
     * Logout: NACH erfolgreichem Backend-Logout ins Frontend
     * ------------------------------------------------------------------- */
    public function onUserAfterLogout($user, $options = []): void
    {
        $app = Factory::getApplication();

        if (!$app->isClient('administrator'))
        {
            return;
        }

        $app->redirect(Uri::root(), 303);
        $app->close();
    }

    /* ---------------------------------------------------------------------
     * Hauptlogik
     * ------------------------------------------------------------------- */
    public function onAfterInitialise(): void
    {
        $app     = Factory::getApplication();
        $session = Factory::getSession();
        $input   = $app->getInput();

        /* -------------------------------------------------------------
         * 1) Admin-Logout: niemals blockieren
         * ----------------------------------------------------------- */
        if ($app->isClient('administrator'))
        {
            $option = (string) $input->getCmd('option', '');
            $task   = (string) $input->getCmd('task', '');

            $this->debugLog($app, $option, $task);

            if ($option === 'com_login' && $task === 'logout')
            {
                $session->clear('block_access');
                return;
            }
        }

        /* -------------------------------------------------------------
         * 2) Frontend: ba_throw validieren und ggf. Exception werfen
         * ----------------------------------------------------------- */
        if ($app->isClient('site'))
        {
            $this->handleFrontendThrow($input);
        }

        /* -------------------------------------------------------------
         * 3) Plugin nicht aktiv oder bereits freigeschaltet
         * ----------------------------------------------------------- */
        $generalKey = (string) $this->params->get('securitykey', '');

        if ($generalKey === '' || (bool) $session->get('block_access', false))
        {
            return;
        }

        /* -------------------------------------------------------------
         * 4) Kontext bestimmen
         * ----------------------------------------------------------- */
        $this->currentUri  = Uri::getInstance();
        $this->securedArea = strtolower((string) $this->params->get('area', 'all'));

        if ($app->isClient('site'))
        {
            $area = 'site';
            $frontendKey = (string) $this->params->get('securitykeyFrontend', '');
            $keyName = $frontendKey !== '' ? $frontendKey : $generalKey;
            $this->correctKey = $input->get($keyName) !== null;
        }
        else
        {
            $area = 'admin';
            $this->correctKey = $input->get($generalKey) !== null;
        }

        /* -------------------------------------------------------------
         * 5) Falscher Bereich → nichts tun
         * ----------------------------------------------------------- */
        if ($this->securedArea !== 'all' && $area !== $this->securedArea)
        {
            return;
        }

        /* -------------------------------------------------------------
         * 6) Key korrekt → Session freischalten
         * ----------------------------------------------------------- */
        if ($this->correctKey)
        {
            $session->set('block_access', true);
            return;
        }

        /* -------------------------------------------------------------
         * 7) Blockieren
         * ----------------------------------------------------------- */
        $this->setRedirectUri();
        $this->blockArea($area);
    }

    /* ---------------------------------------------------------------------
     * Frontend ba_throw
     * ------------------------------------------------------------------- */
    private function handleFrontendThrow($input): void
    {
        if ((int) $input->getInt('ba_throw', 0) !== 1)
        {
            return;
        }

        $msg   = (string) $input->getString('ba_msg', (string) $this->params->get('message', 'Unauthorized'));
        $code  = (int) $input->getInt('ba_code', 401);
        $ts    = (int) $input->getInt('ba_ts', 0);
        $nonce = (string) $input->getString('ba_n', '');
        $sig   = (string) $input->getString('ba_sig', '');

        if ($ts <= 0 || $nonce === '' || $sig === '')
        {
            return;
        }

        if (abs(time() - $ts) > self::BA_THROW_TTL)
        {
            return;
        }

        $secret  = (string) Factory::getConfig()->get('secret');
        $payload = $code . '|' . $msg . '|' . $ts . '|' . $nonce;
        $expected = hash_hmac('sha256', $payload, $secret);

        if (!hash_equals($expected, $sig))
        {
            return;
        }

        throw new \Exception($msg, $code);
    }

    /* ---------------------------------------------------------------------
     * Blockieren
     * ------------------------------------------------------------------- */
    private function blockArea(string $area): void
    {
        $app  = Factory::getApplication();
        $type = (string) $this->params->get('typeOfBlock', 'redirect');

        if (!$this->redirectUri instanceof Uri)
        {
            return;
        }

        if ($this->currentUri && $this->currentUri->toString() === $this->redirectUri->toString())
        {
            return;
        }

        if ($type !== 'message')
        {
            $app->redirect($this->redirectUri->toString(), 303);
            return;
        }

        if ($app->isClient('site'))
        {
            throw new \Exception(
                (string) $this->params->get('message', 'Unauthorized'),
                401
            );
        }

        $this->redirectWithThrow();
    }

    /* ---------------------------------------------------------------------
     * Admin → Frontend Redirect mit ba_throw
     * ------------------------------------------------------------------- */
    private function redirectWithThrow(): void
    {
        $app = Factory::getApplication();

        $msg   = (string) $this->params->get('message', 'Unauthorized');
        $code  = 401;
        $ts    = time();
        $nonce = bin2hex(random_bytes(16));

        $secret  = (string) Factory::getConfig()->get('secret');
        $payload = $code . '|' . $msg . '|' . $ts . '|' . $nonce;
        $sig     = hash_hmac('sha256', $payload, $secret);

        $target = $this->redirectUri->toString();
        $sep    = str_contains($target, '?') ? '&' : '?';

        $target .= $sep
            . 'ba_throw=1'
            . '&ba_code=' . $code
            . '&ba_msg=' . rawurlencode($msg)
            . '&ba_ts=' . $ts
            . '&ba_n=' . $nonce
            . '&ba_sig=' . $sig;

        $app->redirect($target, 303);
    }

    /* ---------------------------------------------------------------------
     * Redirect-URL bestimmen
     * ------------------------------------------------------------------- */
    private function setRedirectUri(): void
    {
        $redirect = trim((string) $this->params->get('redirectUrl', ''));

        if ($redirect !== '' && preg_match('#^https?://#', $redirect))
        {
            $this->redirectUri = Uri::getInstance($redirect);
            return;
        }

        if ($redirect !== '' && str_starts_with($redirect, '/'))
        {
            $this->redirectUri = Uri::getInstance(Uri::root() . ltrim($redirect, '/'));
            return;
        }

        $this->redirectUri = Uri::getInstance(Uri::root());
    }

    /* ---------------------------------------------------------------------
     * Debug-Logging (optional)
     * ------------------------------------------------------------------- */
    private function debugLog($app, string $option, string $task): void
    {

        if (!$this->params->get('debug', 0))
        {
            return;
        }
        
        $line = date('Y-m-d H:i:s')
            . ' client=' . ($app->isClient('administrator') ? 'admin' : 'site')
            . ' uri=' . Uri::getInstance()->toString()
            . ' option=' . $option
            . ' task=' . $task
            . PHP_EOL;

        file_put_contents(__DIR__ . '/task.log', $line, FILE_APPEND | LOCK_EX);
    }
}
