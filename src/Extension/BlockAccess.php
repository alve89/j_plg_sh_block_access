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

/**
 * System plugin to block access to site/admin unless a URL key is provided once per session.
 *
 * The "securitykey" (and optional "securitykeyFrontend") parameters define the **URL parameter name**
 * that must be present, e.g. /administrator/?MY_SECRET_KEY
 */
final class BlockAccess extends CMSPlugin
{
    /**
     * Load the language file on instantiation.
     *
     * @var bool
     */
    protected $autoloadLanguage = true;

    private string $securedArea = '';
    private bool $correctKey = false;
    private ?Uri $currentUri = null;
    private ?Uri $redirectUri = null;

    /**
     * Event: After initialise
     */
    public function onAfterInitialise(): void
    {
        $app = $this->getApplication();

        // If plugin is not configured, or the user already provided the correct key in this session, do nothing.
        $session = Factory::getSession();

        $generalKeyParamName = (string) $this->params->get('securitykey', '');

        if ($generalKeyParamName === '' || $session->get('block_access', false))
        {
            return;
        }

        $this->currentUri = Uri::getInstance();

        $this->securedArea = strtolower((string) $this->params->get('area', 'all'));

        $input = $app->getInput();

        // Determine current client and which key param name to check
        if ($app->isClient('site'))
        {
            $area = 'site';

            $frontendKeyParamName = (string) $this->params->get('securitykeyFrontend', '');

            if ($frontendKeyParamName !== '')
            {
                $this->correctKey = $input->get($frontendKeyParamName, null) !== null;
            }
            else
            {
                $this->correctKey = $input->get($generalKeyParamName, null) !== null;
            }
        }
        elseif ($app->isClient('administrator'))
        {
            $area = 'admin';
            $this->correctKey = $input->get($generalKeyParamName, null) !== null;
        }
        else
        {
            $area = 'all';
            $this->correctKey = $input->get($generalKeyParamName, null) !== null;
        }

        // Only act if this area should be secured
        if ($area !== $this->securedArea && $this->securedArea !== 'all')
        {
            return;
        }

        // If correct key provided, remember it for the session and allow access
        if ($this->correctKey)
        {
            $session->set('block_access', true);

            return;
        }

        // Otherwise block access
        $this->setRedirectUri();
        $this->blockArea();
    }

    private function blockArea(): void
    {
        $type = (string) $this->params->get('typeOfBlock', 'redirect');

        if ($type === 'message')
        {
            throw new \Exception((string) $this->params->get('message', 'Unauthorized'), 401);

        }

        // Default: redirect
        if ($this->redirectUri instanceof Uri)
        {
            // Avoid redirect loops
            if ($this->currentUri instanceof Uri && $this->currentUri->toString() === $this->redirectUri->toString())
            {
                return;
            }

            $app->redirect($this->redirectUri->toString(), 401);
        }
    }

    private function setRedirectUri(): void
    {
        $redirect = trim((string) $this->params->get('redirectUrl', ''));

        // If a valid absolute URL was set, use it
        if (str_starts_with($redirect, 'http://') || str_starts_with($redirect, 'https://'))
        {
            $this->redirectUri = Uri::getInstance($redirect);

            return;
        }

        // If a relative path was set, use it (relative to Joomla root)
        if ($redirect !== '' && str_starts_with($redirect, '/'))
        {
            $this->redirectUri = Uri::getInstance(Uri::root() . ltrim($redirect, '/'));

            return;
        }

        // Otherwise use Joomla root
        $this->redirectUri = Uri::getInstance(Uri::root());
    }
}
