<?php
/**
 * Installer script for System - Block Access.
 *
 * Kept deliberately simple so it remains usable across Joomla 4, 5 and 6.
 */

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;

/**
 * Joomla derives the legacy installer class name from the plugin element
 * (`block_access`), hence this exact class name. Joomla 4/5/6 still support
 * this installer-script form and it lets one package span the three majors.
 */
class block_accessInstallerScript
{
    /**
     * Show a direct management link after installation/update.
     *
     * @param string $type
     * @param object $parent Installer adapter
     */
    public function postflight($type, $parent): bool
    {
        if ($type === 'uninstall') {
            return true;
        }

        $app = Factory::getApplication();

        try {
            $db = $parent->getDatabase();

            $query = $db->getQuery(true)
                ->select($db->quoteName('extension_id'))
                ->from($db->quoteName('#__extensions'))
                ->where($db->quoteName('type') . ' = ' . $db->quote('plugin'))
                ->where($db->quoteName('folder') . ' = ' . $db->quote('system'))
                ->where($db->quoteName('element') . ' = ' . $db->quote('block_access'));

            $db->setQuery($query);
            $extensionId = (int) $db->loadResult();
        } catch (\Throwable $e) {
            $extensionId = 0;
        }

        if ($extensionId <= 0) {
            return true;
        }

        $url = 'index.php?option=com_plugins&task=plugin.edit&extension_id=' . $extensionId;
        $link = '<a href="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '">'
            . Text::_('PLG_SH_BLOCK_ACCESS_POSTFLIGHT_CONFIGURE_LINK')
            . '</a>';

        $app->enqueueMessage(
            Text::sprintf('PLG_SH_BLOCK_ACCESS_POSTFLIGHT_CONFIGURE', $link),
            'message'
        );

        return true;
    }
}
