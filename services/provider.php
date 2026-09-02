<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  System.block_access
 *
 * @copyright   (c) 2017-2026 Stefan Herzog
 * @license     GNU General Public License version 3 or later; see LICENSE.txt
 */

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;
use Joomla\Event\DispatcherInterface;
use Joomla\Plugin\System\BlockAccess\Extension\BlockAccess;

return new class implements ServiceProviderInterface
{
    public function register(Container $container): void
    {
        $container->set(
            PluginInterface::class,
            function (Container $container) {
                return new BlockAccess(
                    $container->get(DispatcherInterface::class),
                    (array) PluginHelper::getPlugin('system', 'block_access')
                );
            }
        );
    }
};
