<?php
/**
 * Created by PhpStorm.
 * User: steevenz
 * Date: 05/04/18
 * Time: 10.11
 */

namespace O2System\Security\Generators;

use O2System\Kernel\Http\Message\Uri;

/**
 * Class MachineId
 *
 * Generate Machine ID based on System Metadata information in UUID (Universally Unique Identifier) format.
 *
 * @package O2System\Security\Generators
 */
class MachineId
{
    /**
     * MachineId::generate
     *
     * @return string
     */
    public static function generate()
    {
        if (class_exists('O2System\Filesystem\System')) {
            $system = new \O2System\Filesystem\System();

            $metadata = [
                'machine'         => $system->getMachine(),
                'operatingSystem' => [
                    'name'    => $system->getName(),
                    'version' => $system->getVersion(),
                    'release' => $system->getRelease(),
                ],
                'hostname'        => $system->getHostname(),
                'cpuCores'        => $system->getCpuCores(),
                'macAddress'      => $system->getMacAddress(),
            ];
        } else {
            $metadata = [
                'machine'         => php_uname('m'),
                'operatingSystem' => [
                    'name'    => php_uname('s'),
                    'version' => php_uname('v'),
                    'release' => php_uname('r'),
                ],
                'hostname'        => php_uname('n'),
                'cpuCores'        => 1,
                'macAddress'      => implode(':', str_split(substr(md5('none'), 0, 12), 2)),
            ];
        }

        $uri = new Uri();

        $metadata[ 'domain' ] = $uri->getHost();
        $metadata[ 'ipAddress' ] = $_SERVER[ 'SERVER_ADDR' ];

        $string = json_encode($metadata);
        $string = md5($string);

        // Converts to UUID (Universally Unique Identifier)
        $parts[] = substr($string, 0, 8);
        $parts[] = substr($string, 8, 4);
        $parts[] = substr($string, 12, 4);
        $parts[] = substr($string, 16, 4);
        $parts[] = substr($string, 20, 12);

        $parts = array_map('strtoupper', $parts);

        return implode('-', $parts);
    }
}