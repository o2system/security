<?php
/**
 * This file is part of the O2System Framework package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author         Steeve Andrian Salim
 * @copyright      Copyright (c) Steeve Andrian Salim
 */

/**
 * Created by PhpStorm.
 * User: steevenz
 * Date: 02/07/18
 * Time: 09.52
 */

namespace O2System\Security\Authentication\User;


use O2System\Spl\Patterns\Structural\Repository\AbstractRepository;

class Authority extends AbstractRepository
{
    public function __construct(array $role)
    {
        foreach ($role as $key => $value) {
            $this->store($key, $value);
        }
    }

    public function store($offset, $data)
    {
        if ($offset === 'permission') {
            if (in_array($data, ['GRANTED', 'DENIED'])) {
                $data = strtoupper($data);
            } else {
                return;
            }
        } elseif ($offset === 'privileges') {
            list($create, $read, $update, $delete, $import, $export, $print, $special) = array_pad(str_split($data), 8,
                0);
            $data = [
                'create'  => ($create == '1' ? true : false),
                'read'    => ($read == '1' ? true : false),
                'update'  => ($update == '1' ? true : false),
                'delete'  => ($delete == '1' ? true : false),
                'import'  => ($import == '1' ? true : false),
                'export'  => ($export == '1' ? true : false),
                'print'   => ($print == '1' ? true : false),
                'special' => ($special == '1' ? true : false),
            ];
        }

        parent::store($offset, $data);
    }

    public function getPermission()
    {
        return $this->get('permission');
    }

    public function getPrivileges()
    {
        return $this->get('privileges');
    }

    public function hasCreatePrivilege()
    {
        return $this->checkPrivilege('create');
    }

    public function checkPrivilege($action)
    {
        if ($privileges = $this->get('privileges')) {
            return (bool)$privileges[ $action ];
        }

        return false;
    }

    public function hasReadPrivilege()
    {
        return $this->checkPrivilege('read');
    }

    public function hasUpdatePrivilage()
    {
        return $this->checkPrivilege('update');
    }

    public function hasDeletePrivilage()
    {
        return $this->checkPrivilege('delete');
    }

    public function hasImportPrivilege()
    {
        return $this->checkPrivilege('import');
    }

    public function hasExportPrivilege()
    {
        return $this->checkPrivilege('export');
    }

    public function hasPrintPrivilege()
    {
        return $this->checkPrivilege('print');
    }

    public function hasSpecialPrivilege()
    {
        return $this->checkPrivilege('special');
    }
}