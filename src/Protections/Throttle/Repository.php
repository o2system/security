<?php
/**
 * This file is part of the O2System PHP Framework package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @author         Steeve Andrian Salim
 * @copyright      Copyright (c) Steeve Andrian Salim
 */

// ------------------------------------------------------------------------

namespace O2System\Security\Protections\Throttle;

// ------------------------------------------------------------------------

use O2System\Psr\Container\ContainerExceptionInterface;
use O2System\Psr\Container\ContainerInterface;
use O2System\Psr\NotFoundExceptionInterface;
use Traversable;

/**
 * Class Repository
 * @package O2System\Kernel\Containers
 */
class Repository implements
    \ArrayAccess,
    \IteratorAggregate,
    \Countable,
    \Serializable,
    \JsonSerializable,
    ContainerInterface
{
    /**
     * Repository::__construct
     */
    public function __construct()
    {
        if (empty($_SESSION[ 'throttle' ])) {
            $_SESSION[ 'throttle' ] = [];
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Retrieve an external iterator
     *
     * @link  http://php.net/manual/en/iteratoraggregate.getiterator.php
     * @return Traversable An instance of an object implementing <b>Iterator</b> or
     *        <b>Traversable</b>
     * @since 5.0.0
     */
    public function getIterator()
    {
        return new \ArrayIterator($_SESSION[ 'throttle' ]);
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::exists
     *
     * Checks if the data exists on the storage.
     * An alias of Globals::__isset method.
     *
     * @param string $offset The object offset key.
     *
     * @return bool Returns TRUE on success or FALSE on failure.
     */
    public function exists($offset)
    {
        return $this->__isset($offset);
    }

    // ------------------------------------------------------------------------

    /**
     * Globals__isset
     *
     * Implementing magic method __isset to simplify when checks if offset exists on PHP native session variable,
     * just simply calling isset( $globals[ 'offset' ] ).
     *
     * @param mixed $offset PHP native GLOBALS offset.
     *
     * @return bool
     */
    public function __isset($offset)
    {
        return $this->offsetExists($offset);
    }

    // ------------------------------------------------------------------------

    /**
     * Whether a offset exists
     *
     * @link  http://php.net/manual/en/arrayaccess.offsetexists.php
     *
     * @param mixed $offset <p>
     *                      An offset to check for.
     *                      </p>
     *
     * @return boolean true on success or false on failure.
     * </p>
     * <p>
     * The return value will be casted to boolean if non-boolean was returned.
     * @since 5.0.0
     */
    public function offsetExists($offset)
    {
        return isset($_SESSION[ 'throttle' ][ $offset ]);
    }

    // ------------------------------------------------------------------------

    /**
     * Session::__get
     *
     * Implementing magic method __get to simplify gets PHP native session variable by requested offset,
     * just simply calling isset( $session[ 'offset' ] ).
     *
     * @param $offset
     *
     * @return mixed
     */
    public function &__get($offset)
    {
        return $_SESSION[ 'throttle' ][ $offset ];
    }

    // ------------------------------------------------------------------------

    /**
     * Globals__set
     *
     * Implementing magic method __set to simplify set PHP native GLOBALS variable,
     * just simply calling $globals->offset = 'foo'.
     *
     * @param mixed $offset PHP native GLOBALS offset.
     * @param mixed $value  PHP native GLOBALS offset value to set.
     */
    public function __set($offset, $value)
    {
        $this->offsetSet($offset, $value);
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::store
     *
     * Store the data into the storage.
     * An alias of Globals::__set method.
     *
     * @param string $offset The data offset key.
     * @param mixed  $value  The data to be stored.
     *
     * @return void
     */
    public function store($offset, $value)
    {
        $this->__set($offset, $value);
    }

    // ------------------------------------------------------------------------

    /**
     * Offset to set
     *
     * @link  http://php.net/manual/en/arrayaccess.offsetset.php
     *
     * @param mixed $offset <p>
     *                      The offset to assign the value to.
     *                      </p>
     * @param mixed $value  <p>
     *                      The value to set.
     *                      </p>
     *
     * @return void
     * @since 5.0.0
     */
    public function offsetSet($offset, $value)
    {
        $_SESSION[ 'throttle' ][ $offset ] = $value;
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::remove
     *
     * Removes a data from the storage.
     * An alias of Globals::__unset method.
     *
     * @param string $offset The object offset key.
     *
     * @return void
     */
    public function remove($offset)
    {
        $this->__unset($offset);
    }

    // ------------------------------------------------------------------------

    /**
     * Globals__unset
     *
     * Implementing magic method __unset to simplify unset method, just simply calling
     * unset( $globals[ 'offset' ] ).
     *
     * @param mixed $offset PHP Native GLOBALS offset
     *
     * @return void
     */
    public function __unset($offset)
    {
        $this->offsetUnset($offset);
    }

    // ------------------------------------------------------------------------

    /**
     * Offset to unset
     *
     * @link  http://php.net/manual/en/arrayaccess.offsetunset.php
     *
     * @param mixed $offset <p>
     *                      The offset to unset.
     *                      </p>
     *
     * @return void
     * @since 5.0.0
     */
    public function offsetUnset($offset)
    {
        if (isset($_SESSION[ 'throttle' ][ $offset ])) {
            unset($_SESSION[ 'throttle' ][ $offset ]);
        }
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::merge
     *
     * Merge new array of data into the data storage.
     *
     * @param array $data New array of data.
     *
     * @return array The old array of data storage.
     */
    public function merge(array $data)
    {
        $oldData = $_SESSION[ 'throttle' ];
        $_SESSION[ 'throttle' ] = array_merge($_SESSION[ 'throttle' ], $data);

        return $oldData;
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::exchange
     *
     * Exchange the array of data storage into the new array of data.
     *
     * @param array $data New array of data.
     *
     * @return array The old array of data storage.
     */
    public function exchange(array $data)
    {
        $oldData = $_SESSION[ 'throttle' ];
        $_SESSION[ 'throttle' ] = $data;

        return $oldData;
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::destroy
     *
     * Removes all object from the container and perform each object destruction.
     *
     * @return array Array of old storage items.
     */
    public function destroy()
    {
        $storage = $_SESSION[ 'throttle' ];

        $_SESSION[ 'throttle' ] = [];

        return $storage;
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::count
     *
     * Application of Countable::count method to count the numbers of contained objects.
     *
     * @see  http://php.net/manual/en/countable.count.php
     * @return int The numbers of data on the storage.
     */
    public function count()
    {
        return (int)count($_SESSION[ 'throttle' ]);
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::serialize
     *
     * Application of Serializable::serialize method to serialize the data storage.
     *
     * @see  http://php.net/manual/en/serializable.serialize.php
     *
     * @return string The string representation of the serialized data storage.
     */
    public function serialize()
    {
        return serialize($_SESSION[ 'throttle' ]);
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::unserialize
     *
     * Application of Serializable::unserialize method to unserialize and construct the data storage.
     *
     * @see  http://php.net/manual/en/serializable.unserialize.php
     *
     * @param string $serialized The string representation of the serialized data storage.
     *
     * @return void
     */
    public function unserialize($serialized)
    {
        $_SESSION[ 'throttle' ] = unserialize($serialized);
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::jsonSerialize
     *
     * Specify data which should be serialized to JSON
     *
     * @link  http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     *        which is a value of any type other than a resource.
     * @since 5.4.0
     */
    public function jsonSerialize()
    {
        return $_SESSION[ 'throttle' ];
    }

    // ------------------------------------------------------------------------

    /**
     * Globals::getArrayCopy
     *
     * Gets a copy of the data storage.
     *
     * @return array Returns a copy of the data storage.
     */
    public function getArrayCopy()
    {
        return $_SESSION[ 'throttle' ];
    }

    // ------------------------------------------------------------------------

    /**
     * Finds an entry of the container by its identifier and returns it.
     *
     * @param string $id Identifier of the entry to look for.
     *
     * @throws NotFoundExceptionInterface  No entry was found for **this** identifier.
     * @throws ContainerExceptionInterface Error while retrieving the entry.
     *
     * @return mixed Entry.
     */
    public function get($id)
    {
        if ($this->has($id)) {
            return $this->offsetGet($id);
        }

        // @todo throw exception
    }

    // ------------------------------------------------------------------------

    /**
     * Returns true if the container can return an entry for the given identifier.
     * Returns false otherwise.
     *
     * `has($id)` returning true does not mean that `get($id)` will not throw an exception.
     * It does however mean that `get($id)` will not throw a `NotFoundExceptionInterface`.
     *
     * @param string $id Identifier of the entry to look for.
     *
     * @return bool
     */
    public function has($id)
    {
        return (bool)$this->offsetExists($id);
    }

    // ------------------------------------------------------------------------

    /**
     * Offset to retrieve
     *
     * @link  http://php.net/manual/en/arrayaccess.offsetget.php
     *
     * @param mixed $offset <p>
     *                      The offset to retrieve.
     *                      </p>
     *
     * @return mixed Can return all value types.
     * @since 5.0.0
     */
    public function offsetGet($offset)
    {
        return (isset($_SESSION[ 'throttle' ][ $offset ])) ? $_SESSION[ 'throttle' ][ $offset ] : false;
    }
}