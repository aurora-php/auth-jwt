<?php

/*
 * This file is part of the 'octris/core' package.
 *
 * (c) Harald Lapp <harald@octris.org>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Octris\Jwt\Auth\Storage;

use Namshi\JOSE\SimpleJWS;

/**
 * Storage handler for storing identity in Json Web Token.
 *
 * @copyright   copyright (c) 2016 by Harald Lapp
 * @author      Harald Lapp <harald@octris.org>
 */
class Jwt implements \Octris\Core\Auth\IStorage
{
    /**
     * File containing private/public key.
     *
     * @type    string
     */
    protected $pem;

    /**
     * Options.
     *
     * @type    array
     */
    protected $options = array(
        'algorithm' => 'RS256',
        'passphrase' => '',
        'cookie' => 'identity'
    );

    /**
     * Identity stored in JWT cookie.
     *
     * @type    null|false|\Octris\Core\Auth\Identity
     */
    protected $identity = null;

    /**
     * Constructor. When reading pem from a file the first argument must be prefixed with 'file://'.
     *
     * @param           string                  $pem                        Private/public key string or file.
     * @param           array                   $options                    Additional optional options.
     */
    public function __construct($pem, array $options = array())
    {
        $this->pem = $pem;
        $this->options = array_merge($this->options, $options);
    }

    /**
     * Fetch identity from JWT cookie.
     *
     * @return          false|\Octris\Core\Auth\Identity                    Identity stored in JWT cookie or false if identity does not exist.
     */
    protected function fetchIdentity()
    {
        if (is_null($this->identity)) {
            $this->identity = false;
            $cookie = \Octris\Core\Provider::access('cookie');
            $name = $this->options['cookie'];

            if (($cookie->isExist($name) && $cookie->isValid($name, \Octris\Core\Validate::T_PRINTABLE))) {
                try {
                    $jws = SimpleJWS::load($cookie->getValue($name));
                    $public_key = openssl_pkey_get_public($this->pem);

                    if ($jws->isValid($public_key, $this->options['algorithm'])) {
                        $payload = $jws->getPayload();

                        if (isset($payload['ser'])) {
                            $this->identity = unserialize($payload['ser']);
                        }
                    }
                } catch(\Exception $e) {
                }
            }
        }

        return $this->identity;
    }

    /**
     * Returns whether storage contains an identity or not.
     *
     * @return                                                  Returns true, if storage is empty.
     */
    public function isEmpty()
    {
        return !$this->fetchIdentity();
    }

    /**
     * Store identity in cookie.
     *
     * @param   \Octris\Core\Auth\Identity  $identity       Identity to store in storage.
     */
    public function setIdentity(\Octris\Core\Auth\Identity $identity)
    {
        $jws  = new SimpleJWS(array(
            'alg' => $this->options['algorithm']
        ));
        $jws->setPayload(['ser' => serialize($identity)]);

        $private_key = openssl_pkey_get_private($this->pem, $this->options['passphrase']);

        $jws->sign($private_key);

        setcookie($this->options['cookie'], $jws->getTokenString(), 0, '/');
    }

    /**
     * Return identity from storage.
     *
     * @return  \Octris\Core\Auth\Identity                  Identity stored in storage.
     */
    public function getIdentity()
    {
        return $this->fetchIdentity();
    }

    /**
     * Deletes identity from storage.
     */
    public function unsetIdentity()
    {
        setcookie($this->options['cookie'], 'deleted', 1, '/');
    }
}
