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
     * JWT Algorithm.
     *
     * @type    string
     */
    protected $algorithm;

    /**
     * File containing private/public key.
     *
     * @type    string
     */
    protected $pem;

    /**
     * Passphrase for private key.
     *
     * @type    string
     */
    protected $passphrase;

    /**
     * Identity stored in JWT cookie.
     *
     * @type    null|false|\Octris\Core\Auth\Identity
     */
    protected $identity = null;

    /**
     * Constructor.
     *
     * @param           string                  $algorithm                  Algorithm to use.
     * @param           string                  $pem                        Private/public key file.
     * @param           string                  $passphrase                 Optional passphrase for private key.
     */
    public function __construct($algorithm, $pem, $passphrase = '')
    {
        $this->algorithm = $algorithm;
        $this->pem = $pem;
        $this->passphrase = $passphrase;
    }

    /**
     * Fetch identity from JWT cookie.
     *
     * @return          false|\Octris\Core\Auth\Identity                    Identity stored in JWT cookie or false if identity does not exist.
     */
    protected function fetchIdentity()
    {
        if (is_null($this->identity)) {
            $cookie = \Octris\Core\Provider::access('cookie');

            if (($cookie->isExist('identity') && $cookie->isValid('identity', \Octris\Core\Validate::T_PRINTABLE))) {
                $jws = SimpleJWS::load($cookie->getValue('identity'));
                $public_key = openssl_pkey_get_public($this->pem);

                if ($jws->isValid($public_key, $this->algorithm)) {
                    $payload = $jws->getPayload();

                    if (!isset($payload['ser'])) {
                        $this->identity = false;
                    } else {
                        $this->identity = unserialize($payload['ser']);
                    }
                } else {
                    $this->identity = false;
                }
            } else {
                $this->identity = false;
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
            'alg' => $this->algorithm
        ));
        $jws->setPayload(['ser' => serialize($identity)]);

        $private_key = openssl_pkey_get_private($this->pem, $this->passphrase);

        $jws->sign($private_key);

        setcookie('identity', $jws->getTokenString());
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
        setcookie('identity', 'deleted', 1);
    }
}
