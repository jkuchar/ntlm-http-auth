<?php
namespace SiViN\NtlmHttpAuth;

/**
 * @property string username
 * @property string domain
 * @property string workstation
 */
class AuthenticateResult
{
    /** @var  array */
    private $data = [];

    /**
     * @param $name
     * @return mixed
     */
    public function &__get($name)
    {
        return $this->data[$name];
    }

    /**
     * @param $name
     * @param $value
     */
    public function __set($name, $value)
    {
        $this->data[$name] = $value;
    }

    /**
     * @param $name
     * @return bool
     */
    public function __isset($name)
    {
        return isset($this->data[$name]);
    }

    /**
     * @param $name
     */
    public function __unset($name)
    {
        unset($this->data[$name]);
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return $this->data;
    }
}