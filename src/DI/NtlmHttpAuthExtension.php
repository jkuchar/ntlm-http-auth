<?php
namespace SiViN\NtlmHttpAuth\DI;

use Nette\DI\CompilerExtension;

class NtlmHttpAuthExtension extends CompilerExtension
{
    private $defaults = [
        'excludedPresenters' => []
    ];

    public function loadConfiguration()
    {
        parent::loadConfiguration();
        $config = $this->_getConfig();
        $builder = $this->getContainerBuilder();
        $builder->addDefinition($this->prefix('ntlmHttpAuth'))
            ->setClass('SiViN\NtlmHttpAuth\NtlmHttpAuth')
            ->addTag('run')
            ->setArguments([
                $config['excludedPresenters']
            ]);
        $builder->addDefinition("NtlmParser")->setClass('SiViN\NtlmHttpAuth\Parsers\NtlmParser');
    }

    /**
     * @return array
     */
    private function _getConfig()
    {
        return $this->validateConfig($this->defaults, $this->config);
    }
}