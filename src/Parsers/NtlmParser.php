<?php
/**
 * Based on https://github.com/loune/php-ntlm, thx!
 */

namespace SiViN\NtlmHttpAuth\Parsers;

use Nette\Http\IResponse;
use Nette\Http\Session;
use SiViN\NtlmHttpAuth\AuthenticateResult;
use SiViN\NtlmHttpAuth\HeaderRecognisedException;
use SiViN\NtlmHttpAuth\IAuthorizationHeaderParser;

class NtlmParser implements IAuthorizationHeaderParser
{
    /** @var  IResponse */
    protected $httpResponse;

    /** @var  Session */
    protected $session;

    /**
     * NtlmParser constructor.
     * @param IResponse $httpResponse
     * @param Session $session
     */
    public function __construct(IResponse $httpResponse, Session $session)
    {
        $this->httpResponse = $httpResponse;
        $this->session = $session;
    }

    /**
     * @param string $authHeader
     * @return AuthenticateResult
     * @throws HeaderRecognisedException
     */
    function parse($authHeader)
    {
        $packet = base64_decode(substr($authHeader, 5));
        if (substr($packet, 0, 8) !== "NTLMSSP\x00") {
            throw new HeaderRecognisedException();
        }

        if ($packet[8] === "\x01") {
            $this->httpResponse->setCode(IResponse::S401_UNAUTHORIZED);
            $targetname = $domain = $computer = $dnsdomain = $dnscomputer = "unknown";
            $msg = $this->ntlm_get_challenge_msg($packet, $this->ntlm_get_random_bytes(8), $targetname, $computer, $domain, $dnscomputer);
            $this->httpResponse->setHeader("WWW-Authenticate", 'NTLM ' . trim(base64_encode($msg)));
            die;
        }

        if ($packet[8] === "\x03") {
            $parsed = $this->ntlm_parse_response_msg($packet);
            $ret = new AuthenticateResult();
            $ret->username = $parsed["username"];
            $ret->domain = $parsed["domain"];
            $ret->workstation = $parsed["workstation"];
            return $ret;
        }

        throw new HeaderRecognisedException();
    }

    /**
     * @param $msg
     * @param $challenge
     * @param $targetname
     * @param $computer
     * @param $dnsdomain
     * @param $dnscomputer
     * @return string
     */
    function ntlm_get_challenge_msg($msg, $challenge, $targetname, $computer, $dnsdomain, $dnscomputer)
    {
        $domain = $this->ntlm_field_value($msg, 16);
        $tdata = $this->ntlm_av_pair(2, $this->ntlm_utf8_to_utf16le($domain)) . $this->ntlm_av_pair(1, $this->ntlm_utf8_to_utf16le($computer)) . $this->ntlm_av_pair(4, $this->ntlm_utf8_to_utf16le($dnsdomain)) . $this->ntlm_av_pair(3, $this->ntlm_utf8_to_utf16le($dnscomputer)) . "\0\0\0\0\0\0\0\0";
        $tname = $this->ntlm_utf8_to_utf16le($targetname);
        $ret = "NTLMSSP\x00\x02\x00\x00\x00" .
            pack('vvV', strlen($tname), strlen($tname), 48) . // target name len/alloc/offset
            "\x01\x02\x81\x00" . // flags
            $challenge . // challenge
            "\x00\x00\x00\x00\x00\x00\x00\x00" . // context
            pack('vvV', strlen($tdata), strlen($tdata), 48 + strlen($tname)) . // target info len/alloc/offset
            $tname . $tdata;
        return $ret;
    }

    /**
     * @param $msg
     * @param $start
     * @param bool $decode_utf16
     * @return string
     */
    private function ntlm_field_value($msg, $start, $decode_utf16 = true)
    {
        $len = (ord($msg[$start + 1]) * 256) + ord($msg[$start]);
        $off = (ord($msg[$start + 5]) * 256) + ord($msg[$start + 4]);
        $result = substr($msg, $off, $len);
        if ($decode_utf16) {
            $result = iconv('UTF-16LE', 'UTF-8', $result);
        }
        return $result;
    }

    /**
     * @param $type
     * @param $utf16
     * @return string
     */
    function ntlm_av_pair($type, $utf16)
    {
        return pack('v', $type) . pack('v', strlen($utf16)) . $utf16;
    }

    /**
     * @param $str
     * @return string
     */
    function ntlm_utf8_to_utf16le($str)
    {
        return iconv('UTF-8', 'UTF-16LE', $str);
    }

    /**
     * @param $length
     * @return string
     */
    function ntlm_get_random_bytes($length)
    {
        $result = "";
        for ($i = 0; $i < $length; $i++) {
            $result .= chr(rand(0, 255));
        }
        return $result;
    }

    /**
     * @param $msg
     * @return array
     * @throws HeaderRecognisedException
     */
    function ntlm_parse_response_msg($msg)
    {
        $user = $this->ntlm_field_value($msg, 36);
        $domain = $this->ntlm_field_value($msg, 28);
        $workstation = $this->ntlm_field_value($msg, 44);
        $ntlmresponse = $this->ntlm_field_value($msg, 20, false);
        $clientblob = substr($ntlmresponse, 16);
        if (substr($clientblob, 0, 8) != "\x01\x01\x00\x00\x00\x00\x00\x00") {
            throw new HeaderRecognisedException('NTLMv2 response required. Please force your client to use NTLMv2.');
        }
        return array('username' => $user, 'domain' => $domain, 'workstation' => $workstation);
    }
}