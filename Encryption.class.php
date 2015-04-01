<?php
/**
 * @category    CodeFelony
 * @package     CF_Encryption
 * @version     1.0.0
 * @license     GNU GENERAL PUBLIC LICENSE 2.0
 * @author      Moriarty <moriarty@codefelony.com>
 * @copyright   Copyright (c) 2015 CodeFelony. <https://codefelony.com>
 */
class Encryption
{
    private $_secretKey = "MBbu1mvK8Rsk0VxLXPRU"; // you can change it

    public static function encode($value)
    {
        return Encryption::_encode($value);
    }

    public static function decode($value)
    {
        return Encryption::_decode($value);
    }

    private function _safe_b64encode($string)
    {
        $data = base64_encode($string);
        $data = str_replace(array('+', '/', '='), array('-', '_', ''), $data);
        return $data;
    }

    private function _safe_b64decode($string)
    {
        $data = str_replace(array('-', '_'), array('+', '/'), $string);
        $mod4 = strlen($data) % 4;
        if ($mod4) {
            $data .= substr('====', $mod4);
        }
        return base64_decode($data);
    }

    private static function _encode($value)
    {
        if (!$value) {return false;}
        $text = $value;
        $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        $crypttext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $this->_secretKey, $text, MCRYPT_MODE_ECB, $iv);
        return trim($this->_safe_b64encode($crypttext));
    }

    private static function _decode($value)
    {
        if (!$value) {return false;}
        $crypttext = $this->_safe_b64decode($value);
        $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        $decrypttext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $this->_secretKey, $crypttext, MCRYPT_MODE_ECB, $iv);
        return trim($decrypttext);
    }
}
