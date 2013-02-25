<?php

/**
 * Encrypt and decrypt.
 *
 * @author Eduardo Cuomo.
 */
class Encriptator {
    /**
     * Default key.
     * Using this full file path to re-implement easily in other projects and is diferent.
     */
    const DEFAULT_KEY = __FILE__;
    
    /**
     * Double encriptation?
     */
    const LEVEL_2 = false;

    /**
     * Code to encript the key.
     */
    private $ENCRYPT_CODE_X;

    /**
     * Encriptator.
     *
     * @param $key OPTIONAL. Key used to encrypt.
     */
    public function __construct($key) {
        $k = md5($key . __CLASS__ . __DIR__);
        $this->ENCRYPT_CODE_X = substr($k, 16) . $key . substr($k, 0, 15);
    }

    /**
     * Encrypt as URL.
     *
     * @param $value Value to encrypt.
     * @param $key OPTIONAL. Key used to encrypt.
     */
    public function encryptURL($value, $key = self::DEFAULT_KEY) {
        return urlencode($this->encrypt($value, $key));
    }

    /**
     * Encrypt.
     *
     * @param $value Value to encrypt.
     * @param $key OPTIONAL. Key used to encrypt.
     * @return Encrypted value.
     */
    public function encrypt($value, $key = self::DEFAULT_KEY) {
        $result = '';
        $key = $this->encryptKey($key);
        $value = $this->invertString(base64_encode($this->invertString(serialize($value))));
        if (self::LEVEL_2) {
            $value = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($key), $value, MCRYPT_MODE_CBC, md5(md5($key))));
        }
        $t = time();
        $value = base64_encode(md5($t . $value . rand(100, 999)) . $value . md5(self::DEFAULT_KEY . rand(100, 999) . $t));
        for($i = 0; $i < strlen($value); $i++) {
            $char = substr($value, $i, 1);
            $keychar = substr($key, ($i % strlen($key)) - 1, 1);
            $char = chr(ord($char) + ord($keychar));
            $result .= $char;
        }
        return base64_encode($result);
    }

    /**
     * Decrypt.
     *
     * @param $value Value to decrypt.
     * @param $key OPTIONAL. Key used to decrypt.
     * @return Decrypted value.
     */
    public function decrypt($value, $key = self::DEFAULT_KEY) {
        if (empty($value)) return $value;
        $result = '';
        $key = $this->encryptKey($key);
        $value = base64_decode($value);
        for($i=0; $i < strlen($value); $i++) {
            $char = substr($value, $i, 1);
            $keychar = substr($key, ($i % strlen($key)) - 1, 1);
            $char = chr(ord($char) - ord($keychar));
            $result .= $char;
        }
        $result = base64_decode($result);
        $result = substr($result, 32, strlen($result) - 64);
        if (self::LEVEL_2) {
            $result = rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($key), base64_decode($result), MCRYPT_MODE_CBC, md5(md5($key))), "\0");
        }
        return unserialize($this->invertString(base64_decode( $this->invertString($result))));
    }

    private function encryptKey($key) {
        $k = '';
        $m = md5($key . $this->ENCRYPT_CODE_X);
        for($i = 0; $i < strlen($key); $i++)
            // $k = ($key + $m) / 2
            $k .= chr(ceil((ord(substr($key, $i, 1)) + ord(substr($m, ($i % strlen($key)) - 1, 1))) / 2));
        return $k;
    }

    private function invertString($str) {
        $s = '';
        if (!empty($str)) for($p = 0; $p < strlen($str); $p++) $s = substr($str, $p, 1) . $s;
        return $s;
    }
}



/** TEST **/

function test($value) {
    $e = new Encriptador(__FILE__ . __CLASS__); $code = $e->encrypt($value); $result = $e->decrypt($code);
    //echo "Generated:\n$code\n\n";
    if ($value != $result) {
        die("ERROR!\nIN: " . var_export($value) . "\n\nOUT: " . var_export($result) . "\n\n");
    }
}

test("Hello world!");
test("áéíóúñüÁÉÍÓÚ·|\\¡'\"");
test(array("a" => "1111asd", "b" => 22222));
test(str_repeat("hello!\t", 1000));

die("PASSED!\n");
