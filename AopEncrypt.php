<?php
namespace ginkgo\alipay;

/**
 * 加密工具类
*/
class AopEncrypt
{
    /**
     * 加密方法
     * @param string $str
     * @return string
     */
    public static function encrypt($str, $screctKey)
    {
        //AES, 128 模式加密数据 CBC
        $screctKey = base64_decode($screctKey);
        $str = trim($str);
        $str = addPKCS7Padding($str);
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128,MCRYPT_MODE_CBC),1);
        $encryptStr =  mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $screctKey, $str, MCRYPT_MODE_CBC);
        return base64_encode($encryptStr);
    }

    /**
     * 解密方法
     * @param string $str
     * @return string
     */
    public function decrypt($str,$screctKey)
    {
        //AES, 128 模式加密数据 CBC
        $str = base64_decode($str);
        $screctKey = base64_decode($screctKey);
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128,MCRYPT_MODE_CBC),1);
        $encryptStr = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $screctKey, $str, MCRYPT_MODE_CBC);
        $encryptStr = trim($encryptStr);

        $encryptStr = stripPKSC7Padding($encryptStr);
        return $encryptStr;
    }

    /**
     * 填充算法
     * @param string $source
     * @return string
     */
    public function addPKCS7Padding($source)
    {
        $source = trim($source);
        $block = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);

        $pad = $block - (strlen($source) % $block);
        if ($pad <= $block) {
            $char = chr($pad);
            $source .= str_repeat($char, $pad);
        }
        return $source;
    }
    /**
     * 移去填充算法
     * @param string $source
     * @return string
     */
    public function stripPKSC7Padding($source)
    {
        $source = trim($source);
        $char = substr($source, -1);
        $num = ord($char);
        if ($num == 62) {
            return $source;
        }
        $source = substr($source,0,-$num);
        return $source;
    }
}

