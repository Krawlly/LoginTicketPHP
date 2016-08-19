<?php

/**
 * Class TicketGenerator
 *
 * Использование:
 *  $cert = file_get_contents('path/to/pem-encoded-certificate');
 *  $tg = new TicketGenerator($cert);
 *  $ticket = $tg->createLoginTicket('userid');
 */
class TicketGenerator
{
    /**
     * @param $cert - сертификат (строка в PEM формате)
     * @throws Exception
     */
    public function __construct($cert){
        $this->cert = openssl_x509_read($cert);
        if($this->cert === FALSE)
            throw new Exception("Could not read certificate!");
    }

    /**
     * Создание произвольного тикета
     * @param $message - кодируемое сообщение
     * @return string
     */
    public function createTicket($message){
        $this->lastMessage = $message;
        return $this->encode($message);
    }

    /**
     * Создание Login тикета
     * @param $name - идентификатор пользователя
     * @param $periodInMinutes - время устаревания тикета (макс. 1 сутки = 1440 мин)
     * @return string
     */
    public function createLoginTicket($name, $periodInMinutes = 1440){
        $message = json_encode(["userName" => $name, "validThrough" => (time() + $periodInMinutes*60) * 1000]);
        return $this->createTicket($message);
    }

    /**
     * Создание Execution тикета
     * @param $callbackUrl - на какой url слать нотификации о вводе кода и капчи
     * @param $resultUrl - на какой url слать результат
     * @return string
     */
    public function createExecutionTicket($callbackUrl, $resultUrl){
        $message = json_encode(["callbackUrl" => $callbackUrl, "resultUrl" => $resultUrl]);
        return $this->createTicket($message);
    }

    /**
     *  Получает хэш сообщения из последнего тикета, используя сгенерированный для него ключ AES
    */
    public function hashLastMessage(){
        assert($this->lastKey && $this->lastMessage);
        if(!$this->lastKey || !$this->lastMessage)
            throw new Exception('createTicket should be called prior to hashLastMessage!');
        return hash_hmac('sha1', $this->lastMessage, $this->lastKey);
    }

    //Private stuff
    //***********************************************************************************************
    private $cert;

    //Настройки AES: алгоритм AES/CTR/NoPadding, последние 16 байт - IV
    private static $cipher_params = "MCoWA0FFUxYRQUVTL0NUUi9Ob1BhZGRpbmcEEPw56FGU1CAasAi89Sb5yiM=";

    private $lastKey;
    private $lastIV;
    private $lastMessage;

    private static function generateAESKey()
    {
        $wasItSecure = false;
        $iv = openssl_random_pseudo_bytes(16, $wasItSecure);
        if (!$wasItSecure) {
            error_log("Generated AES key is not secure");
        }
        return $iv;
    }

    private static function generateIV()
    {
        $wasItSecure = false;
        $iv = openssl_random_pseudo_bytes(16, $wasItSecure);
        if (!$wasItSecure) {
            error_log("Generated initialization vector is not secure");
        }
        return $iv;
    }

    private static function encodeAES($key, $message, $iv)
    {
        $encoded = openssl_encrypt($message, 'AES-128-CTR', $key, true, $iv);
        return $encoded;
    }

    private function encodeRSA($message)
    {
        $pubKey = openssl_pkey_get_public($this->cert);
        openssl_public_encrypt($message, $encoded, $pubKey);
        return $encoded;
    }

    private function encodeBinary($message){
        $this->lastKey = $key = self::generateAESKey();
        $this->lastIV = $iv = self::generateIV();

        $encoded_data = self::encodeAES($key, $message, $iv);

        $cipher_params = base64_decode(self::$cipher_params);
        $cipher_params = substr($cipher_params, 0, -16) . $iv;

        $encoded_params = $this->encodeRSA($cipher_params);
        $encoded_key = $this->encodeRSA($key);

        $encoded_message = $encoded_params . $encoded_key . $encoded_data;
        return $encoded_message;
    }

    private function encode($message){
        return base64_encode($this->encodeBinary($message));
    }

}