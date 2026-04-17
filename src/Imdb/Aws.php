<?php

/**
 * AWS WAF challenge solver.
 *
 * Algorithm based on https://github.com/tveronesi/imdbinfo (MIT License).
 * Ported to PHP for use with imdbphp.
 */

namespace Imdb;

class Aws
{
    const ALPHABET = '0123456789abcdef';
    const IEEE_POLYNOMIAL = 0xEDB88320;
    const KEY_HEX = '6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98';
    const BANDWIDTH_CHALLENGE = 'ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25';
    const CHALLENGES = [
        'h72f957df656e80ba55f5d8ce2e8c7ccb59687dba3bfb273d54b08a261b2f3002' => 'computeScrypt',
        'h7b0c470f0cfe3a80a9e26526ad185f484f6817d0832712a4a37a908786a6a67f' => 'computePow',
        'ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25' => 'computeBandwidth',
    ];

    private $userAgent;
    private $domain;
    private $headers;
    private $config;

    public function __construct($userAgent, $domain, Config $config = null)
    {
        $this->userAgent = $userAgent;
        $this->config = $config;
        $this->domain = (strpos($domain, 'www') === false) ? 'www.' . $domain : $domain;
        $this->headers = [
            'connection: keep-alive',
            'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6',
            'cache-control: no-cache',
            'pragma: no-cache',
            'priority: u=0, i',
            'sec-ch-ua: "Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
            'sec-ch-ua-mobile: ?0',
            'sec-ch-ua-platform: "macOS"',
            'sec-fetch-dest: document',
            'sec-fetch-mode: navigate',
            'sec-fetch-site: same-origin',
            'upgrade-insecure-requests: 1',
            'user-agent: ' . $userAgent,
        ];
    }

    // ====== CRYPTO ======
    private static function secureRandomBytes($length)
    {
        if (function_exists('random_bytes')) {
            return random_bytes($length);
        }
        return openssl_random_pseudo_bytes($length);
    }

    private function encryptPayload($payloadStr)
    {
        $key = hex2bin(self::KEY_HEX);
        $iv = self::secureRandomBytes(12);
        $ivB64 = base64_encode($iv);

        if (PHP_VERSION_ID >= 70100 && function_exists('openssl_encrypt')) {
            $tag = '';
            $ciphertext = openssl_encrypt($payloadStr, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            return $ivB64 . '::' . bin2hex($tag) . '::' . bin2hex($ciphertext);
        }

        if (function_exists('sodium_crypto_aead_aes256gcm_is_available')
            && sodium_crypto_aead_aes256gcm_is_available()) {
            $ct = sodium_crypto_aead_aes256gcm_encrypt($payloadStr, '', $iv, $key);
            $tag = substr($ct, -16);
            $ciphertext = substr($ct, 0, -16);
            return $ivB64 . '::' . bin2hex($tag) . '::' . bin2hex($ciphertext);
        }

        if (function_exists('\Sodium\crypto_aead_aes256gcm_is_available')
            && \Sodium\crypto_aead_aes256gcm_is_available()) {
            $ct = \Sodium\crypto_aead_aes256gcm_encrypt($payloadStr, '', $iv, $key);
            $tag = substr($ct, -16);
            $ciphertext = substr($ct, 0, -16);
            return $ivB64 . '::' . bin2hex($tag) . '::' . bin2hex($ciphertext);
        }

        throw new \RuntimeException(
            'AES-256-GCM not available. Requires PHP 7.1+ with ext-openssl, or ext-sodium (PHP 7.2+ / PECL libsodium).'
        );
    }

    // ====== FINGERPRINT ======
    private function getFp()
    {
        $start = (int)(microtime(true) * 1000);
        $gpuExtensions = explode(';', 'ANGLE_instanced_arrays;EXT_blend_minmax;EXT_clip_control;EXT_color_buffer_half_float;EXT_depth_clamp;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_polygon_offset_clamp;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_texture_mirror_clamp_to_edge;EXT_sRGB;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_blend_func_extended;WEBGL_color_buffer_float;WEBGL_compressed_texture_astc;WEBGL_compressed_texture_etc;WEBGL_compressed_texture_etc1;WEBGL_compressed_texture_pvrtc;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw;WEBGL_polygon_mode');
        $histogramBins = [];
        for ($i = 0; $i < 256; $i++) {
            $histogramBins[] = mt_rand(0, 39);
        }
        return [
            'metrics' => [
                'fp2' => 1, 'browser' => 0, 'capabilities' => 1, 'gpu' => 7,
                'dnt' => 0, 'math' => 0, 'screen' => 0, 'navigator' => 0,
                'auto' => 1, 'stealth' => 0, 'subtle' => 0, 'canvas' => 5,
                'formdetector' => 1, 'be' => 0,
            ],
            'start' => $start,
            'flashVersion' => null,
            'plugins' => [
                ['name' => 'PDF Viewer', 'str' => 'PDF Viewer '],
                ['name' => 'Chrome PDF Viewer', 'str' => 'Chrome PDF Viewer '],
                ['name' => 'Chromium PDF Viewer', 'str' => 'Chromium PDF Viewer '],
                ['name' => 'Microsoft Edge PDF Viewer', 'str' => 'Microsoft Edge PDF Viewer '],
                ['name' => 'WebKit built-in PDF', 'str' => 'WebKit built-in PDF '],
            ],
            'dupedPlugins' => 'PDF Viewer Chrome PDF Viewer Chromium PDF Viewer Microsoft Edge PDF Viewer WebKit built-in PDF ||1920-1080-1032-24-*-*-*',
            'screenInfo' => '1920-1080-1032-24-*-*-*',
            'referrer' => '',
            'userAgent' => $this->userAgent,
            'location' => '',
            'webDriver' => false,
            'capabilities' => [
                'css' => [
                    'textShadow' => 1, 'WebkitTextStroke' => 1, 'boxShadow' => 1,
                    'borderRadius' => 1, 'borderImage' => 1, 'opacity' => 1,
                    'transform' => 1, 'transition' => 1,
                ],
                'js' => [
                    'audio' => true, 'geolocation' => (bool)mt_rand(0, 1),
                    'localStorage' => 'supported', 'touch' => false,
                    'video' => true, 'webWorker' => (bool)mt_rand(0, 1),
                ],
                'elapsed' => 1,
            ],
            'gpu' => [
                'vendor' => 'Google Inc. (Apple)',
                'model' => 'ANGLE (Apple, ANGLE Metal Renderer: Apple M2 Pro, Unspecified Version)',
                'extensions' => $gpuExtensions,
            ],
            'dnt' => null,
            'math' => [
                'tan' => '-1.4214488238747245',
                'sin' => '0.8178819121159085',
                'cos' => '-0.5753861119575491',
            ],
            'automation' => [
                'wd' => ['properties' => ['document' => [], 'window' => [], 'navigator' => []]],
                'phantom' => ['properties' => ['window' => []]],
            ],
            'stealth' => ['t1' => 0, 't2' => 0, 'i' => 1, 'mte' => 0, 'mtd' => false],
            'crypto' => [
                'crypto' => 1, 'subtle' => 1, 'encrypt' => true, 'decrypt' => true,
                'wrapKey' => true, 'unwrapKey' => true, 'sign' => true, 'verify' => true,
                'digest' => true, 'deriveBits' => true, 'deriveKey' => true,
                'getRandomValues' => true, 'randomUUID' => true,
            ],
            'canvas' => [
                'hash' => mt_rand(645172295, 735192295),
                'emailHash' => null,
                'histogramBins' => $histogramBins,
            ],
            'formDetected' => false,
            'numForms' => 0,
            'numFormElements' => 0,
            'be' => ['si' => false],
            'end' => $start + mt_rand(1, 5),
            'errors' => [],
            'version' => '2.4.0',
            'id' => $this->generateUuid(),
        ];
    }

    private function generateUuid()
    {
        $data = self::secureRandomBytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    // ====== CRC ======
    private function buildCrcTable()
    {
        $table = [];
        for ($i = 0; $i < 256; $i++) {
            $v = $i;
            for ($j = 0; $j < 8; $j++) {
                if ($v & 1) {
                    $v = ($v >> 1) ^ self::IEEE_POLYNOMIAL;
                } else {
                    $v >>= 1;
                }
            }
            $table[] = $v;
        }
        return $table;
    }

    private function calculateCrc($data, $crcTable)
    {
        $v51 = 0 ^ 0xFFFFFFFF;
        for ($i = 0; $i < strlen($data); $i++) {
            $charcode = ord($data[$i]);
            $v50 = 255 & ($v51 ^ $charcode);
            $v51 = ($v51 & 0xFFFFFFFF) >> 8 ^ $crcTable[$v50];
        }
        $result = 0xFFFFFFFF ^ $v51;
        if ($result >= 0x80000000) {
            $result -= 0x100000000;
        }
        return $result;
    }

    private function encodeNumber($num)
    {
        $num = $num & 0xFFFFFFFF;
        $alphabet = self::ALPHABET;
        return strtoupper(
            $alphabet[($num >> 28) & 15] . $alphabet[($num >> 24) & 15] .
            $alphabet[($num >> 20) & 15] . $alphabet[($num >> 16) & 15] .
            $alphabet[($num >> 12) & 15] . $alphabet[($num >> 8) & 15] .
            $alphabet[($num >> 4) & 15] . $alphabet[$num & 15]
        );
    }

    private function encodeFp()
    {
        $fp = $this->getFp();
        $crcTable = $this->buildCrcTable();
        $payloadStr = json_encode($fp, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $crcResult = $this->calculateCrc($payloadStr, $crcTable);
        $checksum = $this->encodeNumber($crcResult);
        return [$checksum . '#' . $payloadStr, $checksum];
    }

    private function buildEverything()
    {
        list($encoded, $checksum) = $this->encodeFp();
        return [
            'checksum' => $checksum,
            'encoded' => $encoded,
            'encrypted' => $this->encryptPayload($encoded),
        ];
    }

    // ====== CHALLENGE SOLVERS ======
    private static function check($difficulty, $hexHash)
    {
        $fullChars = intval($difficulty / 4);
        $remainBits = $difficulty % 4;
        for ($i = 0; $i < $fullChars && $i < strlen($hexHash); $i++) {
            if ($hexHash[$i] !== '0') {
                return false;
            }
        }
        if ($remainBits > 0 && $fullChars < strlen($hexHash)) {
            $val = intval($hexHash[$fullChars], 16);
            if (($val >> (4 - $remainBits)) !== 0) {
                return false;
            }
        }
        return true;
    }

    private function sha256Hashcash($inputString)
    {
        $hashBytes = hash('sha256', $inputString, true);
        $parts = [];
        for ($i = 0; $i < strlen($hashBytes); $i += 4) {
            $tmp = unpack('N', substr($hashBytes, $i, 4));
            $uint32 = $tmp[1];
            $parts[] = sprintf('%08x', $uint32);
        }
        return implode('', $parts);
    }

    public function computeScrypt($challengeB64, $checksum, $difficulty)
    {
        $salt = $checksum;
        for ($nonce = 0; ; $nonce++) {
            $password = $challengeB64 . $checksum . $nonce;
            $hashRaw = self::scrypt($password, $salt, 128, 8, 1, 16);
            $hash = bin2hex($hashRaw);
            if (self::check($difficulty, $hash)) {
                return (string)$nonce;
            }
        }
    }

    private static function scrypt($password, $salt, $n, $r, $p, $dklen)
    {
        if (extension_loaded('scrypt') && function_exists('scrypt')) {
            return scrypt($password, $salt, $n, $r, $p, $dklen);
        }
        if (function_exists('hash_pbkdf2')) {
            return self::scryptPure($password, $salt, $n, $r, $p, $dklen);
        }
        throw new \RuntimeException('scrypt support not available. Install ext-scrypt or use PHP with OpenSSL.');
    }

    private static function scryptPure($password, $salt, $n, $r, $p, $dklen)
    {
        $mfLen = 128 * $r;
        $b = hash_pbkdf2('sha256', $password, $salt, 1, $p * $mfLen, true);
        for ($i = 0; $i < $p; $i++) {
            $block = substr($b, $i * $mfLen, $mfLen);
            $block = self::scryptROMix($block, $n, $r);
            $b = substr_replace($b, $block, $i * $mfLen, $mfLen);
        }
        return hash_pbkdf2('sha256', $password, $b, 1, $dklen, true);
    }

    private static function scryptROMix($block, $n, $r)
    {
        $x = $block;
        $v = [];
        for ($i = 0; $i < $n; $i++) {
            $v[$i] = $x;
            $x = self::scryptBlockMix($x, $r);
        }
        for ($i = 0; $i < $n; $i++) {
            $tmp = unpack('V', substr($x, (2 * $r - 1) * 64, 4));
            $j = $tmp[1] % $n;
            $x = self::scryptBlockMix($x ^ $v[$j], $r);
        }
        return $x;
    }

    private static function scryptBlockMix($block, $r)
    {
        $chunks = str_split($block, 64);
        $x = end($chunks);
        $y = [];
        foreach ($chunks as $i => $chunk) {
            $x = self::salsa20_8($x ^ $chunk);
            $y[] = $x;
        }
        $even = '';
        $odd = '';
        foreach ($y as $i => $val) {
            if ($i % 2 === 0) {
                $even .= $val;
            } else {
                $odd .= $val;
            }
        }
        return $even . $odd;
    }

    private static function salsa20_8($input)
    {
        $x = array_values(unpack('V16', $input));
        $orig = $x;
        for ($i = 0; $i < 4; $i++) {
            $x[ 4] ^= self::rotl32($x[ 0] + $x[12], 7);
            $x[ 8] ^= self::rotl32($x[ 4] + $x[ 0], 9);
            $x[12] ^= self::rotl32($x[ 8] + $x[ 4], 13);
            $x[ 0] ^= self::rotl32($x[12] + $x[ 8], 18);
            $x[ 9] ^= self::rotl32($x[ 5] + $x[ 1], 7);
            $x[13] ^= self::rotl32($x[ 9] + $x[ 5], 9);
            $x[ 1] ^= self::rotl32($x[13] + $x[ 9], 13);
            $x[ 5] ^= self::rotl32($x[ 1] + $x[13], 18);
            $x[14] ^= self::rotl32($x[10] + $x[ 6], 7);
            $x[ 2] ^= self::rotl32($x[14] + $x[10], 9);
            $x[ 6] ^= self::rotl32($x[ 2] + $x[14], 13);
            $x[10] ^= self::rotl32($x[ 6] + $x[ 2], 18);
            $x[ 3] ^= self::rotl32($x[15] + $x[11], 7);
            $x[ 7] ^= self::rotl32($x[ 3] + $x[15], 9);
            $x[11] ^= self::rotl32($x[ 7] + $x[ 3], 13);
            $x[15] ^= self::rotl32($x[11] + $x[ 7], 18);
            $x[ 1] ^= self::rotl32($x[ 0] + $x[ 3], 7);
            $x[ 2] ^= self::rotl32($x[ 1] + $x[ 0], 9);
            $x[ 3] ^= self::rotl32($x[ 2] + $x[ 1], 13);
            $x[ 0] ^= self::rotl32($x[ 3] + $x[ 2], 18);
            $x[ 6] ^= self::rotl32($x[ 5] + $x[ 4], 7);
            $x[ 7] ^= self::rotl32($x[ 6] + $x[ 5], 9);
            $x[ 4] ^= self::rotl32($x[ 7] + $x[ 6], 13);
            $x[ 5] ^= self::rotl32($x[ 4] + $x[ 7], 18);
            $x[11] ^= self::rotl32($x[10] + $x[ 9], 7);
            $x[ 8] ^= self::rotl32($x[11] + $x[10], 9);
            $x[ 9] ^= self::rotl32($x[ 8] + $x[11], 13);
            $x[10] ^= self::rotl32($x[ 9] + $x[ 8], 18);
            $x[12] ^= self::rotl32($x[15] + $x[14], 7);
            $x[13] ^= self::rotl32($x[12] + $x[15], 9);
            $x[14] ^= self::rotl32($x[13] + $x[12], 13);
            $x[15] ^= self::rotl32($x[14] + $x[13], 18);
        }
        $out = '';
        for ($i = 0; $i < 16; $i++) {
            $out .= pack('V', ($x[$i] + $orig[$i]) & 0xFFFFFFFF);
        }
        return $out;
    }

    private static function rotl32($v, $n)
    {
        $v = $v & 0xFFFFFFFF;
        return (($v << $n) | ($v >> (32 - $n))) & 0xFFFFFFFF;
    }

    public function computePow($inputStr, $checksum, $difficulty)
    {
        $base = $inputStr . $checksum;
        $nonce = 0;
        while (true) {
            $hashHex = $this->sha256Hashcash($base . $nonce);
            if (self::check($difficulty, $hashHex)) {
                return (string)$nonce;
            }
            $nonce++;
        }
    }

    public function computeBandwidth($challengeB64, $checksum, $difficulty)
    {
        $sizes = [1 => 1024, 2 => 10240, 3 => 102400, 4 => 1048576, 5 => 10485760];
        $n = isset($sizes[$difficulty]) ? $sizes[$difficulty] : 0;
        $nullBytes = str_repeat("\0", $n);
        return base64_encode($nullBytes);
    }

    // ====== EXTRACT / HTTP ======
    public function extract($html)
    {
        $parts = explode('window.gokuProps = ', $html, 2);
        $gokuJson = explode(';', $parts[1], 2)[0];
        $gokuProps = json_decode($gokuJson, true);
        $parts2 = explode('src="https://', $html, 2);
        $hostUrl = explode('/challenge.js', $parts2[1], 2)[0];
        return [$gokuProps, $hostUrl];
    }

    private function curlGet($url)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $this->headers);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        if ($this->config && $this->config->use_proxy) {
            curl_setopt($ch, CURLOPT_PROXY, $this->config->proxy_host);
            curl_setopt($ch, CURLOPT_PROXYPORT, $this->config->proxy_port);
            if (!empty($this->config->proxy_user) && !empty($this->config->proxy_pw)) {
                curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
                curl_setopt($ch, CURLOPT_PROXYUSERPWD, $this->config->proxy_user . ':' . $this->config->proxy_pw);
            }
        }
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }

    private function curlPostMultipart($url, $solutionData, $solutionMetadata)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $postFields = [
            'solution_data' => $solutionData,
            'solution_metadata' => $solutionMetadata,
        ];
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
        $headers = $this->headers;
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        if ($this->config && $this->config->use_proxy) {
            curl_setopt($ch, CURLOPT_PROXY, $this->config->proxy_host);
            curl_setopt($ch, CURLOPT_PROXYPORT, $this->config->proxy_port);
            if (!empty($this->config->proxy_user) && !empty($this->config->proxy_pw)) {
                curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
                curl_setopt($ch, CURLOPT_PROXYUSERPWD, $this->config->proxy_user . ':' . $this->config->proxy_pw);
            }
        }
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }

    private function curlPostJson($url, $payload)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
        $headers = $this->headers;
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        if ($this->config && $this->config->use_proxy) {
            curl_setopt($ch, CURLOPT_PROXY, $this->config->proxy_host);
            curl_setopt($ch, CURLOPT_PROXYPORT, $this->config->proxy_port);
            if (!empty($this->config->proxy_user) && !empty($this->config->proxy_pw)) {
                curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
                curl_setopt($ch, CURLOPT_PROXYUSERPWD, $this->config->proxy_user . ':' . $this->config->proxy_pw);
            }
        }
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }

    private function getFinalValues($hostUrl)
    {
        $response = $this->curlGet("https://{$hostUrl}/inputs?client=browser");
        return json_decode($response, true);
    }

    private function buildPayload($input, $gokuProps)
    {
        $challengeType = $input['challenge_type'];
        $method = self::CHALLENGES[$challengeType];
        $payload = $this->buildEverything();
        $isBandwidth = ($challengeType === self::BANDWIDTH_CHALLENGE);

        if ($isBandwidth) {
            $solutionB64 = $this->$method('', '', $input['difficulty']);
            $solutionMetadata = [
                'challenge' => $input['challenge'],
                'solution' => null,
                'signals' => [['name' => 'Zoey', 'value' => ['Present' => $payload['encrypted']]]],
                'checksum' => $payload['checksum'],
                'client' => 'Browser',
                'domain' => $this->domain,
                'metrics' => $this->buildMetrics(),
                'goku_props' => $gokuProps,
            ];
            return [
                '_is_bandwidth' => true,
                'solution_data' => $solutionB64,
                'solution_metadata' => $solutionMetadata,
            ];
        }

        $solution = $this->$method($input['challenge'], $payload['checksum'], $input['difficulty']);
        return [
            '_is_bandwidth' => false,
            'challenge' => $input['challenge'],
            'solution' => $solution,
            'signals' => [['name' => 'Zoey', 'value' => ['Present' => $payload['encrypted']]]],
            'checksum' => $payload['checksum'],
            'client' => 'Browser',
            'domain' => $this->domain,
            'metrics' => $this->buildMetrics(),
            'goku_props' => $gokuProps,
        ];
    }

    private function buildMetrics()
    {
        return [
            ['name' => '2',         'value' => lcg_value(),           'unit' => '2'],
            ['name' => '100',       'value' => 0,                     'unit' => '2'],
            ['name' => '101',       'value' => 0,                     'unit' => '2'],
            ['name' => '102',       'value' => 0,                     'unit' => '2'],
            ['name' => '103',       'value' => 8,                     'unit' => '2'],
            ['name' => '104',       'value' => 0,                     'unit' => '2'],
            ['name' => '105',       'value' => 0,                     'unit' => '2'],
            ['name' => '106',       'value' => 0,                     'unit' => '2'],
            ['name' => '107',       'value' => 0,                     'unit' => '2'],
            ['name' => '108',       'value' => 1,                     'unit' => '2'],
            ['name' => 'undefined', 'value' => 0,                     'unit' => '2'],
            ['name' => '110',       'value' => 0,                     'unit' => '2'],
            ['name' => '111',       'value' => 2,                     'unit' => '2'],
            ['name' => '112',       'value' => 0,                     'unit' => '2'],
            ['name' => 'undefined', 'value' => 0,                     'unit' => '2'],
            ['name' => '3',         'value' => 4,                     'unit' => '2'],
            ['name' => '7',         'value' => 0,                     'unit' => '4'],
            ['name' => '1',         'value' => 5 + lcg_value() * 15,  'unit' => '2'],
            ['name' => '4',         'value' => 36.5,                  'unit' => '2'],
            ['name' => '5',         'value' => lcg_value(),           'unit' => '2'],
            ['name' => '6',         'value' => 100 + lcg_value()*400, 'unit' => '2'],
            ['name' => '0',         'value' => 135 + lcg_value()*365, 'unit' => '2'],
            ['name' => '8',         'value' => 1,                     'unit' => '4'],
        ];
    }

    private function postPayload($payload, $hostUrl)
    {
        if (!empty($payload['_is_bandwidth'])) {
            $metaJson = json_encode($payload['solution_metadata'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $response = $this->curlPostMultipart(
                "https://{$hostUrl}/mp_verify",
                $payload['solution_data'],
                $metaJson
            );
        } else {
            unset($payload['_is_bandwidth']);
            $response = $this->curlPostJson("https://{$hostUrl}/verify", $payload);
        }
        return json_decode($response, true);
    }

    /**
     * Solve the AWS WAF challenge from the given HTML page.
     * @param string $siteHtml The HTML containing gokuProps and challenge.js
     * @return string The solved token
     */
    public function solve($siteHtml)
    {
        list($goku, $hostUrl) = $this->extract($siteHtml);
        $values = $this->getFinalValues($hostUrl);
        $payload = $this->buildPayload($values, $goku);
        $result = $this->postPayload($payload, $hostUrl);
        return $result['token'];
    }
}
