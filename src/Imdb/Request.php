<?php

#############################################################################
# IMDBPHP                              (c) Giorgos Giagas & Itzchak Rehberg #
# written by Giorgos Giagas                                                 #
# extended & maintained by Itzchak Rehberg <izzysoft AT qumran DOT org>     #
# http://www.izzysoft.de/                                                   #
# ------------------------------------------------------------------------- #
# This program is free software; you can redistribute and/or modify it      #
# under the terms of the GNU General Public License (see doc/LICENSE)       #
#############################################################################

namespace Imdb;

/**
 * The request class
 * Here we emulate a browser accessing the IMDB site. You don't need to
 * call any of its method directly - they are rather used by the IMDB classes.
 */
class Request
{
    private $ch;
    private $urltoopen;
    private $page;
    private $requestHeaders = array();
    private $responseHeaders = array();
    private $config;
    private $userAgent;
    private $postContent = null;
    private $maxChallengeRetries = 3;
    private static $wafToken = null;

    /**
     * No need to call this.
     * @param string $url URL to open
     * @param Config $config The Config object to use
     */
    public function __construct($url, Config $config)
    {
        $this->config = $config;
        $this->ch = curl_init($url);
        curl_setopt($this->ch, CURLOPT_ENCODING, "");
        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->ch, CURLOPT_HEADERFUNCTION, array(&$this, "callback_CURLOPT_HEADERFUNCTION"));
        if (self::$wafToken === null) {
            self::$wafToken = self::loadWafToken($config);
        }
        if (self::$wafToken !== null) {
            curl_setopt($this->ch, CURLOPT_COOKIE, "aws-waf-token=" . self::$wafToken);
        }

        //use HTTP-Proxy
        if ($config->use_proxy === true) {
            curl_setopt($this->ch, CURLOPT_PROXY, $config->proxy_host);
            curl_setopt($this->ch, CURLOPT_PROXYPORT, $config->proxy_port);

            //Login credentials set?
            if (!empty($config->proxy_user) && !empty($config->proxy_pw)) {
                curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
                curl_setopt($this->ch, CURLOPT_PROXYUSERPWD, $config->proxy_user . ':' . $config->proxy_pw);
            }
        }

        $this->urltoopen = $url;

        $this->addHeaderLine('Referer', 'https://' . $config->imdbsite . '/');

        $this->userAgent = $config->force_agent ?: $config->default_agent;
        curl_setopt($this->ch, CURLOPT_USERAGENT, $this->userAgent);
        if ($config->language) {
            $this->addHeaderLine('Accept-Language', $config->language);
        }
        if ($config->ip_address) {
            $this->addHeaderLine('X-Forwarded-For', $config->ip_address);
        }
    }

    public function addHeaderLine($name, $value)
    {
        $this->requestHeaders[] = "$name: $value";
    }

    /**
     * Send a POST request
     *
     * @param string|array $content
     * @return boolean success
     * @throws Exception\Http
     */
    public function post($content)
    {
        $this->postContent = $content;
        curl_setopt($this->ch, CURLOPT_POST, true);
        curl_setopt($this->ch, CURLOPT_POSTFIELDS, $content);
        return $this->sendRequest();
    }

    /**
     * Send a request to the movie site
     * @return boolean success
     * @throws Exception\Http
     */
    public function sendRequest()
    {
        $this->responseHeaders = array();
        curl_setopt($this->ch, CURLOPT_HTTPHEADER, $this->requestHeaders);
        $this->page = curl_exec($this->ch);
        $httpCode = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
        curl_close($this->ch);

        if ($this->page === false) {
            if ($this->config->throwHttpExceptions) {
                throw new Exception\Http("Failed fetch url [$this->urltoopen] " . curl_error($this->ch));
            }
            return false;
        }

        if ($httpCode == 202) {
            return $this->solveAwsChallenge();
        }

        return true;
    }

    private function fetchChallengeHtml()
    {
        $ch = curl_init('https://' . $this->config->imdbsite . '/');
        curl_setopt($ch, CURLOPT_ENCODING, "");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->userAgent);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language: en-US,en;q=0.9',
            'cache-control: no-cache',
            'pragma: no-cache',
            'sec-ch-ua: "Chromium";v="144", "Google Chrome";v="144"',
            'sec-ch-ua-mobile: ?0',
            'sec-ch-ua-platform: "macOS"',
            'sec-fetch-dest: document',
            'sec-fetch-mode: navigate',
            'sec-fetch-site: none',
            'upgrade-insecure-requests: 1',
        ));
        if ($this->config->use_proxy === true) {
            curl_setopt($ch, CURLOPT_PROXY, $this->config->proxy_host);
            curl_setopt($ch, CURLOPT_PROXYPORT, $this->config->proxy_port);
            if (!empty($this->config->proxy_user) && !empty($this->config->proxy_pw)) {
                curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
                curl_setopt($ch, CURLOPT_PROXYUSERPWD, $this->config->proxy_user . ':' . $this->config->proxy_pw);
            }
        }
        $html = curl_exec($ch);
        curl_close($ch);
        return $html;
    }

    private function solveAwsChallenge()
    {
        for ($attempt = 0; $attempt < $this->maxChallengeRetries; $attempt++) {
            $challengeHtml = $this->page;
            if (empty($challengeHtml) || strpos($challengeHtml, 'window.gokuProps') === false) {
                $challengeHtml = $this->fetchChallengeHtml();
            }
            if (empty($challengeHtml) || strpos($challengeHtml, 'window.gokuProps') === false) {
                continue;
            }
            $aws = new Aws($this->userAgent, $this->config->imdbsite, $this->config);
            $token = $aws->solve($challengeHtml);
            if (empty($token)) {
                continue;
            }

            $this->ch = curl_init($this->urltoopen);
            curl_setopt($this->ch, CURLOPT_ENCODING, "");
            curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($this->ch, CURLOPT_HEADERFUNCTION, array(&$this, "callback_CURLOPT_HEADERFUNCTION"));
            curl_setopt($this->ch, CURLOPT_USERAGENT, $this->userAgent);
            curl_setopt($this->ch, CURLOPT_COOKIE, "aws-waf-token=" . $token);
            curl_setopt($this->ch, CURLOPT_HTTPHEADER, $this->requestHeaders);
            if ($this->postContent !== null) {
                curl_setopt($this->ch, CURLOPT_POST, true);
                curl_setopt($this->ch, CURLOPT_POSTFIELDS, $this->postContent);
            }

            if ($this->config->use_proxy === true) {
                curl_setopt($this->ch, CURLOPT_PROXY, $this->config->proxy_host);
                curl_setopt($this->ch, CURLOPT_PROXYPORT, $this->config->proxy_port);
                if (!empty($this->config->proxy_user) && !empty($this->config->proxy_pw)) {
                    curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
                    curl_setopt($this->ch, CURLOPT_PROXYUSERPWD, $this->config->proxy_user . ':' . $this->config->proxy_pw);
                }
            }

            $this->responseHeaders = array();
            $this->page = curl_exec($this->ch);
            $retryCode = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
            curl_close($this->ch);

            if ($this->page !== false && $retryCode != 202) {
                self::$wafToken = $token;
                self::saveWafToken($token, $this->config);
                return true;
            }
        }

        return true;
    }

    /**
     * Get the Response body
     * @return string page
     */
    public function getResponseBody()
    {
        return $this->page;
    }

    /**
     * Set the URL we need to parse
     * @param string $url
     */
    public function setURL($url)
    {
        $this->urltoopen = $url;
        curl_setopt($this->ch, CURLOPT_URL, $url);
    }

    /**
     * Get a header value from the response
     * @param string $header header field name
     * @return string header value
     */
    public function getResponseHeader($header)
    {
        $headers = $this->getLastResponseHeaders();
        foreach ($headers as $head) {
            if (is_integer(stripos($head, $header))) {
                $hstart = strpos($head, ": ");
                $head = trim(substr($head, $hstart + 2, 100));
                return $head;
            }
        }
        return '';
    }

    /**
     * HTTP status code of the last response
     * @return int|null null if last request failed
     */
    public function getStatus()
    {
        $headers = $this->getLastResponseHeaders();
        if (empty($headers[0])) {
            return null;
        }

        if (!preg_match("#^HTTP/[\d\.]+ (\d+)#i", $headers[0], $matches)) {
            return null;
        }

        return (int)$matches[1];
    }

    /**
     * Get the URL to redirect to if a 30* was returned
     * @return string|null URL to redirect to if 300, otherwise null
     */
    public function getRedirect()
    {
        $status = $this->getStatus();
        if ($status == 301 || $status == 302 || $status == 303 || $status == 307 || $status == 308) {
            foreach ($this->getLastResponseHeaders() as $header) {
                if (strpos(trim(strtolower($header)), 'location') !== 0) {
                    continue;
                }
                $aline = explode(': ', $header);
                $target = trim($aline[1]);
                $urlParts = parse_url($target);
                if (!isset($urlParts['host'])) {
                    $initialRequestUrlParts = parse_url($this->urltoopen);
                    $target = $initialRequestUrlParts['scheme'] . "://" . $initialRequestUrlParts['host'] . $target;
                }
                return $target;
            }
        }
        return null;
    }

    public function getLastResponseHeaders()
    {
        return $this->responseHeaders;
    }

    private function callback_CURLOPT_HEADERFUNCTION($ch, $str)
    {
        $len = strlen($str);
        if ($len) {
            $this->responseHeaders[] = $str;
        }
        return $len;
    }

    private static function wafTokenPath(Config $config)
    {
        $dir = !empty($config->cachedir) && is_dir($config->cachedir)
            ? $config->cachedir
            : sys_get_temp_dir();
        return rtrim($dir, '/') . '/imdb_waf_token';
    }

    private static function loadWafToken(Config $config)
    {
        $path = self::wafTokenPath($config);
        if (file_exists($path) && (time() - filemtime($path)) < 280) {
            return file_get_contents($path);
        }
        return null;
    }

    private static function saveWafToken($token, Config $config)
    {
        @file_put_contents(self::wafTokenPath($config), $token);
    }
}
