<?php

declare(strict_types=1);

namespace Tym\Websocket;

/**
 * @author Yvan Tchuente <yvantchuente@gmail.com>
 */
class Server
{
    /**
     * Globally Unique Identifier.
     */
    public const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    /**
     * The port number.
     */
    private int $port;

    /**
     * The IP address.
     */
    private string $address;

    /**
     * The server hostname.
     */
    private string $hostname;

    /**
     * The server socket.
     */
    private ?\Socket $socket = null;

    /**
     * List of endpoints served by the server.
     * 
     * @var string[]
     */
    private array $services = [];

    /**
     * The origin hosts from which to incoming requests shall be accepted.
     */
    private array $origins = [];

    /**
     * List of connected client sockets.
     *
     * @var \Socket[]
     */
    private array $clients = [];

    /**
     * Initializes the server.
     * 
     * @param string $address The IP address (in dotted-quad notation) to bind to the server.
     * @param int $port The port on which the server shall listen for incoming connections.
     * @param string $hostname The server hostname.
     * @param string[] $services The list of services provided by the server, these are the the endpoints served by the server.
     * 
     * @throws \Exception if an error occurs.
     */
    public function __construct(
        string $address,
        int $port,
        string $hostname,
        array $services
    ) {
        if (!preg_match('/(\d{1,3}(\b|\.)){4}/', $address)) {
            throw new \InvalidArgumentException("[$address] is not a valid IP address.");
        }
        if ($port >= 1023 && $port <= 65536) {
            throw new \DomainException("Well-known ports are not accepted.");
        }
        if (!$hostname) {
            throw new \LengthException("Empty hostnames are not accepted.");
        }
        if (!$services) {
            throw new \LengthException("The server's services were not provided.");
        }

        $this->port = $port;
        $this->address = $address;
        $this->hostname = $hostname;
        $this->services = $services;
    }

    /**
     * Start the server.
     */
    public function start()
    {
        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 1);
        socket_bind($socket, $this->address, $this->port);
        socket_listen($socket);

        $this->socket = $socket;
    }

    /**
     * Stop the server.
     */
    public function stop()
    {
        if (isset($this->socket)) {
            socket_close($this->socket);
            $this->socket = null;
        }
    }

    /**
     * Get the server socket.
     */
    public function getSocket()
    {
        return $this->socket;
    }

    /**
     * Adds an origin host from which incoming requests shall be accepted.
     */
    public function addOrigin(string $hostname)
    {
        if (!filter_var($hostname, FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException("The hostname is not valid.");
        }

        $this->origins[] = $hostname;
        return $this;
    }

    /**
     * Establishes the websocket connection with a remote host.
     * 
     * @param string $handshake The remote host's opening handshake.
     * @param \Socket $host The remote host's socket.
     * 
     * @return bool
     */
    public function connect(string $handshake, \Socket $host)
    {
        if (!$this->acceptHandshake($handshake)) {
            $response = "HTTP/1.1 400 Bad Request\r\n" . "Connection: close\r\n";
            socket_write($host, $response, strlen($response));
            return false;
        }

        $endpoint = $this->getRequestLine($handshake)['endpoint'];
        if (!$this->isService($endpoint)) {
            $response = "HTTP/1.1 404 Not Found\r\n" . "Connection: close\r\n";
            socket_write($host, $response, strlen($response));
            return false;
        }

        $headers = $this->getHeaders($handshake);
        $origin = $headers['Origin'];
        switch (true) {
            case ($this->origins && !$origin):
            case ($this->origins && !in_array($origin, $this->origins, true)):
                $response = "HTTP/1.1 403 Forbidden";
                socket_write($host, $response, strlen($response));
                return false;
                break;
        }

        $secKey = $headers['Sec-WebSocket-Key'];
        $secAccept_key = base64_encode(pack(
            'H*',
            sha1($secKey . self::GUID)
        ));
        $server_upgrade_headers  = "HTTP/1.1 101 Switching Protocols\r\n" .
            "Upgrade: websocket\r\n" .
            "Connection: Upgrade\r\n" .
            "Sec-WebSocket-Version: 13\r\n" .
            "Sec-WebSocket-Accept:$secAccept_key\r\n\r\n";
        socket_write($host, $server_upgrade_headers, strlen($server_upgrade_headers));

        // Register the client socket
        $this->clients[] = $host;

        return true;
    }

    /**
     * Closes the websocket connection with a remote host.
     *
     * @param int $code The status code.
     * @param string $reason The close reason.
     */
    public function disconnect(\Socket $host, int $code, string $reason = "")
    {
        $message = pack('I', $code) . $reason;
        $this->send($host, 'close', $message);
        socket_shutdown($host);
        socket_close($host);
    }

    /**
     * Gets the list of connected hosts.
     */
    public function getClients()
    {
        return $this->clients;
    }

    /**
     * Sends a data frame to a remote host.
     * 
     * @param \Socket $client The remote host's socket.
     * @param string $type The data frame type.
     * @param string|\Stringable $data The piece of data.
     * 
     * @return bool
     * 
     * @throws \DomainException If type is not a valid frame type.
     */
    public function send(\Socket $client, string $type, string $data)
    {
        $encoded_data = $this->encode($type, $data);
        return (bool) socket_write($client, $encoded_data, strlen($encoded_data));
    }

    /**
     * Broadcasts a data frame to a given list of connected hosts.
     * 
     * @param \Socket[] $clients A list of connected client sockets.
     * @param string $type The type of the data frame.
     * @param string $data The data frame.
     */
    public function broadcast(array $clients, string $type, string $data)
    {
        foreach ($clients as $client) {
            $this->send($client, $type, $data);
        }
    }

    /**
     * Masks a data frame to send over a websocket connection.
     * 
     * @param string $type The data type.
     * @param string|Stringable $data The data.
     * 
     * @throws \DomainException if the given type is not a valid.
     */
    public function encode(string $type, string|\Stringable $data)
    {
        if (!in_array($type, ['text', 'binary', 'close', 'ping', 'pong'])) {
            throw new \DomainException("Invalid frame type");
        }

        switch ($type) {
            case 'text':
                $byte1 = 0x81; // 1000 0001
                break;
            case 'binary':
                $byte1 = 0x82; // 1000 0010
                break;
            case 'close':
                $byte1 = 0x88; // 1000 1000 
                break;
            case 'ping':
                $byte1 = 0x89; // 1000 1001 
                break;
            case 'pong':
                $byte1 = 0x8A; // 1000 1010
                break;
        }

        $length = strlen($data);
        if ($length <= 125) {
            $header = pack('C*', $byte1, $length);
        } elseif ($length > 125 && $length < 65536) {
            $header = pack('CCn', $byte1, 126, $length);
        } elseif ($length >= 65536) {
            $header = pack('CCN', $byte1, 127, $length);
        }

        return $header . $data;
    }

    /**
     * Unmasks a data frame sent over a websocket connection.
     * 
     * @param string $frame The masked data frame.
     */
    public function decode(string $frame)
    {
        $length = ord($frame[1]) & 127;
        if ($length == 126) {
            $masks = substr($frame, 4, 4);
            $data = substr($frame, 8);
        } elseif ($length == 127) {
            $masks = substr($frame, 10, 4);
            $data = substr($frame, 14);
        } else {
            $masks = substr($frame, 2, 4);
            $data = substr($frame, 6);
        }

        $frame = "";
        for ($i = 0; $i < strlen($data); ++$i) {
            $frame .= $data[$i] ^ $masks[$i % 4];
        }

        return $frame;
    }

    /**
     * Retrieves the request line from the given client opening handshake.
     *
     * @return array An array of request method, request endpoint and version.
     * 
     * @throws \RuntimeException If an invalid HTTP method or version is found in the request line.
     */
    public function getRequestLine(string $handshake)
    {
        $requestLine = preg_split("/\r\n/", $handshake)[0];
        $parts = explode(" ", $requestLine);

        if (!preg_match('/^GET$/', $parts[0])) {
            throw new \RuntimeException("Invalid request: invalid HTTP request method. It must be a GET method");
        } elseif (!preg_match('/^HTTP\/\d\.\d$/', $parts[2])) {
            throw new \RuntimeException("Invalid request: invalid HTTP version");
        }

        return [
            'method' => $parts[0], 'endpoint' => $parts[1], 'version' => $parts[2]
        ];
    }

    /**
     * Retrieves query paramaters if any present in the given client opening handshake.
     * 
     * @return array|null
     */
    public function getQueryParams(string $handshake)
    {
        $requestLine = $this->getRequestLine($handshake);

        if (preg_match('/\?(\S+)=(.*)/', $requestLine['endpoint'], $matches)) {
            $query[$matches[1]] = $matches[2];
        }
        if (isset($query)) {
            return $query;
        } else {
            return null;
        }
    }

    /**
     * Tells whether the server accepts a given client opening handshake. 
     *
     * @return bool
     */
    private function acceptHandshake(string $handshake)
    {
        $headers = $this->getHeaders($handshake);

        $host = $headers['Host'];
        $upgrade = $headers['Upgrade'];
        $connection = $headers['Connection'];
        $secKey = $headers['Sec-WebSocket-Key'];
        $secVersion = (int) $headers['Sec-WebSocket-Version'];

        if (empty($host) || !preg_match("/" . $this->hostname . "/", $host)) {
            return false;
        }
        if (empty($upgrade) || !preg_match('/^websocket$/i', $upgrade)) {
            return false;
        }
        if (empty($connection) || !preg_match('/Upgrade/i', $connection)) {
            return false;
        }
        if (empty($secKey) || strlen(base64_decode($secKey)) !== 16) {
            return false;
        }
        if (empty($secVersion) || $secVersion !== 13) {
            return false;
        }

        return true;
    }

    /**
     * Retrieves the header fields of a given remote host opening handshake.
     *
     * @return string[] A list of header fields.
     */
    private function getHeaders(string $handshake)
    {
        $lines = preg_split("/\r\n/", $handshake);

        // Client handshake headers
        foreach ($lines as $line) {
            $line = rtrim($line);
            if (preg_match('/(\S+): (.*)/', $line, $matches)) {
                $headers[$matches[1]] = $matches[2];
            }
        }

        return $headers;
    }

    /**
     * Determines whether a given endpoint is served by the server.
     */
    private function isService(string $endpoint)
    {
        $services = array_filter($this->services, function ($service) use ($endpoint) {
            $service = preg_quote($service, '/');
            if (preg_match("/^$service(\?(\w+(=.+)?&?)+)?$/", $endpoint)) {
                return true;
            }
        });

        return boolval(count($services));
    }
}
