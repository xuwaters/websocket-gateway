## websocket gateway

A gateway that translates websocket connections to tcp connections transparently.

### build

```bash
gem install thor
thor cli:build
```


### usage

Clients that setup a connection to gate on path ```/gate/{target:[a-zA-Z0-9.-_:]+}```, will be proxied to backend tcp server specified by ```${target}``` in configuration.

For example, if configuration is:
```
// supports comment line starting with '//'
{
  // __default__ is a special configuration that all other configuration will inherit from it
  // if some field is missing in other configuration, field in __default__ will be used.
  "__default__" : {
    "ssl": false
  },
  "api.example.com" : {
    "ip": "192.168.0.100",
    // only these ports will be proxied
    "port": "80,443,1024-30000",
    // whether connect backend server via ssl
    "ssl": true
  }
}
```

A client that connects to ```/gate/api.example.com:80``` via websocket protocol, will be proxied to ```192.168.0.100:80``` and the data received from websocket will be transfered via tcp protocol to backend.

And if client is flashplayer, it may request for a policy file, this gateway can return a policy file to make flashplayer happy. This policy file is also configurable.


```
Usage of ./bin/wsgate (version 1.0.2):
  -addr string
    	Service Address (default "127.0.0.1:8080")
  -connect-target-timeout duration
    	maxium timeout connecting to game (default 2s)
  -fetch-interval duration
    	Server list fetch interval (default 30s)
  -help
    	print help message
  -idle-timeout duration
    	Maximum time a request could idle (default 1m0s)
  -insecure-skip-verify
    	Skip verify tls connection certificates (default true)
  -policy-file string
    	Policy file, will be reloaded on receiving signal SIGUSR1. If empty, default policy is: 
      <?xml version="1.0"?>
    	<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    	<cross-domain-policy>
    	  <allow-access-from domain="*" to-ports="80-32767" />
    	</cross-domain-policy>
  -policy-idle-timeout duration
    	Maximum time a request for policy should take (default 3s)
  -profile-addr string
    	pprof service address, empty string disables profiling (default "127.0.0.1:6060")
  -serverlist string
    	server list json file path or url of configuration
  -tls-cert-file string
    	TLS certificate file; cert and key files will be reloaded on receiving signal SIGUSR1
  -tls-key-file string
    	TLS key file
  -version
    	print version number

- Samle serverlist.json

// supports comment line starting with '//'
{
  "__default__" : {
    "ssl": false
  },
  "api.example.com" : {
    "ip": "192.168.0.100",
    "port": "80,443,1024-30000",
    "ssl": true
  }
}
```

