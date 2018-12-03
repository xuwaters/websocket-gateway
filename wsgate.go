package main

import (
	"io"
	"context"
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/soheilhy/cmux"
  "golang.org/x/net/websocket"

)

// Version number of current program
const Version = "1.0.2"

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
- Samle serverlist.json

// supports comment line starting with '//'
{
  "__default__" : {
    "ssl": false
  },
  "api.example.com" : {
    "ip": "192.168.0.23",
    "port": "80,443,1024-30000",
    "ssl": true
  }
}
`)
}

// ServerMapping data
type ServerMapping struct {
	IP         *string `json:"ip"`
	Ports      *string `json:"port"`
	SSL        *bool   `json:"ssl"`
	PortRanges [][]int `json:"port_ranges"` // parsed from ports
}

// ServerListMapping data
type ServerListMapping map[string]*ServerMapping

// serverlist
const (
	DefaultHost  = "__defaults__"
	MaxPortValue = 0xffff
)

const (
	// PolicyRequest request string from flash
	PolicyRequest = "<policy-file-request/>\000"
	// PolicyResponse default response
	PolicyResponse = `<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <allow-access-from domain="*" to-ports="80-32767" />
</cross-domain-policy>`
)

var (
	gServerListMapping     ServerListMapping
	gServerListMutex       = &sync.RWMutex{}
	gInsecureSkipVerify    = true
	gConnectionIdleTimeout time.Duration
	gConnectTargetTimeout  time.Duration

	gFetchInterval time.Duration
	gServerListURL string

	gPolicyIdleTimeout time.Duration
	gPolicyFile        string

	gProfileAddr = ""
)

func main() {
	flag.Usage = usage

	// arguments
	var (
		serviceAddress string
		certFile       string
		keyFile        string
		printHelp      bool
		printVersion   bool
	)

	flag.BoolVar(&printHelp, "help", false, "print help message")
	flag.BoolVar(&printVersion, "version", false, "print version number")
	flag.StringVar(&serviceAddress, "addr", "127.0.0.1:8080", "Service Address")
	flag.StringVar(&certFile, "tls-cert-file", "", "TLS certificate file; cert and key files will be reloaded on receiving signal SIGUSR1")
	flag.StringVar(&keyFile, "tls-key-file", "", "TLS key file")

	flag.DurationVar(&gFetchInterval, "fetch-interval", 30*time.Second, "Server list fetch interval")
	flag.StringVar(&gServerListURL, "serverlist", "", "server list json file path or url of configuration")
	flag.DurationVar(&gConnectionIdleTimeout, "idle-timeout", 1*time.Minute, "Maximum time a request could idle")
	flag.DurationVar(&gConnectTargetTimeout, "connect-target-timeout", 2*time.Second, "maxium timeout connecting to game")
	flag.BoolVar(&gInsecureSkipVerify, "insecure-skip-verify", true, "Skip verify tls connection certificates")

	flag.DurationVar(&gPolicyIdleTimeout, "policy-idle-timeout", 3*time.Second, "Maximum time a request for policy should take")
	flag.StringVar(&gPolicyFile, "policy-file", "", "Policy file, will be reloaded on receiving signal SIGUSR1. If empty, default policy is: "+PolicyResponse)

	flag.StringVar(&gProfileAddr, "profile-addr", "127.0.0.1:6060", "pprof service address, empty string disables profiling")

	flag.Parse()
	if !flag.Parsed() || printHelp {
		flag.Usage()
		return
	}

	if printVersion {
		fmt.Printf("%s\n", Version)
		return
	}

	if gServerListURL == "" {
		flag.Usage()
		return
	}

	// start profiling
	go serveProfilingService()

	log.Printf("starting wsgate server, addr = %s\n", serviceAddress)

	// listen
	listener, err := listen(serviceAddress, certFile, keyFile)
	if err != nil {
		log.Fatalf("Can not listen on address %s, err = %v\n", serviceAddress, err)
		return
	}
	defer listener.Close()

	// mux
	m := cmux.New(listener)
	m.SetReadTimeout(gConnectionIdleTimeout)

  // mux flash policy file request and tcp request
	httpListener := m.Match(cmux.HTTP1Fast())
	tcpListener := m.Match(cmux.Any())

	go servePolicyService(tcpListener)
	go serveAgentService(httpListener)

	m.Serve()
}

func listen(serviceAddress string, certFile string, keyFile string) (listener net.Listener, err error) {
	if len(certFile) == 0 || len(keyFile) == 0 {
		log.Printf("tls not configured, listening in non-tls mode")
		listener, err = net.Listen("tcp", serviceAddress)
	} else {
		var reloader *CertReloader
		reloader, err = NewCertReloader(context.Background(), certFile, keyFile, syscall.SIGUSR1)
		if err != nil {
			log.Fatalf("load keypair failure: %v\n", err)
			return
		}
		config := &tls.Config{}
		config.GetCertificate = reloader.CreateGetCertificateFunc()
		listener, err = tls.Listen("tcp", serviceAddress, config)
	}
	return
}

//////////////////////// Profile //////////////////
func serveProfilingService() {
	if gProfileAddr == "" {
		log.Println("empty profile-addr, ignore")
		return
	}
	log.Printf("start profiling service: %s\n", gProfileAddr)
	log.Println(http.ListenAndServe(gProfileAddr, nil))
}

//////////////////////// Unkown Service ////////////////////
func serveUnknownService(listener net.Listener) {
	log.Printf("staring unkown service\n")
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("unknown service: Error accepting new connection.\n")
			continue
		}
		log.Printf("unknown service: close connection: %v\n", client.RemoteAddr())
		client.Close()
	}
}

//////////////////////// Policy Service ////////////////////

func servePolicyService(listener net.Listener) {
	log.Printf("starting policy service\n")

	defaultResponse := append([]byte(PolicyResponse), 0)

	// reading policy content
	getResponseContent := func() []byte {
		return defaultResponse
	}

	if len(gPolicyFile) > 0 {
		reloader, err := NewFileReloader(gPolicyFile, syscall.SIGUSR1)
		if err != nil {
			log.Printf("load policy file failure, ignore: %s\n", gPolicyFile)
		} else {
			getFileContent := reloader.GetFileContentFunc()
			getResponseContent = func() []byte {
				content := getFileContent()
				if content != nil {
					content = append(content, 0)
				}
				return content
			}
		}
	}

	currContent := getResponseContent()
	log.Printf("current policy: %s\n", string(currContent))

	// serve
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting new connection.\n")
			continue
		}
		go servePolicy(client, gPolicyIdleTimeout, getResponseContent)
	}
}

func servePolicy(c net.Conn, timeout time.Duration, getResponseContent func() []byte) {
	defer c.Close()

	c.SetDeadline(time.Now().Add(timeout))

	reqBuf := make([]byte, len(PolicyRequest))
	n, err := io.ReadFull(c, reqBuf)
	if err != nil && err != io.EOF {
		log.Printf("Error reading reqeust: %v, %v\n", c.RemoteAddr(), err)
		return
	}
	reqBuf = reqBuf[:n]
	if !bytes.Equal(reqBuf, []byte(PolicyRequest)) {
		log.Printf("Invalid request from %v, payload = %v, hex = %v\n", c.RemoteAddr(), string(reqBuf), reqBuf)
		return
	}

	responseContent := getResponseContent()

	_, err = c.Write(responseContent)
	if err != nil {
		log.Printf("Error writing response: %v, %v\n", c.RemoteAddr(), err)
		return
	}
	log.Printf("Response to %v: %v\n", c.RemoteAddr(), string(responseContent))
}

////////////////////// Agent Service //////////////////

func serveAgentService(listener net.Listener) {
	r := mux.NewRouter()
	r.Handle("/gate/{target:[a-zA-Z0-9.-_:]+}", websocket.Handler(gateProxyHandler))

	// handle with mux
	http.Handle("/", r)

	// fetch server list
	go fetchServerListPeriodically(gServerListURL, gFetchInterval)

	log.Printf("starting agent service")
	http.Serve(listener, nil)
}

func gateProxyHandler(ws *websocket.Conn) {
	remoteAddr := ws.RemoteAddr()
	req := ws.Request()
	vars := mux.Vars(req)
	log.Printf("handling data from client = %s, url = %s, var = %#v\n", remoteAddr, req.RequestURI, vars)
	if vars == nil {
		log.Printf(" vars empty, client = %s, url = %s\n", remoteAddr, req.RequestURI)
		return
	}
	targetServer, found := vars["target"]
	if !found {
		log.Printf(" target host not found, client = %s, url = %s\n", remoteAddr, req.RequestURI)
		return
	}

	// find target server and connect
	upstream, err := connectTargetServer(targetServer, gConnectTargetTimeout)
	if err != nil {
		log.Printf("connect to target server failure: %s, err = %v\n", targetServer, err)
		return
	}
	defer upstream.Close()
	log.Printf("connected to target server: %s, client = %s\n", targetServer, remoteAddr)

	// read from upstream
	go pumpUpstreamToDownstream(upstream, ws)

	// read from downstream
	pumpDownstreamToUpstream(ws, upstream)
}

// server list
func connectTargetServer(targetServer string, timeout time.Duration) (conn net.Conn, err error) {
	// address translation
	var useSSL bool
	targetServer, useSSL, err = convertServerAddress(targetServer)
	if err != nil {
		return
	}

	dialer := &net.Dialer{Timeout: timeout}
	if useSSL {
		config := &tls.Config{
			InsecureSkipVerify: gInsecureSkipVerify,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", targetServer, config)
	} else {
		conn, err = dialer.Dial("tcp", targetServer)
	}
	return
}

// socket client
func pumpUpstreamToDownstream(upstream net.Conn, ws *websocket.Conn) {
	in := make([]byte, 1024)
	for {
		n, err := upstream.Read(in)
		if err != nil {
			log.Printf("read from upstream err = %v\n", err)
			ws.Close()
			return
		}
		if err := websocket.Message.Send(ws, in[:n]); err != nil {
			log.Printf("write to downstream err = %v\n", err)
			upstream.Close()
			return
		}
	}
}

func pumpDownstreamToUpstream(ws *websocket.Conn, upstream net.Conn) {
	for {
		var in []byte
		if err := websocket.Message.Receive(ws, &in); err != nil {
			log.Printf("read from downstream error %v\n", err)
			upstream.Close()
			return
		}
		//log.Printf("received data = %v\n", in)
		if _, err := upstream.Write(in); err != nil {
			log.Printf("write to upstream error %v\n", err)
			ws.Close()
			return
		}
	}
}

// fetch serverlist.json

func fetchServerListPeriodically(serverListURL string, fetchInterval time.Duration) {
	for {
		mapping, err := readServerListContent(serverListURL)
		if err != nil {
			log.Printf("read serverlist url '%s', error = %v\n", serverListURL, err)
		} else {
			swapServerListMapping(mapping)
		}
		time.Sleep(fetchInterval)
	}
}

var (
	hostRegex, _ = regexp.Compile(`[a-zA-Z0-9.-_]+`)
	portRegex, _ = regexp.Compile(`[0-9]+`)
)

func convertServerAddress(serverAddress string) (translatedAddress string, useSSL bool, err error) {
	gServerListMutex.RLock()
	defer gServerListMutex.RUnlock()

	//
	serverAddress = strings.TrimSpace(serverAddress)
	parts := strings.SplitN(serverAddress, ":", 3)

	// format
	if len(parts) != 2 || hostRegex.MatchString(parts[0]) == false || portRegex.MatchString(parts[1]) == false {
		err = fmt.Errorf("serverAddress '%s' format error", serverAddress)
		return
	}

	host := parts[0]
	portStr := parts[1]
	// port range
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > MaxPortValue {
		err = fmt.Errorf("serverAddress '%s' port value out of range", serverAddress)
		return
	}
	// find in mapping
	sm, ok := gServerListMapping[host]
	if !ok {
		err = fmt.Errorf("serverAddress '%s' host not found in mapping", serverAddress)
		return
	}
	// check ranges
	for _, rng := range sm.PortRanges {
		if rng[0] <= port && port <= rng[1] {
			// found
			translatedAddress = fmt.Sprintf("%s:%d", *sm.IP, port)
			useSSL = *sm.SSL
			err = nil
			return
		}
	}
	// not found
	err = fmt.Errorf("serverAddress '%s' port not found in mapping", serverAddress)
	return
}

func swapServerListMapping(mapping ServerListMapping) {
	gServerListMutex.Lock()
	defer gServerListMutex.Unlock()

	gServerListMapping = mapping

	str, _ := json.Marshal(mapping)
	log.Printf("swap mapping = %s\n", str)
}

func readServerListContent(serverListURL string) (mapping ServerListMapping, err error) {
	var content []byte
	if strings.HasPrefix(serverListURL, "http://") || strings.HasPrefix(serverListURL, "https://") {
		var resp *http.Response
		if resp, err = http.Get(serverListURL); err != nil {
			return
		}
		if content, err = ioutil.ReadAll(resp.Body); err != nil {
			return
		}
	} else {
		// read file
		if content, err = ioutil.ReadFile(serverListURL); err != nil {
			return
		}
	}
	// trim comments
	content = trimComments(content)
	//
	if err = json.Unmarshal(content, &mapping); err != nil {
		return
	}
	// post process
	err = parseMappingPortRanges(mapping)
	return
}

func parseMappingPortRanges(mapping ServerListMapping) (err error) {
	def, ok := mapping[DefaultHost]
	if ok {
		delete(mapping, DefaultHost)
	}
	for k, v := range mapping {
		// update using default
		if ok {
			if def.IP != nil && v.IP == nil {
				v.IP = def.IP
			}
			if def.Ports != nil && v.Ports == nil {
				v.Ports = def.Ports
			}
			if def.SSL != nil && v.SSL == nil {
				v.SSL = def.SSL
			}
		}
		// at last, check nil
		if v.IP == nil || v.Ports == nil || v.SSL == nil {
			log.Printf("ignoring host: %s, missing 'ip', 'port' or 'ssl' fields\n", k)
			delete(mapping, k)
			continue
		}
		//
		if v.PortRanges, err = parsePortRanges(*v.Ports); err != nil {
			log.Printf("ignoring host: %s, port range parsing error = %v\n", k, err)
			delete(mapping, k)
			continue
		}
	}
	return
}

func parsePortRanges(ports string) (ranges [][]int, err error) {
	parts := strings.Split(ports, ",")
	ranges = make([][]int, 0)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) == 0 {
			continue
		}
		rng := strings.SplitN(part, "-", 3)
		var from, to int
		if len(rng) >= 1 {
			rng[0] = strings.TrimSpace(rng[0])
			if from, err = strconv.Atoi(rng[0]); err != nil {
				ranges = nil
				return
			}
			to = from
		}
		if len(rng) >= 2 {
			rng[1] = strings.TrimSpace(rng[1])
			if to, err = strconv.Atoi(rng[1]); err != nil {
				ranges = nil
				return
			}
		}
		// value range
		if from <= 0 || from > MaxPortValue || to <= 0 || to > MaxPortValue {
			ranges = nil
			err = fmt.Errorf("port value out of range: '%s'", part)
			return
		}
		// good
		ranges = append(ranges, []int{from, to})
	}
	return
}

func trimComments(content []byte) []byte {
	inbuf := bytes.NewBuffer(content)
	outbuf := bytes.NewBuffer(nil)

	scanner := bufio.NewScanner(inbuf)
	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)
		if len(trimmedLine) == 0 || strings.HasPrefix(trimmedLine, "//") {
			continue
		}
		fmt.Fprintln(outbuf, line)
	}

	return outbuf.Bytes()
}
