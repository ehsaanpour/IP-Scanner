package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/atotto/clipboard"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/ehsaanpour/IP-Scanner/internal/engine"
	"github.com/ehsaanpour/IP-Scanner/internal/ipsrc"
	"github.com/ehsaanpour/IP-Scanner/internal/output"
	"github.com/ehsaanpour/IP-Scanner/internal/prober"
	"github.com/ehsaanpour/IP-Scanner/internal/result"
	"github.com/ehsaanpour/IP-Scanner/pkg/version"
)

// CustomScanConfig holds all parameters for a custom scan
type CustomScanConfig struct {
	Count      int    `json:"count"`
	Workers    int    `json:"workers"`
	Timeout    string `json:"timeout"`
	Tries      int    `json:"tries"`
	Port       int    `json:"port"`
	CIDR       string `json:"cidr"`
	OutputFile string `json:"outputFile"`
	ColoFilter string `json:"coloFilter"`
	SNI        string `json:"sni"`
	Mode       string `json:"mode"`
	UseV4      bool   `json:"useV4"`
	UseV6      bool   `json:"useV6"`
	Config     string `json:"config"`
	MinSpeed   string `json:"minSpeed"`
	SpeedURL   string `json:"speedURL"`
	SpeedSize  string `json:"speedSize"`
	Upload     bool   `json:"upload"`
}

// FrontendResult holds a JSON-serializable result representation
type FrontendResult struct {
	IP         string  `json:"ip"`
	Loss       float64 `json:"loss"`
	Avg        float64 `json:"avg"`
	Min        float64 `json:"min"`
	Max        float64 `json:"max"`
	Jitter     float64 `json:"jitter"`
	Speed      float64 `json:"speed"` // KB/s
	Colo       string  `json:"colo"`
	TLSOk      bool    `json:"tlsOk"`
	HTTPStatus int     `json:"httpStatus"`
	IsHealthy  bool    `json:"isHealthy"`
}

// App struct
type App struct {
	ctx        context.Context
	scanCancel context.CancelFunc
	scanMutex  sync.Mutex
	isScanning bool
}

// NewApp creates a new App struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// GetVersion returns the version string of the scanner
func (a *App) GetVersion() string {
	return version.String()
}

// OpenGitHub opens the GitHub repository in the default browser
func (a *App) OpenGitHub() {
	runtime.BrowserOpenURL(a.ctx, "https://github.com/ehsaanpour/IP-Scanner")
}

// CopyToClipboard copies the given text to the system clipboard
func (a *App) CopyToClipboard(text string) bool {
	err := clipboard.WriteAll(text)
	return err == nil
}

// SelectFile opens a native save or open file dialog
func (a *App) SelectFile(title string, filterPattern string, save bool) string {
	var path string
	var err error

	filters := []runtime.FileFilter{
		{DisplayName: "Supported Files", Pattern: filterPattern},
		{DisplayName: "All Files", Pattern: "*.*"},
	}

	if save {
		path, err = runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
			Title:           title,
			Filters:         filters,
			DefaultFilename: "results.csv",
		})
	} else {
		path, err = runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
			Title:   title,
			Filters: filters,
		})
	}

	if err != nil {
		return ""
	}
	return path
}

// CancelScan cancels the currently running scan
func (a *App) CancelScan() {
	a.scanMutex.Lock()
	defer a.scanMutex.Unlock()

	if a.isScanning && a.scanCancel != nil {
		a.scanCancel()
		a.isScanning = false
		runtime.EventsEmit(a.ctx, "scan:cancelled")
	}
}

// StartQuickScan starts a quick scan with simple presets
func (a *App) StartQuickScan(count int, workers int, timeoutMs int) string {
	a.scanMutex.Lock()
	defer a.scanMutex.Unlock()

	if a.isScanning {
		return "A scan is already running"
	}

	a.isScanning = true
	ctx, cancel := context.WithCancel(context.Background())
	a.scanCancel = cancel

	go a.runScanGoroutine(ctx, CustomScanConfig{
		Count:   count,
		Workers: workers,
		Timeout: fmt.Sprintf("%dms", timeoutMs),
		Tries:   4,
		Port:    443,
		Mode:    "http",
		UseV4:   true,
		UseV6:   false,
	})

	return ""
}

// StartCustomScan starts a custom scan with detailed configuration
func (a *App) StartCustomScan(cfg CustomScanConfig) string {
	a.scanMutex.Lock()
	defer a.scanMutex.Unlock()

	if a.isScanning {
		return "A scan is already running"
	}

	a.isScanning = true
	ctx, cancel := context.WithCancel(context.Background())
	a.scanCancel = cancel

	go a.runScanGoroutine(ctx, cfg)

	return ""
}

// StartTestIPs starts a test pass against a file of IPs
func (a *App) StartTestIPs(ipFile string) string {
	a.scanMutex.Lock()
	defer a.scanMutex.Unlock()

	if a.isScanning {
		return "A scan is already running"
	}

	a.isScanning = true
	ctx, cancel := context.WithCancel(context.Background())
	a.scanCancel = cancel

	go a.runTestGoroutine(ctx, ipFile)

	return ""
}

// StartDiscoverColos starts Cloudflare Colo discovery
func (a *App) StartDiscoverColos() string {
	a.scanMutex.Lock()
	defer a.scanMutex.Unlock()

	if a.isScanning {
		return "A scan is already running"
	}

	a.isScanning = true
	ctx, cancel := context.WithCancel(context.Background())
	a.scanCancel = cancel

	go a.runColosGoroutine(ctx)

	return ""
}

// ---------------------------------------------------------------------------
// Private runner implementations
// ---------------------------------------------------------------------------

func (a *App) runScanGoroutine(ctx context.Context, cfg CustomScanConfig) {
	defer func() {
		a.scanMutex.Lock()
		a.isScanning = false
		a.scanMutex.Unlock()
		runtime.EventsEmit(a.ctx, "scan:done")
	}()

	concurrency := cfg.Workers
	if concurrency <= 0 {
		concurrency = 50
	}
	timeout := parseTimeoutDuration(cfg.Timeout, 5*time.Second)
	tries := cfg.Tries
	if tries <= 0 {
		tries = 4
	}
	port := cfg.Port
	if port <= 0 {
		port = 443
	}

	mode, err := prober.ParseMode(cfg.Mode)
	if err != nil {
		mode = prober.ModeHTTP
	}

	var extra []string
	for _, c := range strings.Split(cfg.CIDR, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			extra = append(extra, c)
		}
	}

	useBuiltin := len(extra) == 0
	src, err := ipsrc.NewWithOptions(cfg.UseV4, cfg.UseV6, extra, ipsrc.Options{UseBuiltin: useBuiltin})
	if err != nil {
		runtime.EventsEmit(a.ctx, "scan:error", fmt.Sprintf("Scan setup failed: %v", err))
		return
	}

	sni := cfg.SNI
	wsHost := ""
	wsPath := ""
	requireWS := false

	if cfg.Config != "" {
		uSNI, uHost, uPath, uReqWS, uPort := ParseConfigURL(cfg.Config)
		if uSNI != "" {
			sni = uSNI
		}
		wsHost = uHost
		wsPath = uPath
		requireWS = uReqWS
		if uPort > 0 && port == 443 {
			port = uPort
		}
	}

	speedBytes := parseSpeedSize(cfg.SpeedSize)
	if mode != prober.ModeHTTP {
		speedBytes = 0
	}

	var uploadBytes int64
	if cfg.Upload && mode == prober.ModeHTTP {
		uploadBytes = speedBytes
	}

	engCfg := engine.Config{
		Concurrency: concurrency,
		ProbeConfig: prober.Config{
			Port:             port,
			Mode:             mode,
			Tries:            tries,
			Timeout:          timeout,
			SNI:              sni,
			SpeedBytes:       speedBytes,
			RequireWebSocket: requireWS,
			WebSocketHost:    wsHost,
			WebSocketPath:    wsPath,
			SpeedURL:         cfg.SpeedURL,
			UploadBytes:      uploadBytes,
		},
	}
	eng := engine.New(engCfg)

	coloSet := buildColoSetMap(cfg.ColoFilter)
	minSpeedThreshold := parseMinSpeed(cfg.MinSpeed)

	var writer *output.Writer
	if cfg.OutputFile != "" {
		fmt2 := output.DetectFormat(cfg.OutputFile)
		if w, e := output.New(cfg.OutputFile, fmt2); e == nil {
			writer = w
			defer writer.Close()
		} else {
			runtime.EventsEmit(a.ctx, "scan:error", fmt.Sprintf("Output disabled: %v", e))
		}
	}

	ipStream := src.Stream(ctx, cfg.Count)
	eng.Run(ctx, ipStream, func(r *result.Result) {
		s := eng.Stats()
		runtime.EventsEmit(a.ctx, "scan:stats", map[string]int64{
			"tested":   s.Tested.Load(),
			"healthy":  s.Healthy.Load(),
			"failed":   s.Failed.Load(),
			"inFlight": s.InFlight.Load(),
		})

		if !passesColoFilterMap(r, coloSet) {
			return
		}

		if minSpeedThreshold > 0 && r.Throughput < minSpeedThreshold {
			return
		}

		if writer != nil && r.IsHealthy() {
			if err := writer.Write(r); err != nil {
				runtime.EventsEmit(a.ctx, "scan:error", fmt.Sprintf("Output write failed: %v", err))
			}
		}

		runtime.EventsEmit(a.ctx, "scan:result", toFrontendResult(r))
	})
}

func (a *App) runTestGoroutine(ctx context.Context, ipFile string) {
	defer func() {
		a.scanMutex.Lock()
		a.isScanning = false
		a.scanMutex.Unlock()
		runtime.EventsEmit(a.ctx, "scan:done")
	}()

	ips, err := loadIPsFromFile(ipFile)
	if err != nil {
		runtime.EventsEmit(a.ctx, "scan:error", fmt.Sprintf("Test IPs failed: %v", err))
		return
	}
	if len(ips) == 0 {
		runtime.EventsEmit(a.ctx, "scan:error", fmt.Sprintf("Test IPs failed: no valid IPs found in %s", ipFile))
		return
	}

	// Emit initial stats with total count
	runtime.EventsEmit(a.ctx, "test:total", len(ips))

	engCfg := engine.Config{
		Concurrency: 20,
		ProbeConfig: prober.Config{
			Port:             443,
			Mode:             prober.ModeHTTP,
			Tries:            6,
			Timeout:          10 * time.Second,
			SNI:              "speed.cloudflare.com",
			SpeedBytes:       512 * 1024,
			RequireWebSocket: true,
		},
	}
	eng := engine.New(engCfg)

	eng.RunList(ctx, ips, func(r *result.Result) {
		s := eng.Stats()
		runtime.EventsEmit(a.ctx, "scan:result", toFrontendResult(r))
		runtime.EventsEmit(a.ctx, "scan:stats", map[string]int64{
			"tested":   s.Tested.Load(),
			"healthy":  s.Healthy.Load(),
			"failed":   s.Failed.Load(),
			"inFlight": s.InFlight.Load(),
		})
	})
}

func (a *App) runColosGoroutine(ctx context.Context) {
	defer func() {
		a.scanMutex.Lock()
		a.isScanning = false
		a.scanMutex.Unlock()
		runtime.EventsEmit(a.ctx, "scan:done")
	}()

	src, err := ipsrc.New(true, false, nil)
	if err != nil {
		runtime.EventsEmit(a.ctx, "scan:error", fmt.Sprintf("Colo discovery failed: %v", err))
		return
	}

	engCfg := engine.Config{
		Concurrency: 80,
		ProbeConfig: prober.Config{
			Port:       443,
			Mode:       prober.ModeHTTP,
			Tries:      2,
			Timeout:    5 * time.Second,
			SpeedBytes: 0,
		},
	}
	eng := engine.New(engCfg)
	ipStream := src.Stream(ctx, 300)

	eng.Run(ctx, ipStream, func(r *result.Result) {
		s := eng.Stats()
		runtime.EventsEmit(a.ctx, "scan:stats", map[string]int64{
			"tested":   s.Tested.Load(),
			"healthy":  s.Healthy.Load(),
			"failed":   s.Failed.Load(),
			"inFlight": s.InFlight.Load(),
		})

		if !r.IsHealthy() || r.Colo == "" {
			return
		}

		runtime.EventsEmit(a.ctx, "scan:result", toFrontendResult(r))
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseTimeoutDuration(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if timeout, err := time.ParseDuration(raw); err == nil {
		return timeout
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func buildColoSetMap(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(strings.ToUpper(c))
		if c != "" {
			set[c] = true
		}
	}
	return set
}

func passesColoFilterMap(r *result.Result, set map[string]bool) bool {
	if set == nil {
		return true
	}
	return set[strings.ToUpper(r.Colo)]
}

func speedSampleForProbeMode(mode prober.Mode) int64 {
	if mode != prober.ModeHTTP {
		return 0
	}
	return 128 * 1024
}

func loadIPsFromFile(path string) ([]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var ips []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "ip") {
			continue
		}
		field := strings.SplitN(line, ",", 2)[0]
		field = strings.TrimSpace(field)
		if ip := net.ParseIP(field); ip != nil {
			if ip.To4() != nil {
				ips = append(ips, ip)
			}
		} else if strings.Contains(field, "/") {
			_, ipNet, err := net.ParseCIDR(field)
			if err == nil {
				if ipNet.IP.To4() != nil {
					ips = append(ips, sampleIPsFromSubnet(ipNet, 256)...)
				}
			} else {
				return nil, fmt.Errorf("invalid CIDR %q: %w", field, err)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	// Shuffle loaded IPs
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(ips), func(i, j int) {
		ips[i], ips[j] = ips[j], ips[i]
	})

	return ips, nil
}

func sampleIPsFromSubnet(ipNet *net.IPNet, count int) []net.IP {
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil
	}

	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones

	if hostBits <= 8 {
		var ips []net.IP
		for ip := cloneIPBytes(ipNet.IP); ipNet.Contains(ip); incrementIPBytes(ip) {
			if ip.To4() != nil {
				ips = append(ips, cloneIPBytes(ip))
			}
		}
		return ips
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	base := binary.BigEndian.Uint32(ip4)
	mask := binary.BigEndian.Uint32([]byte(ipNet.Mask))
	size := ^mask

	seen := make(map[uint32]struct{})
	var ips []net.IP
	for i := 0; i < count*3 && len(ips) < count; i++ {
		offset := rng.Uint32() & size
		if _, ok := seen[offset]; ok {
			continue
		}
		seen[offset] = struct{}{}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base|offset)
		ips = append(ips, ip)
	}
	return ips
}

func toFrontendResult(r *result.Result) FrontendResult {
	loss := r.Loss()
	avg := float64(r.Avg().Microseconds()) / 1000.0       // ms
	min := float64(r.Min().Microseconds()) / 1000.0       // ms
	max := float64(r.Max().Microseconds()) / 1000.0       // ms
	jitter := float64(r.Jitter().Microseconds()) / 1000.0 // ms
	speed := r.Throughput / 1024.0                        // KB/s

	return FrontendResult{
		IP:         r.IP.String(),
		Loss:       loss,
		Avg:        avg,
		Min:        min,
		Max:        max,
		Jitter:     jitter,
		Speed:      speed,
		Colo:       r.Colo,
		TLSOk:      r.TLSOk,
		HTTPStatus: r.HTTPStatus,
		IsHealthy:  r.IsHealthy(),
	}
}

func cloneIPBytes(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incrementIPBytes(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func ParseConfigURL(raw string) (sni string, wsHost string, wsPath string, requireWS bool, port int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", false, 0
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", false, 0
	}

	if u.Port() != "" {
		if p, err := strconv.Atoi(u.Port()); err == nil {
			port = p
		}
	}

	q := u.Query()

	sni = q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}

	wsHost = q.Get("host")
	wsPath = q.Get("path")

	transportType := q.Get("type")
	if transportType == "ws" {
		requireWS = true
	}

	return sni, wsHost, wsPath, requireWS, port
}

func parseSpeedSize(raw string) int64 {
	raw = strings.TrimSpace(strings.ToUpper(raw))
	if raw == "" {
		return 512 * 1024
	}
	if strings.Contains(raw, "128") {
		return 128 * 1024
	}
	if strings.Contains(raw, "512") {
		return 512 * 1024
	}
	if strings.Contains(raw, "1 MB") || strings.Contains(raw, "1MB") {
		return 1024 * 1024
	}
	if strings.Contains(raw, "5 MB") || strings.Contains(raw, "5MB") {
		return 5 * 1024 * 1024
	}
	rawNum := strings.TrimRight(raw, " KBMB")
	if val, err := strconv.ParseInt(rawNum, 10, 64); err == nil {
		if strings.Contains(raw, "MB") {
			return val * 1024 * 1024
		}
		if strings.Contains(raw, "KB") {
			return val * 1024
		}
		return val
	}
	return 512 * 1024
}

func parseMinSpeed(raw string) float64 {
	raw = strings.TrimSpace(strings.ToUpper(raw))
	if raw == "" || raw == "NONE" {
		return 0
	}
	if strings.Contains(raw, "1") {
		return 125 * 1024
	}
	if strings.Contains(raw, "2") {
		return 250 * 1024
	}
	if strings.Contains(raw, "5") {
		return 625 * 1024
	}
	rawNum := strings.TrimRight(raw, " MBPS")
	if val, err := strconv.ParseFloat(rawNum, 64); err == nil {
		return val * 125 * 1024
	}
	return 0
}
