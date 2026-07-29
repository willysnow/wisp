// Command wispd runs the wisp honeypot sensor.
//
// Every enabled service binds its own listener and runs in its own goroutine.
// One service failing to bind is logged and skipped rather than fatal: a sensor
// that reports on two of three ports is far better than one that refuses to
// start because 11434 was already taken.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/willysnow/wisp/internal/build"
	"github.com/willysnow/wisp/internal/config"
	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/bannersvc"
	"github.com/willysnow/wisp/internal/service/dockersvc"
	"github.com/willysnow/wisp/internal/service/elasticsvc"
	"github.com/willysnow/wisp/internal/service/ftpsvc"
	"github.com/willysnow/wisp/internal/service/gitlabsvc"
	"github.com/willysnow/wisp/internal/service/gitsvc"
	"github.com/willysnow/wisp/internal/service/httpsvc"
	"github.com/willysnow/wisp/internal/service/imdssvc"
	"github.com/willysnow/wisp/internal/service/jenkinssvc"
	"github.com/willysnow/wisp/internal/service/k8ssvc"
	"github.com/willysnow/wisp/internal/service/kubeletsvc"
	"github.com/willysnow/wisp/internal/service/llmnrsvc"
	"github.com/willysnow/wisp/internal/service/mcpsvc"
	"github.com/willysnow/wisp/internal/service/mongosvc"
	"github.com/willysnow/wisp/internal/service/mssqlsvc"
	"github.com/willysnow/wisp/internal/service/mysqlsvc"
	"github.com/willysnow/wisp/internal/service/ntpsvc"
	"github.com/willysnow/wisp/internal/service/ollamasvc"
	"github.com/willysnow/wisp/internal/service/proxysvc"
	"github.com/willysnow/wisp/internal/service/redissvc"
	"github.com/willysnow/wisp/internal/service/sipsvc"
	"github.com/willysnow/wisp/internal/service/smbsvc"
	"github.com/willysnow/wisp/internal/service/snmpsvc"
	"github.com/willysnow/wisp/internal/service/sshsvc"
	"github.com/willysnow/wisp/internal/service/telnetsvc"
	"github.com/willysnow/wisp/internal/service/tftpsvc"
	"github.com/willysnow/wisp/internal/service/vncsvc"
	"github.com/willysnow/wisp/internal/sink"
	"github.com/willysnow/wisp/internal/tlsutil"
)

func main() {
	cfgPath := flag.String("config", "wisp.yaml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("wispd", build.Info())
		return
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)
	logger.Printf("wispd %s", build.Info())

	cfg, found, err := config.Load(*cfgPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	if found {
		logger.Printf("loaded config from %s", *cfgPath)
	} else {
		logger.Printf("no config at %s - running on defaults", *cfgPath)
	}
	if d := cfg.Device; d.Persona != "" {
		logger.Printf("device: %s (%s)", d.Desc, d.Persona)
	}
	// Said out loud rather than silently corrected: whether to run a service is
	// the operator's call, but a banner contradicting the rest of the disguise
	// is worth knowing about.
	for _, w := range cfg.PersonaWarnings() {
		logger.Printf("device: WARNING %s", w)
	}

	emit, closeSinks, err := buildEmitter(cfg)
	if err != nil {
		logger.Fatalf("log sink: %v", err)
	}
	defer closeSinks()

	services, err := buildServices(cfg)
	if err != nil {
		logger.Fatalf("service: %v", err)
	}
	if len(services) == 0 {
		logger.Fatal("no services enabled - nothing to do")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	started := 0
	for _, svc := range services {
		// TCP and UDP services bind differently, so the runner dispatches on
		// which half of the interface the service implements.
		switch s := svc.(type) {
		case service.StreamService:
			ln, err := net.Listen("tcp", s.Addr())
			if err != nil {
				logger.Printf("%-8s FAILED to bind tcp %s: %v", s.Name(), s.Addr(), err)
				continue
			}
			started++
			logger.Printf("%-8s listening on tcp %s", s.Name(), ln.Addr())

			wg.Add(1)
			go func(s service.StreamService, ln net.Listener) {
				defer wg.Done()
				defer ln.Close()
				if err := s.Serve(ctx, ln, emit); err != nil {
					logger.Printf("%-8s stopped: %v", s.Name(), err)
				}
			}(s, ln)

		case service.PacketService:
			pc, err := net.ListenPacket("udp", s.Addr())
			if err != nil {
				logger.Printf("%-8s FAILED to bind udp %s: %v", s.Name(), s.Addr(), err)
				continue
			}
			started++
			logger.Printf("%-8s listening on udp %s", s.Name(), pc.LocalAddr())

			wg.Add(1)
			go func(s service.PacketService, pc net.PacketConn) {
				defer wg.Done()
				defer pc.Close()
				if err := s.ServePacket(ctx, pc, emit); err != nil {
					logger.Printf("%-8s stopped: %v", s.Name(), err)
				}
			}(s, pc)

		default:
			logger.Printf("%-8s SKIPPED: implements neither StreamService nor PacketService", svc.Name())
		}
	}

	if started == 0 {
		logger.Fatal("no service could bind - exiting")
	}

	<-ctx.Done()
	logger.Print("shutting down")
	wg.Wait()
}

// buildEmitter assembles the sink chain and stamps the node name onto every
// event, so services never have to know which sensor they are running on.
func buildEmitter(cfg *config.Config) (event.Emitter, func(), error) {
	var sinks sink.Multi
	closers := []func(){}

	if cfg.Log.Console {
		sinks = append(sinks, sink.NewConsole(os.Stdout))
	}
	if cfg.Log.File != "" {
		s, f, err := sink.NewJSONLFile(cfg.Log.File, sink.RotateConfig{
			MaxSize:  cfg.Log.Rotate.MaxSizeBytes(),
			MaxFiles: cfg.Log.Rotate.Files(),
		})
		if err != nil {
			return nil, nil, err
		}
		sinks = append(sinks, s)
		closers = append(closers, func() { _ = f.Close() })
	}
	if c := cfg.Log.Syslog; c.Enabled {
		s, err := sink.NewSyslog(c)
		if err != nil {
			return nil, nil, err
		}
		sinks = append(sinks, s)
		closers = append(closers, func() { _ = s.Close() })
	}
	if c := cfg.Log.HPFeeds; c.Enabled {
		var tlsCfg *tls.Config
		if c.TLS {
			var err error
			tlsCfg, err = tlsutil.ClientConfig(c.CAFile, c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return nil, nil, fmt.Errorf("hpfeeds: %w", err)
			}
			if tlsCfg == nil {
				// System roots. ClientConfig returns nil to mean "net/http's
				// own default is fine", which a raw tls.Dial cannot use.
				tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
			}
		}
		hp := sink.NewHPFeeds(sink.HPFeedsOptions{
			Addr:    c.Addr,
			Ident:   c.Ident,
			Secret:  c.Secret,
			Channel: c.Channel,
			TLS:     tlsCfg,
		})
		sinks = append(sinks, hp)
		closers = append(closers, hp.Close)
	}
	if u := cfg.Log.Remote.URL; u != "" {
		r := cfg.Log.Remote
		tlsCfg, err := tlsutil.ClientConfig(r.CAFile, r.Fingerprint, r.InsecureSkipVerify)
		if err != nil {
			return nil, nil, err
		}
		remote := sink.NewRemote(sink.RemoteOptions{URL: u, Token: r.Token, TLS: tlsCfg})
		sinks = append(sinks, remote)
		closers = append(closers, remote.Close)
	}

	// The limiter sits in front of every sink, so a flood cannot fill the local
	// log or bury the console. It goes after node stamping so its own
	// suppression summaries carry the sensor's name like any other event.
	var out event.Emitter = sinks
	if rl := cfg.Log.RateLimit; rl.Enabled {
		limiter := sink.NewLimiter(sinks, sink.LimitConfig{
			PerSourceRate:  rl.PerSource,
			PerSourceBurst: rl.PerSourceBurst,
			HighValueRate:  rl.HighValue,
			HighValueBurst: rl.HighValueBurst,
			GlobalRate:     rl.Global,
			GlobalBurst:    rl.GlobalBurst,
		})
		out = limiter
		// Closed first, so the final suppression summary is written before the
		// sinks it has to travel through are shut down.
		closers = append([]func(){limiter.Close}, closers...)
	}

	// The node name and, when a persona is in use, what this sensor claims to
	// be. Services never have to know either: an alert can say "the intrusion
	// hit the box pretending to be the DiskStation" without anyone looking up
	// the deployment.
	//
	// Both device fields are absent unless configured, so an existing
	// deployment's events do not change shape.
	node, device := cfg.Node, cfg.Device
	emit := event.EmitterFunc(func(e event.Event) {
		e.Node = node
		if device.Name != "" || device.Desc != "" {
			if e.Data == nil {
				e.Data = map[string]any{}
			}
			if device.Name != "" {
				e.Data["device_name"] = device.Name
			}
			if device.Desc != "" {
				e.Data["device_desc"] = device.Desc
			}
		}
		out.Emit(e)
	})

	return emit, func() {
		for _, c := range closers {
			c()
		}
	}, nil
}

// parseDuration reads an optional duration from the config, naming the field
// in the error so a typo says which line to look at.
func parseDuration(field, value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	return d, nil
}

func buildServices(cfg *config.Config) ([]service.Service, error) {
	var out []service.Service

	if c := cfg.Services.SSH; c.Enabled {
		s, err := sshsvc.New(c.Addr, c.Banner, c.HostKey)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if c := cfg.Services.HTTP; c.Enabled {
		out = append(out, httpsvc.New(c.Addr, c.ServerHeader, c.Realm, c.Footer))
	}
	if c := cfg.Services.HTTPS; c.Enabled {
		s, err := httpsvc.NewTLS(c.Addr, c.ServerHeader, c.Realm, c.Footer, c.Cert, c.Key, c.Names)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if c := cfg.Services.Ollama; c.Enabled {
		out = append(out, ollamasvc.New(c.Addr, c.Version))
	}
	if c := cfg.Services.Telnet; c.Enabled {
		out = append(out, telnetsvc.New(c.Addr, c.Banner))
	}
	if c := cfg.Services.FTP; c.Enabled {
		out = append(out, ftpsvc.New(c.Addr, c.Banner))
	}
	if c := cfg.Services.Redis; c.Enabled {
		out = append(out, redissvc.New(c.Addr, c.Version))
	}
	if c := cfg.Services.TFTP; c.Enabled {
		out = append(out, tftpsvc.New(c.Addr))
	}
	if c := cfg.Services.NTP; c.Enabled {
		out = append(out, ntpsvc.New(c.Addr))
	}
	if c := cfg.Services.K8s; c.Enabled {
		s, err := k8ssvc.New(c.Addr, c.Version, c.Cert, c.Key)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if c := cfg.Services.Kubelet; c.Enabled {
		s, err := kubeletsvc.New(c.Addr, c.NodeName, c.Cert, c.Key)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if c := cfg.Services.Docker; c.Enabled {
		out = append(out, dockersvc.New(c.Addr, c.Version, c.APIVersion))
	}
	if c := cfg.Services.IMDS; c.Enabled {
		out = append(out, imdssvc.New(c.Addr, c.Region, c.Role))
	}
	if c := cfg.Services.Elasticsearch; c.Enabled {
		out = append(out, elasticsvc.New(c.Addr, c.Version, c.ClusterName))
	}
	if c := cfg.Services.Jenkins; c.Enabled {
		out = append(out, jenkinssvc.New(c.Addr, c.Version))
	}
	if c := cfg.Services.GitLab; c.Enabled {
		out = append(out, gitlabsvc.New(c.Addr, c.Version))
	}
	if c := cfg.Services.MCP; c.Enabled {
		out = append(out, mcpsvc.New(c.Addr, c.ServerName, c.Version))
	}
	if c := cfg.Services.Git; c.Enabled {
		out = append(out, gitsvc.New(c.Addr))
	}
	if c := cfg.Services.MongoDB; c.Enabled {
		out = append(out, mongosvc.New(c.Addr, c.Version))
	}
	if c := cfg.Services.MySQL; c.Enabled {
		out = append(out, mysqlsvc.New(c.Addr, c.Version))
	}
	if c := cfg.Services.MSSQL; c.Enabled {
		out = append(out, mssqlsvc.New(c.Addr, c.Version, c.ServerName))
	}
	if c := cfg.Services.SMB; c.Enabled {
		out = append(out, smbsvc.New(c.Addr, c.ComputerName, c.DomainName))
	}
	if c := cfg.Services.VNC; c.Enabled {
		out = append(out, vncsvc.New(c.Addr, c.Version))
	}
	if c := cfg.Services.SIP; c.Enabled {
		out = append(out, sipsvc.New(c.Addr, c.Realm, c.Server))
	}
	if c := cfg.Services.HTTPProxy; c.Enabled {
		out = append(out, proxysvc.New(c.Addr, c.ServerHeader, c.Realm))
	}
	if c := cfg.Services.SNMP; c.Enabled {
		out = append(out, snmpsvc.New(c.Addr))
	}
	if c := cfg.Services.LLMNR; c.Enabled {
		interval, err := parseDuration("services.llmnr.interval", c.Interval)
		if err != nil {
			return nil, err
		}
		splay, err := parseDuration("services.llmnr.splay", c.Splay)
		if err != nil {
			return nil, err
		}
		out = append(out, llmnrsvc.New(c.Addr, c.Hostname, interval, splay))
	}
	for _, c := range cfg.Services.Banners {
		if !c.Enabled {
			continue
		}
		if c.Name == "" || c.Addr == "" {
			return nil, fmt.Errorf("banner service needs both name and addr (got name=%q addr=%q)", c.Name, c.Addr)
		}
		out = append(out, bannersvc.New(c.Name, c.Addr, c.Banner))
	}

	return out, nil
}
