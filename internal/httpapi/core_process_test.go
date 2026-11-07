//go:build darwin || linux

package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/wang4386/CDT-Monitor/internal/aliyun"
	"github.com/wang4386/CDT-Monitor/internal/app"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/engine"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"github.com/wang4386/CDT-Monitor/internal/web"
)

// This subprocess uses the production owner/recovery, SQLite, HTTP server,
// engine, and notification worker. Only the cloud boundary is an HTTP fake.
func TestCoreRuntimeProcessHelper(t *testing.T) {
	if os.Getenv("CDT_CORE_PROCESS_HELPER") != "1" {
		t.Skip("subprocess only")
	}
	runtime, err := app.OpenData(os.Getenv("CDT_CORE_DATA"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eng := engine.New(runtime.Store, processProvider{base: os.Getenv("CDT_CORE_CLOUD")}, notify.New(), logger, 2)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	eng.Start(ctx)
	defer func() { stop(); eng.Wait() }()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: New(runtime.Store, eng, web.FS(), logger).Handler(), ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(listener)
	if err = os.WriteFile(os.Getenv("CDT_CORE_READY"), []byte("http://"+listener.Addr().String()), 0600); err != nil {
		t.Fatal(err)
	}
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(shutdown)
}

type processProvider struct{ base string }

func (p processProvider) query(ctx context.Context, path string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", p.base+path, nil)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(out)
}
func (p processProvider) GetTraffic(ctx context.Context, _ domain.Account, _ string) (float64, error) {
	var v float64
	err := p.query(ctx, "/traffic", &v)
	return v, err
}
func (p processProvider) GetInstanceStatus(ctx context.Context, _ domain.Account, _ string) (string, error) {
	var v string
	err := p.query(ctx, "/status", &v)
	return v, err
}
func (p processProvider) ControlInstance(ctx context.Context, a domain.Account, _ string, action, mode string) error {
	body, _ := json.Marshal(map[string]any{"account_id": a.ID, "region": a.RegionID, "instance": a.InstanceID, "action": action, "mode": mode})
	req, _ := http.NewRequestWithContext(ctx, "POST", p.base+"/control", bytes.NewReader(body))
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("fake response %d", r.StatusCode)
	}
	return nil
}
func (p processProvider) GetAccountBalance(context.Context, domain.Account, string) (aliyun.BillingBalance, error) {
	return aliyun.BillingBalance{}, nil
}
func (p processProvider) GetInstanceBill(context.Context, domain.Account, string, string) (aliyun.BillingBill, error) {
	return aliyun.BillingBill{}, nil
}

type coreChild struct {
	cmd  *exec.Cmd
	done chan error
	url  string
	log  bytes.Buffer
}

func startCoreChild(t *testing.T, dir, cloud string) *coreChild {
	t.Helper()
	ready := filepath.Join(dir, fmt.Sprintf("ready-%d", time.Now().UnixNano()))
	c := &coreChild{done: make(chan error, 1)}
	c.cmd = exec.Command(os.Args[0], "-test.run=^TestCoreRuntimeProcessHelper$", "-test.v")
	c.cmd.Env = append(os.Environ(), "CDT_CORE_PROCESS_HELPER=1", "CDT_CORE_DATA="+dir, "CDT_CORE_CLOUD="+cloud, "CDT_CORE_READY="+ready)
	c.cmd.Stdout = &c.log
	c.cmd.Stderr = &c.log
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { c.done <- c.cmd.Wait() }()
	t.Cleanup(func() {
		if c.cmd.ProcessState == nil {
			c.cmd.Process.Kill()
			<-c.done
		}
		t.Logf("child output: %s", c.log.String())
	})
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(ready); err == nil {
			c.url = string(data)
			return c
		}
		select {
		case err := <-c.done:
			t.Fatalf("child exited before ready: %v %s", err, c.log.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("child readiness timeout")
	return nil
}
func stopCoreChild(t *testing.T, c *coreChild, signal os.Signal) {
	t.Helper()
	if err := c.cmd.Process.Signal(signal); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-c.done:
		if signal != os.Kill && err != nil {
			t.Fatalf("graceful stop: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("child failed to stop")
	}
}

func TestCoreProcessRestartHTTPWorkerChain(t *testing.T) {
	for _, stopSignal := range []os.Signal{os.Kill, syscall.SIGTERM} {
		t.Run(stopSignal.String(), func(t *testing.T) {
			var mu sync.Mutex
			controls, notifications := 0, 0
			status := "Running"
			traffic := 200.0
			controlAccepted := make(chan struct{}, 8)
			notificationAccepted := make(chan struct{}, 8)
			fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/traffic":
					mu.Lock()
					v := traffic
					mu.Unlock()
					json.NewEncoder(w).Encode(v)
				case "/status":
					mu.Lock()
					v := status
					mu.Unlock()
					json.NewEncoder(w).Encode(v)
				case "/control":
					io.Copy(io.Discard, r.Body)
					mu.Lock()
					controls++
					mu.Unlock()
					controlAccepted <- struct{}{}
					<-r.Context().Done()
				case "/notify":
					io.Copy(io.Discard, r.Body)
					mu.Lock()
					notifications++
					mu.Unlock()
					notificationAccepted <- struct{}{}
					<-r.Context().Done()
				default:
					http.NotFound(w, r)
				}
			}))
			defer func() { fake.CloseClientConnections(); fake.Close() }()
			dir := t.TempDir()
			child := startCoreChild(t, dir, fake.URL)
			jar, _ := cookiejar.New(nil)
			client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
			request := func(method, path, body string) (int, []byte) {
				t.Helper()
				req, _ := http.NewRequest(method, child.url+path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				for _, c := range jar.Cookies(req.URL) {
					if c.Name == "cdt_csrf" {
						req.Header.Set("X-CDT-CSRF", c.Value)
					}
				}
				r, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Body.Close()
				b, _ := io.ReadAll(r.Body)
				return r.StatusCode, b
			}
			cfg := domain.Config{AdminPassword: testAdminPassword, TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai", Accounts: []domain.Account{{AccessKeyID: "LTAIfake", AccessKeySecret: "test-only-secret", RegionID: "cn-hongkong", InstanceID: "i-fake", MaxTraffic: 200, SiteType: "china"}}, Notifications: domain.NotificationConfig{Webhook: domain.WebhookConfig{Enabled: true, URL: fake.URL + "/notify", Method: "POST", Type: "JSON"}}}
			raw, _ := json.Marshal(cfg)
			code, _ := request("POST", "/api/v1/setup", string(raw))
			if code != 201 {
				t.Fatalf("setup=%d", code)
			}
			code, raw = request("POST", "/api/v1/accounts/1/refresh", "")
			if code != 202 {
				t.Fatalf("refresh=%d", code)
			}
			var job domain.Job
			json.Unmarshal(raw, &job)
			select {
			case <-controlAccepted:
			case <-time.After(8 * time.Second):
				t.Fatal("control was not accepted by fake cloud")
			}
			code, _ = request("POST", "/api/v1/notifications/daily-report", `{}`)
			if code != 202 {
				t.Fatalf("report=%d", code)
			}
			select {
			case <-notificationAccepted:
			case <-time.After(8 * time.Second):
				t.Fatal("outbox did not reach fake notification endpoint")
			}
			db, err := sql.Open("sqlite", filepath.Join(dir, "data.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var before string
			db.QueryRow(`SELECT status FROM jobs WHERE id=?`, job.ID).Scan(&before)
			if before != "running" {
				t.Fatalf("active job=%s", before)
			}
			// A second complete startup must fail before migration or recovery.
			contender := exec.Command(os.Args[0], "-test.run=^TestCoreRuntimeProcessHelper$", "-test.v")
			contender.Env = append(os.Environ(), "CDT_CORE_PROCESS_HELPER=1", "CDT_CORE_DATA="+dir, "CDT_CORE_CLOUD="+fake.URL, "CDT_CORE_READY="+filepath.Join(dir, "contender-ready"))
			output, err := contender.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "already owned") {
				t.Fatalf("second runtime not refused: %v %s", err, output)
			}
			var after string
			db.QueryRow(`SELECT status FROM jobs WHERE id=?`, job.ID).Scan(&after)
			if after != before {
				t.Fatal("contender modified active owner job")
			}
			stoppedAt := time.Now()
			stopCoreChild(t, child, stopSignal)
			child = startCoreChild(t, dir, fake.URL)
			elapsed := time.Since(stoppedAt)
			if elapsed >= 120*time.Second {
				t.Fatal("restart not below 120 seconds")
			}
			// New port is the same origin host; cookie jar preserves the admin session.
			code, raw = request("GET", "/api/v1/jobs/"+job.ID, "")
			if code != 200 {
				t.Fatalf("job read=%d %s", code, raw)
			}
			json.Unmarshal(raw, &job)
			if job.Status != "interrupted" {
				t.Fatalf("restart job=%s", job.Status)
			}
			var outboxStatus, outboxError string
			db.QueryRow(`SELECT status,last_error FROM notification_outbox ORDER BY created_at LIMIT 1`).Scan(&outboxStatus, &outboxError)
			if outboxStatus != "failed" || !strings.Contains(outboxError, "delivery_unknown") {
				t.Fatalf("outbox=%s %s", outboxStatus, outboxError)
			}
			// A distinct formal refresh executes read-only while uncertainty remains.
			code, raw = request("POST", "/api/v1/accounts/1/refresh", "")
			if code != 202 {
				t.Fatal(code)
			}
			code, raw = request("GET", "/api/v1/status", "")
			if code != 200 || !bytes.Contains(raw, []byte(`"automation_blocked":true`)) {
				t.Fatalf("missing visible block %d %s", code, raw)
			}
			mu.Lock()
			gotControls, gotNotifications := controls, notifications
			mu.Unlock()
			if gotControls != 1 || gotNotifications != 1 {
				t.Fatalf("unexpected resend controls=%d notifications=%d", gotControls, gotNotifications)
			}
			code, raw = request("GET", "/api/v1/recovery", "")
			if code != 200 || !bytes.Contains(raw, []byte(job.ID)) {
				t.Fatal("recovery list missing interrupted job")
			}
			mu.Lock()
			status = "Stopped"
			traffic = 1
			mu.Unlock()
			code, _ = request("POST", "/api/v1/recovery/job/"+job.ID+"/resolve", `{"reviewed":true,"note":"verified original fake target"}`)
			if code != 200 {
				t.Fatalf("explicit review=%d", code)
			}
			mu.Lock()
			gotControls = controls
			mu.Unlock()
			if gotControls != 1 {
				t.Fatal("review resent cloud control")
			}
			stopCoreChild(t, child, syscall.SIGTERM)
			t.Logf("proof: signal=%s restart_ms=%d second_owner_refused=true interrupted_job=%s outbox=failed/delivery_unknown control_calls=%d notification_calls=%d", stopSignal, elapsed.Milliseconds(), job.ID, gotControls, gotNotifications)
		})
	}
}
