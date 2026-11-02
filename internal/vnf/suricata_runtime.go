package vnf

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/networkservicemesh/sdk/pkg/tools/log"

	"nse-ovs-dpi/internal/processor"
)

const suricataStartupGracePeriod = 500 * time.Millisecond

type ruleSnapshot struct {
	Hash      string
	RuleCount int
}

type suricataSession struct {
	cmd              *exec.Cmd
	closeCh          chan struct{}
	doneCh           chan struct{}
	watchDoneCh      chan struct{}
	logCtx           context.Context
	logFile          *os.File
	rulesPath        string
	rulePollInterval time.Duration
	flow             FlowInfo
	sessionDir       string
	evePath          string
	logPath          string
	state            *SessionState

	closeOnce sync.Once
	mu        sync.Mutex
	closing   bool
	exitErr   error
}

func DefaultRuntimeHook(options Options) RuntimeHook {
	options = options.withDefaults()
	return RuntimeHookFunc(func(ctx context.Context, sessionCtx *SessionContext) (processor.Session, error) {
		return startTrafficProcessing(ctx, sessionCtx, options)
	})
}

// startTrafficProcessing runs a per-session Suricata worker on the ingress leg.
// V1 remains alert-only and only mounts Suricata native rules from a shared file.
func startTrafficProcessing(ctx context.Context, sessionCtx *SessionContext, options Options) (processor.Session, error) {
	if sessionCtx == nil {
		return nil, fmt.Errorf("session context is required")
	}

	options = options.withDefaults()
	if err := options.validate(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(options.TempRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create dpi temp root %s: %w", options.TempRoot, err)
	}

	sessionPrefix := fmt.Sprintf("session-%s-", sanitizeComponent(sessionCtx.ConnectionID()))
	sessionDir, err := os.MkdirTemp(options.TempRoot, sessionPrefix)
	if err != nil {
		return nil, fmt.Errorf("create dpi session dir: %w", err)
	}

	logPath := filepath.Join(sessionDir, "suricata.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		_ = os.RemoveAll(sessionDir)
		return nil, fmt.Errorf("open suricata log file %s: %w", logPath, err)
	}

	cmd := exec.Command(
		options.SuricataBinary,
		"-c", options.SuricataConfigPath,
		"-i", sessionCtx.IngressInterface(),
		"-l", sessionDir,
		"-S", options.RulesPath,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		_ = os.RemoveAll(sessionDir)
		return nil, fmt.Errorf("start suricata on ingress interface %s: %w", sessionCtx.IngressInterface(), err)
	}

	session := &suricataSession{
		cmd:              cmd,
		closeCh:          make(chan struct{}),
		doneCh:           make(chan struct{}),
		watchDoneCh:      make(chan struct{}),
		logCtx:           log.WithLog(context.Background(), log.FromContext(ctx)),
		logFile:          logFile,
		rulesPath:        options.RulesPath,
		rulePollInterval: options.RulePollInterval,
		flow:             sessionCtx.Flow(),
		sessionDir:       sessionDir,
		evePath:          filepath.Join(sessionDir, "eve.json"),
		logPath:          logPath,
		state:            sessionCtx.State(),
	}

	if state := sessionCtx.State(); state != nil {
		state.Store(StateKeyDPIEngine, "suricata")
		state.Store(StateKeyDPIRulesPath, options.RulesPath)
		state.Store(StateKeyDPISuricataConfig, options.SuricataConfigPath)
		state.Store(StateKeyDPISessionDir, sessionDir)
		state.Store(StateKeyDPIEVEPath, session.evePath)
		state.Store(StateKeyDPILogPath, logPath)
		state.Store(StateKeyDPIHTTPPort, options.HTTPPort)
		state.Store(StateKeyDPIProcessPID, cmd.Process.Pid)
	}

	go session.waitProcess()

	select {
	case <-session.doneCh:
		startErr := session.processExitErr()
		_ = logFile.Close()
		_ = os.RemoveAll(sessionDir)
		if startErr == nil {
			startErr = fmt.Errorf("suricata exited during startup without reporting an error")
		}
		return nil, fmt.Errorf("suricata startup failed: %w", startErr)
	case <-time.After(suricataStartupGracePeriod):
	}

	go session.watchRules()

	log.FromContext(ctx).Infof(
		"started suricata pid=%d ingress=%s rules=%s session_dir=%s",
		cmd.Process.Pid,
		sessionCtx.IngressInterface(),
		options.RulesPath,
		sessionDir,
	)

	return session, nil
}

func (s *suricataSession) watchRules() {
	defer close(s.watchDoneCh)

	snapshot, err := loadRuleSnapshot(s.rulesPath)
	if err != nil {
		log.FromContext(s.logCtx).Errorf("initial dpi rules snapshot failed for %s: %v", s.rulesPath, err)
	}

	ticker := time.NewTicker(s.rulePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-s.doneCh:
			return
		case <-ticker.C:
		}

		nextSnapshot, err := loadRuleSnapshot(s.rulesPath)
		if err != nil {
			log.FromContext(s.logCtx).Errorf("reload dpi rules failed for %s: %v", s.rulesPath, err)
			continue
		}

		if snapshot != nil && nextSnapshot.Hash == snapshot.Hash {
			continue
		}

		if err := s.signal(syscall.SIGUSR2); err != nil {
			log.FromContext(s.logCtx).Errorf("signal suricata reload failed for %s: %v", s.flow.IngressInterface, err)
			continue
		}

		snapshot = nextSnapshot
		if s.state != nil {
			s.state.Store(StateKeyDPIRuleHash, nextSnapshot.Hash)
			s.state.Store(StateKeyDPIRuleCount, nextSnapshot.RuleCount)
		}

		log.FromContext(s.logCtx).Infof(
			"reloaded dpi rules pid=%d hash=%s count=%d ingress=%s",
			s.pid(),
			shortHash(nextSnapshot.Hash),
			nextSnapshot.RuleCount,
			s.flow.IngressInterface,
		)
	}
}

func (s *suricataSession) waitProcess() {
	err := s.cmd.Wait()

	s.mu.Lock()
	closing := s.closing
	if closing {
		s.exitErr = nil
	} else {
		s.exitErr = err
	}
	s.mu.Unlock()

	if err != nil && !closing {
		log.FromContext(s.logCtx).Errorf(
			"suricata exited unexpectedly pid=%d ingress=%s err=%v",
			s.pid(),
			s.flow.IngressInterface,
			err,
		)
	} else {
		log.FromContext(s.logCtx).Infof(
			"suricata stopped pid=%d ingress=%s",
			s.pid(),
			s.flow.IngressInterface,
		)
	}

	close(s.doneCh)
}

func (s *suricataSession) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}

	var errs []error

	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.mu.Unlock()
		close(s.closeCh)
		if err := s.signal(syscall.SIGTERM); err != nil && !isFinishedProcessError(err) {
			errs = append(errs, err)
		}
	})

	if err := waitForChannel(ctx, s.watchDoneCh); err != nil {
		errs = append(errs, err)
	}

	if err := waitForChannelWithKill(ctx, s.doneCh, func() error {
		if s.cmd == nil || s.cmd.Process == nil {
			return nil
		}
		return s.cmd.Process.Kill()
	}); err != nil {
		errs = append(errs, err)
	}

	if err := s.processExitErr(); err != nil {
		errs = append(errs, err)
	}

	if s.logFile != nil {
		if err := s.logFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := os.RemoveAll(s.sessionDir); err != nil {
		errs = append(errs, err)
	}

	s.clearState()

	return errors.Join(errs...)
}

func (s *suricataSession) signal(sig syscall.Signal) error {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return fmt.Errorf("suricata process is unavailable")
	}
	return s.cmd.Process.Signal(sig)
}

func (s *suricataSession) pid() int {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return 0
	}
	return s.cmd.Process.Pid
}

func (s *suricataSession) processExitErr() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exitErr
}

func (s *suricataSession) clearState() {
	if s == nil || s.state == nil {
		return
	}
	s.state.Delete(StateKeyDPIProcessPID)
	s.state.Delete(StateKeyDPIRuleHash)
	s.state.Delete(StateKeyDPIRuleCount)
	s.state.Delete(StateKeyDPISessionDir)
	s.state.Delete(StateKeyDPIEVEPath)
	s.state.Delete(StateKeyDPILogPath)
}

func waitForChannel(ctx context.Context, ch <-chan struct{}) error {
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitForChannelWithKill(ctx context.Context, ch <-chan struct{}, kill func() error) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		if killErr := kill(); killErr != nil && !isFinishedProcessError(killErr) {
			return errors.Join(ctx.Err(), killErr)
		}
		<-ch
		return ctx.Err()
	case <-timer.C:
		if killErr := kill(); killErr != nil && !isFinishedProcessError(killErr) {
			return killErr
		}
		<-ch
		return nil
	}
}

func loadRuleSnapshot(path string) (*ruleSnapshot, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(content)
	return &ruleSnapshot{
		Hash:      hex.EncodeToString(sum[:]),
		RuleCount: countRuleLines(content),
	}, nil
}

func countRuleLines(content []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
	}
	return count
}

func sanitizeComponent(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}

	var builder strings.Builder
	for _, r := range value {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			builder.WriteRune(r)
		default:
			builder.WriteByte('-')
		}
	}

	sanitized := strings.Trim(builder.String(), "-")
	if sanitized == "" {
		return "unknown"
	}
	return sanitized
}

func shortHash(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func isFinishedProcessError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "process already finished") || strings.Contains(text, "os: process already finished")
}
