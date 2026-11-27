//go:build unix

package cli

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	askpassEnvSock  = "_OUTSIDER_ASKPASS_SOCK"
	askpassEnvToken = "_OUTSIDER_ASKPASS_TOKEN"
)

// MaybeRunAskpassHelper checks if outsider was self-invoked by ssh/git/sudo as an ASKPASS helper.
// Must be called as the very first line in main().
func MaybeRunAskpassHelper() {
	sockPath := os.Getenv(askpassEnvSock)
	token := os.Getenv(askpassEnvToken)
	if sockPath == "" || token == "" {
		return
	}

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider-askpass] connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, token+"\n"); err != nil {
		os.Exit(1)
	}
	buf, err := io.ReadAll(conn)
	if err != nil {
		os.Exit(1)
	}
	defer clear(buf)

	if _, err := os.Stdout.Write(buf); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

type askpassGuard struct {
	dir      string
	listener net.Listener
	mu       sync.Mutex
	secret   []byte
	token    []byte
	wg       sync.WaitGroup
}

func (g *askpassGuard) Close() {
	if g == nil {
		return
	}
	_ = g.listener.Close()
	g.wg.Wait()
	g.mu.Lock()
	clear(g.secret)
	clear(g.token)
	g.secret = nil
	g.token = nil
	g.mu.Unlock()
	_ = os.RemoveAll(g.dir)
}

func startAskpassServer(secret []byte) (*askpassGuard, map[string]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot locate current outsider binary for --askpass: %w", err)
	}

	var dirRnd [12]byte
	var tokRnd [32]byte
	if _, err := rand.Read(dirRnd[:]); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(tokRnd[:]); err != nil {
		return nil, nil, err
	}

	baseDir := preferredTempDir()
	dir := filepath.Join(baseDir, "outsider-askpass-"+base64.RawURLEncoding.EncodeToString(dirRnd[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create askpass dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, fmt.Errorf("chmod askpass dir: %w", err)
	}

	sockPath := filepath.Join(dir, "askpass.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, fmt.Errorf("bind askpass socket: %w", err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.RemoveAll(dir)
		return nil, nil, fmt.Errorf("chmod askpass socket: %w", err)
	}

	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	tokenStr := base64.RawURLEncoding.EncodeToString(tokRnd[:])
	tokenBytes := []byte(tokenStr)

	g := &askpassGuard{
		dir:      dir,
		listener: ln,
		secret:   secretCopy,
		token:    tokenBytes,
	}

	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(io.LimitReader(c, 4096))
				line, err := r.ReadString('\n')
				if err != nil && line == "" {
					return
				}
				got := []byte(strings.TrimRight(line, "\r\n"))
				defer clear(got)

				g.mu.Lock()
				tok := g.token
				sec := g.secret
				if len(tok) > 0 && subtle.ConstantTimeCompare(got, tok) == 1 && sec != nil {
					_, _ = c.Write(sec)
				}
				g.mu.Unlock()
			}(conn)
		}
	}()

	envs := map[string]string{
		"SSH_ASKPASS":         exe,
		"SSH_ASKPASS_REQUIRE": "force",
		"GIT_ASKPASS":         exe,
		"SUDO_ASKPASS":        exe,
		askpassEnvSock:        sockPath,
		askpassEnvToken:       tokenStr,
	}
	if _, ok := os.LookupEnv("DISPLAY"); !ok {
		envs["DISPLAY"] = "outsider:0"
	}
	return g, envs, nil
}

func preferredTempDir() string {
	if runtime.GOOS == "linux" {
		if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
			return "/dev/shm"
		}
	}
	return os.TempDir()
}
