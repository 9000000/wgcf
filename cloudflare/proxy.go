package cloudflare

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const ProxyListURL = "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/US/data.txt"

type ProxyManager struct {
	mu          sync.RWMutex
	proxies     []string
	currIdx     int
	uses        int
	initialized bool
	enabled     bool
}

var GlobalProxyManager = &ProxyManager{}

// LoadProxies fetches and updates the internal proxy pool
func (m *ProxyManager) LoadProxies() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("ProxyManager: Fetching latest proxy list from %s", ProxyListURL)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(ProxyListURL)
	if err != nil {
		return fmt.Errorf("failed to fetch proxy list: %w", err)
	}
	defer resp.Body.Close()

	var list []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Filter out empty lines, comments, and invalid protocols
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		
		// Filter specifically for schemes Go standard library can support natively: http, https, socks5
		if strings.HasPrefix(line, "socks5://") || strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			list = append(list, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error during scanning proxy list: %w", err)
	}

	if len(list) == 0 {
		return fmt.Errorf("proxy scanner returned zero usable proxies")
	}

	m.proxies = list
	m.currIdx = 0
	m.uses = 0
	m.initialized = true
	log.Printf("ProxyManager: Successfully loaded %d usable SOCKS5/HTTP proxies", len(list))
	return nil
}

// GetProxy fits the signature expected by http.Transport.Proxy callback
func (m *ProxyManager) GetProxy(req *http.Request) (*url.URL, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.initialized || len(m.proxies) == 0 || !m.enabled {
		return nil, nil // Bypass proxy (Direct Connection)
	}

	proxyStr := m.proxies[m.currIdx]
	parsedUrl, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid parsed URL in proxy pool '%s': %w", proxyStr, err)
	}

	return parsedUrl, nil
}

// HasProxies returns true if pool has valid addresses loaded
func (m *ProxyManager) HasProxies() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.proxies) > 0
}

// Rotate unconditionally increments index to the next available proxy
func (m *ProxyManager) Rotate() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.proxies) == 0 {
		return
	}

	m.currIdx = (m.currIdx + 1) % len(m.proxies)
	m.uses = 0
	log.Printf("ProxyManager: Active proxy rotated to #%d: %s", m.currIdx, m.proxies[m.currIdx])
}

// IncrementUse records a successful registration, automatically rotating after 2 successful cycles
func (m *ProxyManager) IncrementUse() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.proxies) == 0 {
		return
	}

	m.uses++
	log.Printf("ProxyManager: Success registration counter increments to %d/2 for active proxy", m.uses)
	if m.uses >= 2 {
		m.currIdx = (m.currIdx + 1) % len(m.proxies)
		m.uses = 0
		log.Printf("ProxyManager: Usage threshold met. Automatically rotating to proxy #%d: %s", m.currIdx, m.proxies[m.currIdx])
	}
}

// GetCurrentProxyStr returns current active proxy address for debugging/logging
func (m *ProxyManager) GetCurrentProxyStr() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.proxies) == 0 {
		return "Direct Connection"
	}
	if !m.enabled {
		return fmt.Sprintf("Direct Connection (Proxy pool available: %d URLs)", len(m.proxies))
	}
	return fmt.Sprintf("[%d/%d] %s", m.currIdx, len(m.proxies), m.proxies[m.currIdx])
}

// SetEnabled dynamically switches proxy usage on or off
func (m *ProxyManager) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
	log.Printf("ProxyManager: Routing set to ProxyEnabled=%t", enabled)
}

// IsEnabled returns the current routing operational mode
func (m *ProxyManager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

