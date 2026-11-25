package main

import (
	"sync"
	"time"

	"github.com/pkg/errors"
)

// configuration holds the System Console settings. A configuration is never modified after it
// becomes active, so readers share one pointer.
type configuration struct {
	EnableAccess       bool
	EnableWriteTools   bool
	ToolsChannels      bool
	ToolsPosts         bool
	ToolsSearch        bool
	ToolsUnreads       bool
	ToolsUsers         bool
	AccessTokenMinutes int
	RefreshTokenDays   int
}

// accessTokenTTL is how long a new access token works.
func (c *configuration) accessTokenTTL() time.Duration {
	return time.Duration(c.AccessTokenMinutes) * time.Minute
}

// refreshTokenTTL is how long a new refresh token works.
func (c *configuration) refreshTokenTTL() time.Duration {
	return time.Duration(c.RefreshTokenDays) * 24 * time.Hour
}

// validate rejects lifetimes outside the documented ranges, so a typo cannot mint year-long access tokens.
func (c *configuration) validate() error {
	if c.AccessTokenMinutes < 5 || c.AccessTokenMinutes > 1440 {
		return errors.Errorf("AccessTokenMinutes must be 5 to 1440, got %d", c.AccessTokenMinutes)
	}
	if c.RefreshTokenDays < 1 || c.RefreshTokenDays > 365 {
		return errors.Errorf("RefreshTokenDays must be 1 to 365, got %d", c.RefreshTokenDays)
	}
	return nil
}

// configStore guards the active configuration.
type configStore struct {
	lock   sync.RWMutex
	active *configuration
}

// get returns the active configuration, or a closed default before the first load.
func (s *configStore) get() *configuration {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.active == nil {
		return &configuration{AccessTokenMinutes: 60, RefreshTokenDays: 30}
	}
	return s.active
}

// set makes c active.
func (s *configStore) set(c *configuration) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.active = c
}

// loadConfiguration reads and validates the settings and makes them active, or changes nothing on error.
func (p *Plugin) loadConfiguration() error {
	c := new(configuration)
	if err := p.API.LoadPluginConfiguration(c); err != nil {
		return errors.Wrap(err, "load plugin configuration")
	}
	if err := c.validate(); err != nil {
		return err
	}
	p.config.set(c)
	return nil
}

// OnConfigurationChange keeps the previous settings when the new ones are invalid.
func (p *Plugin) OnConfigurationChange() error {
	return p.loadConfiguration()
}
