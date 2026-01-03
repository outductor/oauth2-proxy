package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testDiscordProvider(hostname string, opts options.DiscordOptions) *DiscordProvider {
	p, err := NewDiscordProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""},
		opts)
	if err != nil {
		panic(err)
	}
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testDiscordBackend(payloads map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			payload, ok := payloads[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
				return
			}
			w.WriteHeader(200)
			w.Write([]byte(payload))
		}))
}

func TestNewDiscordProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	p, err := NewDiscordProvider(&ProviderData{}, options.DiscordOptions{})
	g.Expect(err).To(BeNil())
	providerData := p.Data()
	g.Expect(providerData.ProviderName).To(Equal("Discord"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://discord.com/oauth2/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://discord.com/api/oauth2/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://discord.com/api/users/@me"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://discord.com/api/users/@me"))
	g.Expect(providerData.Scope).To(Equal("identify guilds"))
}

func TestDiscordProviderWithRolesAddsScope(t *testing.T) {
	g := NewWithT(t)

	// Test that guilds.members.read scope is added when roles are specified
	p, err := NewDiscordProvider(&ProviderData{}, options.DiscordOptions{
		Guilds: []options.DiscordGuild{
			{ID: "111111111", Roles: []string{"123456789"}},
		},
	})
	g.Expect(err).To(BeNil())
	g.Expect(p.Data().Scope).To(ContainSubstring("guilds.members.read"))
}

func TestDiscordProviderGuildWithoutRolesNoExtraScope(t *testing.T) {
	g := NewWithT(t)

	// Test that guilds.members.read scope is NOT added when no roles are specified
	p, err := NewDiscordProvider(&ProviderData{}, options.DiscordOptions{
		Guilds: []options.DiscordGuild{
			{ID: "111111111"},
		},
	})
	g.Expect(err).To(BeNil())
	g.Expect(p.Data().Scope).ToNot(ContainSubstring("guilds.members.read"))
}

func TestDiscordProviderOverrides(t *testing.T) {
	p, err := NewDiscordProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ProfileURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/profile"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			Scope: "identify"},
		options.DiscordOptions{})
	assert.NoError(t, err)
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Discord", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "identify", p.Data().Scope)
}

func TestDiscordProviderEnrichSession(t *testing.T) {
	b := testDiscordBackend(map[string]string{
		"/api/users/@me": `{
			"id": "123456789",
			"username": "testuser",
			"global_name": "Test User"
		}`,
		"/api/users/@me/guilds": `[
			{"id": "111111111", "name": "Test Guild 1"},
			{"id": "222222222", "name": "Test Guild 2"}
		]`,
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{})
	p.ProfileURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/users/@me"}

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "123456789", session.User)
	assert.Equal(t, "Test User", session.PreferredUsername)
	assert.Equal(t, "123456789", session.Email) // User ID used as Email
}

func TestDiscordProviderGuildRestriction(t *testing.T) {
	b := testDiscordBackend(map[string]string{
		"/api/users/@me": `{
			"id": "123456789",
			"username": "testuser"
		}`,
		"/api/users/@me/guilds": `[
			{"id": "111111111", "name": "Test Guild 1"},
			{"id": "222222222", "name": "Test Guild 2"}
		]`,
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)

	// Test with allowed guild (no roles required)
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{
		Guilds: []options.DiscordGuild{
			{ID: "111111111"},
		},
	})
	p.ProfileURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/users/@me"}

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
}

func TestDiscordProviderGuildRestrictionDenied(t *testing.T) {
	b := testDiscordBackend(map[string]string{
		"/api/users/@me": `{
			"id": "123456789",
			"username": "testuser"
		}`,
		"/api/users/@me/guilds": `[
			{"id": "111111111", "name": "Test Guild 1"}
		]`,
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)

	// Test with non-matching guild
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{
		Guilds: []options.DiscordGuild{
			{ID: "999999999"},
		},
	})
	p.ProfileURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/users/@me"}

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a member of any allowed Discord guild")
}

func TestDiscordProviderRoleRestriction(t *testing.T) {
	b := testDiscordBackend(map[string]string{
		"/api/users/@me": `{
			"id": "123456789",
			"username": "testuser"
		}`,
		"/api/users/@me/guilds": `[
			{"id": "111111111", "name": "Test Guild 1"}
		]`,
		"/api/users/@me/guilds/111111111/member": `{
			"roles": ["role1", "role2", "admin"]
		}`,
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)

	// Test with allowed role in allowed guild
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{
		Guilds: []options.DiscordGuild{
			{ID: "111111111", Roles: []string{"admin"}},
		},
	})
	p.ProfileURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/users/@me"}

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
}

func TestDiscordProviderRoleRestrictionDenied(t *testing.T) {
	b := testDiscordBackend(map[string]string{
		"/api/users/@me": `{
			"id": "123456789",
			"username": "testuser"
		}`,
		"/api/users/@me/guilds": `[
			{"id": "111111111", "name": "Test Guild 1"}
		]`,
		"/api/users/@me/guilds/111111111/member": `{
			"roles": ["role1", "role2"]
		}`,
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)

	// Test with non-matching role
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{
		Guilds: []options.DiscordGuild{
			{ID: "111111111", Roles: []string{"superadmin"}},
		},
	})
	p.ProfileURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/users/@me"}

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not have any required Discord role")
}

func TestDiscordProviderMultipleGuildsOR(t *testing.T) {
	b := testDiscordBackend(map[string]string{
		"/api/users/@me": `{
			"id": "123456789",
			"username": "testuser"
		}`,
		"/api/users/@me/guilds": `[
			{"id": "222222222", "name": "Test Guild 2"}
		]`,
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)

	// User is in guild2, not guild1. Should pass because it's OR logic.
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{
		Guilds: []options.DiscordGuild{
			{ID: "111111111"},
			{ID: "222222222"},
		},
	})
	p.ProfileURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/users/@me"}

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
}

func TestDiscordProviderMultipleGuildsWithDifferentRoles(t *testing.T) {
	b := testDiscordBackend(map[string]string{
		"/api/users/@me": `{
			"id": "123456789",
			"username": "testuser"
		}`,
		"/api/users/@me/guilds": `[
			{"id": "111111111", "name": "Test Guild 1"},
			{"id": "222222222", "name": "Test Guild 2"}
		]`,
		"/api/users/@me/guilds/111111111/member": `{
			"roles": ["member"]
		}`,
		"/api/users/@me/guilds/222222222/member": `{
			"roles": ["admin"]
		}`,
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)

	// User has "member" role in guild1 (not matching "admin")
	// User has "admin" role in guild2 (matching "admin")
	// Should pass because guild2 matches
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{
		Guilds: []options.DiscordGuild{
			{ID: "111111111", Roles: []string{"admin"}},
			{ID: "222222222", Roles: []string{"admin"}},
		},
	})
	p.ProfileURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/users/@me"}

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
}

func TestDiscordProviderValidateSession(t *testing.T) {
	b := testDiscordBackend(map[string]string{
		"/api/users/@me": `{"id": "123456789", "username": "testuser"}`,
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{})
	p.ValidateURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/users/@me"}

	session := CreateAuthorizedSession()
	valid := p.ValidateSession(context.Background(), session)
	assert.True(t, valid)
}

func TestDiscordProviderValidateSessionInvalid(t *testing.T) {
	b := testDiscordBackend(map[string]string{})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{})
	p.ValidateURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/users/@me"}

	session := &sessions.SessionState{AccessToken: "invalid_token"}
	valid := p.ValidateSession(context.Background(), session)
	assert.False(t, valid)
}

func TestDiscordProviderRefreshSession(t *testing.T) {
	refreshResponse := map[string]interface{}{
		"access_token":  "new_access_token",
		"refresh_token": "new_refresh_token",
		"expires_in":    604800,
		"token_type":    "Bearer",
		"scope":         "identify email guilds",
	}
	responseBytes, _ := json.Marshal(refreshResponse)

	b := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/oauth2/token" && r.Method == "POST" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				w.Write(responseBytes)
			} else {
				w.WriteHeader(404)
			}
		}))
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(bURL.Host, options.DiscordOptions{})
	p.RedeemURL = &url.URL{Scheme: "http", Host: bURL.Host, Path: "/api/oauth2/token"}

	session := &sessions.SessionState{
		AccessToken:  "old_access_token",
		RefreshToken: "old_refresh_token",
	}

	refreshed, err := p.RefreshSession(context.Background(), session)
	assert.NoError(t, err)
	assert.True(t, refreshed)
	assert.Equal(t, "new_access_token", session.AccessToken)
	assert.Equal(t, "new_refresh_token", session.RefreshToken)
}

func TestDiscordProviderRefreshSessionNoRefreshToken(t *testing.T) {
	p := testDiscordProvider("", options.DiscordOptions{})

	session := &sessions.SessionState{
		AccessToken: "access_token",
	}

	refreshed, err := p.RefreshSession(context.Background(), session)
	assert.NoError(t, err)
	assert.False(t, refreshed)
}
