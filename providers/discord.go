package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// DiscordProvider represents a Discord based Identity Provider
type DiscordProvider struct {
	*ProviderData
	Guilds []options.DiscordGuild
}

var _ Provider = (*DiscordProvider)(nil)

const (
	discordProviderName = "Discord"
	discordDefaultScope = "identify guilds"
)

var (
	// Default Login URL for Discord.
	// Pre-parsed URL of https://discord.com/oauth2/authorize.
	discordDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "discord.com",
		Path:   "/oauth2/authorize",
	}

	// Default Redeem URL for Discord.
	// Pre-parsed URL of https://discord.com/api/oauth2/token.
	discordDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "discord.com",
		Path:   "/api/oauth2/token",
	}

	// Default Profile URL for Discord.
	// Pre-parsed URL of https://discord.com/api/users/@me.
	discordDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "discord.com",
		Path:   "/api/users/@me",
	}

	// Default Validate URL for Discord (same as profile).
	discordDefaultValidateURL = discordDefaultProfileURL
)

// NewDiscordProvider initiates a new DiscordProvider
func NewDiscordProvider(p *ProviderData, opts options.DiscordOptions) (*DiscordProvider, error) {
	p.setProviderDefaults(providerDefaults{
		name:        discordProviderName,
		loginURL:    discordDefaultLoginURL,
		redeemURL:   discordDefaultRedeemURL,
		profileURL:  discordDefaultProfileURL,
		validateURL: discordDefaultValidateURL,
		scope:       discordDefaultScope,
	})
	p.getAuthorizationHeaderFunc = makeDiscordHeader

	provider := &DiscordProvider{
		ProviderData: p,
		Guilds:       opts.Guilds,
	}

	// Add guilds.members.read scope if any guild has role restrictions
	if provider.hasRoleRestrictions() && !strings.Contains(p.Scope, "guilds.members.read") {
		p.Scope += " guilds.members.read"
	}

	return provider, nil
}

// hasRoleRestrictions returns true if any guild has role restrictions configured
func (p *DiscordProvider) hasRoleRestrictions() bool {
	for _, guild := range p.Guilds {
		if len(guild.Roles) > 0 {
			return true
		}
	}
	return false
}

func makeDiscordHeader(accessToken string) http.Header {
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, nil)
}

// buildAPIURL constructs a Discord API URL with the given path
func (p *DiscordProvider) buildAPIURL(path string) string {
	u := *p.ProfileURL
	u.Path = path
	return u.String()
}

// EnrichSession updates the User & Email after the initial Redeem
func (p *DiscordProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Get user info
	if err := p.getUser(ctx, s); err != nil {
		return err
	}

	// Get guilds for group membership
	if err := p.getGuilds(ctx, s); err != nil {
		return err
	}

	// Check guild and role restrictions
	if err := p.checkRestrictions(ctx, s); err != nil {
		return err
	}

	return nil
}

// ValidateSession validates the AccessToken
func (p *DiscordProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeDiscordHeader(s.AccessToken))
}

// getUser fetches user info from Discord API
func (p *DiscordProvider) getUser(ctx context.Context, s *sessions.SessionState) error {
	var user struct {
		ID         string `json:"id"`
		Username   string `json:"username"`
		GlobalName string `json:"global_name"`
	}

	err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeDiscordHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&user)
	if err != nil {
		return fmt.Errorf("failed to get user info: %v", err)
	}

	// Use Discord User ID (immutable) instead of Username (can be changed)
	s.User = user.ID
	if user.GlobalName != "" {
		s.PreferredUsername = user.GlobalName
	} else {
		s.PreferredUsername = user.Username
	}

	// Use User ID as Email to pass oauth2-proxy's email validation
	// Works with --email-domain="*"
	s.Email = user.ID

	return nil
}

// getGuilds fetches the user's guild memberships from Discord API
// Only guilds that are in the configured allowed list are retained.
// If no guilds are configured, no guild IDs are added to session groups.
func (p *DiscordProvider) getGuilds(ctx context.Context, s *sessions.SessionState) error {
	var guilds []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	err := requests.New(p.buildAPIURL("/api/users/@me/guilds")).
		WithContext(ctx).
		WithHeaders(makeDiscordHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&guilds)
	if err != nil {
		return fmt.Errorf("failed to get guilds: %v", err)
	}

	// Build a set of allowed guild IDs for filtering
	allowedGuildSet := make(map[string]struct{}, len(p.Guilds))
	for _, g := range p.Guilds {
		allowedGuildSet[g.ID] = struct{}{}
	}

	// Only retain guilds that are in the allowed list (privacy protection)
	for _, guild := range guilds {
		if _, isAllowed := allowedGuildSet[guild.ID]; isAllowed {
			s.Groups = append(s.Groups, guild.ID)
		}
	}

	return nil
}

// getRolesInGuild fetches the user's roles in a specific guild
func (p *DiscordProvider) getRolesInGuild(ctx context.Context, accessToken, guildID string) ([]string, error) {
	var member struct {
		Roles []string `json:"roles"`
	}

	err := requests.New(p.buildAPIURL(fmt.Sprintf("/api/users/@me/guilds/%s/member", guildID))).
		WithContext(ctx).
		WithHeaders(makeDiscordHeader(accessToken)).
		Do().
		UnmarshalInto(&member)
	if err != nil {
		return nil, fmt.Errorf("failed to get guild member info: %v", err)
	}

	return member.Roles, nil
}

// checkRestrictions verifies that the user meets guild and role requirements
func (p *DiscordProvider) checkRestrictions(ctx context.Context, s *sessions.SessionState) error {
	// If no guild restrictions are configured, allow all Discord users
	if len(p.Guilds) == 0 {
		return nil
	}

	// Build a set of user's guilds for quick lookup
	userGuildSet := make(map[string]struct{}, len(s.Groups))
	for _, g := range s.Groups {
		userGuildSet[g] = struct{}{}
	}

	// Check each configured guild
	for _, allowedGuild := range p.Guilds {
		// Check if user is a member of this guild
		if _, isMember := userGuildSet[allowedGuild.ID]; !isMember {
			continue
		}

		// If no role restrictions for this guild, user passes
		if len(allowedGuild.Roles) == 0 {
			return nil
		}

		// Check role restrictions for this guild
		userRoles, err := p.getRolesInGuild(ctx, s.AccessToken, allowedGuild.ID)
		if err != nil {
			logger.Printf("Could not fetch roles for guild %s: %v", allowedGuild.ID, err)
			continue
		}

		// Build a set of user's roles for quick lookup
		userRoleSet := make(map[string]struct{}, len(userRoles))
		for _, roleID := range userRoles {
			userRoleSet[roleID] = struct{}{}
			// Add guild:role format to groups for potential use in authorization
			s.Groups = append(s.Groups, fmt.Sprintf("%s:%s", allowedGuild.ID, roleID))
		}

		// Check if user has any of the required roles
		for _, requiredRole := range allowedGuild.Roles {
			if _, hasRole := userRoleSet[requiredRole]; hasRole {
				logger.Printf("Found Discord Role: %s in Guild: %s", requiredRole, allowedGuild.ID)
				return nil
			}
		}
	}

	// Determine appropriate error message
	if p.hasRoleRestrictions() {
		logger.Printf("User does not have required role in any allowed guild")
		return errors.New("user does not have any required Discord role in allowed guilds")
	}

	logger.Printf("User is not a member of any allowed guild. Required: %v", p.getGuildIDs())
	return errors.New("user is not a member of any allowed Discord guild")
}

// getGuildIDs returns a list of configured guild IDs for logging
func (p *DiscordProvider) getGuildIDs() []string {
	ids := make([]string, len(p.Guilds))
	for i, g := range p.Guilds {
		ids[i] = g.ID
	}
	return ids
}

// RefreshSession refreshes the user's session using the refresh token
func (p *DiscordProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return false, err
	}

	params := url.Values{}
	params.Add("grant_type", "refresh_token")
	params.Add("refresh_token", s.RefreshToken)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)

	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(strings.NewReader(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&response)
	if err != nil {
		return false, fmt.Errorf("failed to refresh token: %v", err)
	}

	s.AccessToken = response.AccessToken
	if response.RefreshToken != "" {
		s.RefreshToken = response.RefreshToken
	}
	s.CreatedAtNow()
	s.ExpiresIn(time.Duration(response.ExpiresIn) * time.Second)

	return true, nil
}
