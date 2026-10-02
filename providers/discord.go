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

	discordDefaultAPIPath = "/api/v10"
	discordProfilePath    = "/users/@me"
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
	// Pre-parsed URL of https://discord.com/api/v10/users/@me.
	// Requests without an API version are routed to the deprecated v6.
	discordDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "discord.com",
		Path:   discordDefaultAPIPath + discordProfilePath,
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

	// Without guilds every Discord account is accepted, and the user ID is used
	// as the email, so email domain restrictions cannot narrow this down.
	// The legacy --provider=discord flags cannot configure guilds at all.
	if len(provider.Guilds) == 0 {
		logger.Print("WARNING: Discord provider has no guilds configured, any Discord user will be able to log in. " +
			"Set discordConfig.guilds in the alpha configuration to restrict access.")
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

// buildAPIURL constructs a Discord API URL with the given path.
// The API base is taken from the profile URL, so a profile URL of
// https://discord.com/api/v10/users/@me resolves paths under /api/v10.
// If the profile URL does not end with /users/@me, the default /api/v10 base
// on the profile URL's host is used.
func (p *DiscordProvider) buildAPIURL(path string) string {
	u := *p.ProfileURL
	base, ok := strings.CutSuffix(u.Path, discordProfilePath)
	if !ok {
		base = discordDefaultAPIPath
	}
	u.Path = base + path
	u.RawPath = ""
	return u.String()
}

// EnrichSession updates the User & Email after the initial Redeem
func (p *DiscordProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if err := p.getUser(ctx, s); err != nil {
		return err
	}

	return p.checkMembership(ctx, s)
}

// ValidateSession checks that the session still satisfies the guild and role
// restrictions and that the AccessToken is still valid.
// The session groups are kept up to date by RefreshSession.
func (p *DiscordProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	if !p.isAllowed(s.Groups) {
		logger.Printf("Discord user %s no longer meets the guild and role restrictions", s.User)
		return false
	}
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

// getUserGuildIDs fetches the IDs of the guilds the user is a member of
func (p *DiscordProvider) getUserGuildIDs(ctx context.Context, accessToken string) (map[string]struct{}, error) {
	var guilds []struct {
		ID string `json:"id"`
	}

	err := requests.New(p.buildAPIURL("/users/@me/guilds")).
		WithContext(ctx).
		WithHeaders(makeDiscordHeader(accessToken)).
		Do().
		UnmarshalInto(&guilds)
	if err != nil {
		return nil, fmt.Errorf("failed to get guilds: %v", err)
	}

	ids := make(map[string]struct{}, len(guilds))
	for _, guild := range guilds {
		ids[guild.ID] = struct{}{}
	}
	return ids, nil
}

// getRolesInGuild fetches the user's roles in a specific guild
func (p *DiscordProvider) getRolesInGuild(ctx context.Context, accessToken, guildID string) ([]string, error) {
	var member struct {
		Roles []string `json:"roles"`
	}

	err := requests.New(p.buildAPIURL(fmt.Sprintf("/users/@me/guilds/%s/member", guildID))).
		WithContext(ctx).
		WithHeaders(makeDiscordHeader(accessToken)).
		Do().
		UnmarshalInto(&member)
	if err != nil {
		return nil, fmt.Errorf("failed to get guild member info: %v", err)
	}

	return member.Roles, nil
}

// checkMembership stores the user's membership in the configured guilds in the
// session groups and verifies the guild and role restrictions
func (p *DiscordProvider) checkMembership(ctx context.Context, s *sessions.SessionState) error {
	// If no guild restrictions are configured, allow all Discord users
	if len(p.Guilds) == 0 {
		return nil
	}

	groups, roleErr, err := p.getMembership(ctx, s.AccessToken)
	if err != nil {
		return err
	}
	s.Groups = groups

	if p.isAllowed(groups) {
		return nil
	}
	if roleErr != nil {
		return fmt.Errorf("could not verify Discord roles: %w", roleErr)
	}
	if p.hasRoleRestrictions() {
		return errors.New("user does not have any required Discord role in allowed guilds")
	}
	return errors.New("user is not a member of any allowed Discord guild")
}

// getMembership returns the session groups for the user's membership in the
// configured guilds.
// Groups only contain configured guild IDs, plus "guildID:roleID" entries for
// every role the user has in configured guilds that have role restrictions.
// roleErr is set when the roles of some guilds could not be fetched; the
// returned groups then lack the role entries of those guilds.
func (p *DiscordProvider) getMembership(ctx context.Context, accessToken string) (groups []string, roleErr error, err error) {
	userGuilds, err := p.getUserGuildIDs(ctx, accessToken)
	if err != nil {
		return nil, nil, err
	}

	var roleErrs []error
	for _, guild := range p.Guilds {
		if _, isMember := userGuilds[guild.ID]; !isMember {
			continue
		}
		groups = append(groups, guild.ID)

		if len(guild.Roles) == 0 {
			continue
		}
		roles, err := p.getRolesInGuild(ctx, accessToken, guild.ID)
		if err != nil {
			roleErrs = append(roleErrs, fmt.Errorf("guild %s: %v", guild.ID, err))
			continue
		}
		for _, role := range roles {
			groups = append(groups, discordRoleGroup(guild.ID, role))
		}
	}

	return groups, errors.Join(roleErrs...), nil
}

// isAllowed reports whether the given session groups satisfy any of the
// configured guild and role restrictions
func (p *DiscordProvider) isAllowed(groups []string) bool {
	if len(p.Guilds) == 0 {
		return true
	}

	groupSet := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		groupSet[group] = struct{}{}
	}

	for _, guild := range p.Guilds {
		if _, isMember := groupSet[guild.ID]; !isMember {
			continue
		}
		if len(guild.Roles) == 0 {
			return true
		}
		for _, role := range guild.Roles {
			if _, hasRole := groupSet[discordRoleGroup(guild.ID, role)]; hasRole {
				return true
			}
		}
	}
	return false
}

func discordRoleGroup(guildID, roleID string) string {
	return fmt.Sprintf("%s:%s", guildID, roleID)
}

// Redeem exchanges the OAuth2 authorization code for an access token and keeps
// the refresh token and expiry so the session can be refreshed later
func (p *DiscordProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}

	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	params.Add("redirect_uri", redirectURL)
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	s := &sessions.SessionState{}
	if err := p.requestToken(ctx, params, s); err != nil {
		return nil, fmt.Errorf("failed to redeem code: %v", err)
	}
	return s, nil
}

// RefreshSession refreshes the user's session using the refresh token
func (p *DiscordProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	params := url.Values{}
	params.Add("grant_type", "refresh_token")
	params.Add("refresh_token", s.RefreshToken)

	if err := p.requestToken(ctx, params, s); err != nil {
		return false, fmt.Errorf("failed to refresh token: %v", err)
	}

	// Re-read the guild and role membership so that ValidateSession can reject
	// users who left a guild or lost a role. On lookup failures the previous
	// groups are kept, as the refreshed tokens must still be saved.
	if len(p.Guilds) > 0 {
		groups, roleErr, err := p.getMembership(ctx, s.AccessToken)
		switch {
		case err != nil:
			logger.Errorf("Could not refresh Discord guilds for user %s: %v", s.User, err)
		case roleErr != nil:
			logger.Errorf("Could not refresh Discord roles for user %s: %v", s.User, roleErr)
		default:
			s.Groups = groups
		}
	}

	return true, nil
}

// requestToken calls the token endpoint with the given grant parameters and
// stores the returned tokens and expiry in the session
func (p *DiscordProvider) requestToken(ctx context.Context, params url.Values, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}
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
		return err
	}
	if response.AccessToken == "" {
		return errors.New("no access token in response")
	}

	s.AccessToken = response.AccessToken
	if response.RefreshToken != "" {
		s.RefreshToken = response.RefreshToken
	}
	s.CreatedAtNow()
	if response.ExpiresIn > 0 {
		s.ExpiresIn(time.Duration(response.ExpiresIn) * time.Second)
	}

	return nil
}
