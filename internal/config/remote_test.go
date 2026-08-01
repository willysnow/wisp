package config

import "testing"

// TestResolveTokenPrefersFile. An explicit token in the config file is a
// deliberate choice and must never be shadowed by a variable that happens to be
// in the environment — otherwise a stray WISP_TOKEN in a shell profile would
// silently redirect a sensor's credentials.
func TestResolveTokenPrefersFile(t *testing.T) {
	t.Setenv(TokenEnvVar, "from-env")

	r := Remote{Token: "from-file"}
	if got := r.ResolveToken(); got != "from-file" {
		t.Errorf("ResolveToken() = %q, want the file value to win over the environment", got)
	}
}

// TestResolveTokenFallsBackToEnv is the whole point of the feature: one config
// file with no token, shipped to every sensor, each supplying its own secret
// through WISP_TOKEN.
func TestResolveTokenFallsBackToEnv(t *testing.T) {
	t.Setenv(TokenEnvVar, "from-env")

	r := Remote{} // token left empty in the file
	if got := r.ResolveToken(); got != "from-env" {
		t.Errorf("ResolveToken() = %q, want the WISP_TOKEN fallback", got)
	}
}

// TestResolveTokenEmptyWhenNeitherSet. With no token anywhere, the result is
// empty rather than an error — remote delivery is off unless a URL is set too,
// and the console rejects an empty bearer on its own.
func TestResolveTokenEmptyWhenNeitherSet(t *testing.T) {
	t.Setenv(TokenEnvVar, "")

	r := Remote{}
	if got := r.ResolveToken(); got != "" {
		t.Errorf("ResolveToken() = %q, want empty when neither file nor env sets it", got)
	}
}

// TestResolveURLPrefersFile. Same rule as the token: a URL written in the file
// is deliberate and must not be redirected by a variable in the environment.
func TestResolveURLPrefersFile(t *testing.T) {
	t.Setenv(RemoteURLEnvVar, "http://env.example:8000")

	r := Remote{URL: "http://file.example:8000"}
	if got := r.ResolveURL(); got != "http://file.example:8000" {
		t.Errorf("ResolveURL() = %q, want the file value to win over the environment", got)
	}
}

// TestResolveURLFallsBackToEnv. Because an empty URL is what disables remote
// delivery, this fallback is what lets `WISP_REMOTE_URL=... wispd` reach a
// console with no config file at all.
func TestResolveURLFallsBackToEnv(t *testing.T) {
	t.Setenv(RemoteURLEnvVar, "http://127.0.0.1:8001")

	r := Remote{} // url left empty in the file
	if got := r.ResolveURL(); got != "http://127.0.0.1:8001" {
		t.Errorf("ResolveURL() = %q, want the WISP_REMOTE_URL fallback", got)
	}
}

// TestResolveURLEmptyWhenNeitherSet. Neither file nor env means remote delivery
// stays off — the standalone honeypot other users run every day.
func TestResolveURLEmptyWhenNeitherSet(t *testing.T) {
	t.Setenv(RemoteURLEnvVar, "")

	r := Remote{}
	if got := r.ResolveURL(); got != "" {
		t.Errorf("ResolveURL() = %q, want empty when neither file nor env sets it", got)
	}
}
