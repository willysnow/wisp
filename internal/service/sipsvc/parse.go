package sipsvc

import "strings"

// sipRequest is the part of a SIP request the decoy acts on. SIP is a text
// protocol shaped like HTTP: a request line, then headers, then an optional
// body the decoy ignores.
type sipRequest struct {
	method    string
	uri       string
	via       []string
	from      string
	to        string
	callID    string
	cseq      string
	userAgent string
	contact   string
	// auth is the value of an Authorization (or Proxy-Authorization) header, the
	// "Digest ..." part, empty when the request carried no credential.
	auth string
}

// parseRequest reads a SIP request. It returns ok=false for anything that is
// not a well-formed request line, so the decoy never answers arbitrary UDP.
func parseRequest(payload []byte) (sipRequest, bool) {
	// SIP uses CRLF, but tolerate bare LF the way lenient stacks do.
	text := strings.ReplaceAll(string(payload), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return sipRequest{}, false
	}

	parts := strings.Fields(lines[0])
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "SIP/") {
		return sipRequest{}, false
	}
	req := sipRequest{method: strings.ToUpper(parts[0]), uri: parts[1]}

	for _, line := range lines[1:] {
		if line == "" {
			break // end of headers
		}
		name, value, ok := splitHeader(line)
		if !ok {
			continue
		}
		switch canonicalHeader(name) {
		case "via":
			req.via = append(req.via, value)
		case "from":
			req.from = value
		case "to":
			req.to = value
		case "call-id":
			req.callID = value
		case "cseq":
			req.cseq = value
		case "user-agent":
			req.userAgent = value
		case "contact":
			req.contact = value
		case "authorization", "proxy-authorization":
			req.auth = value
		}
	}
	return req, true
}

func splitHeader(line string) (name, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// canonicalHeader lowercases a header name and expands the single-letter compact
// forms SIP allows, so "f" and "From" reach the same case.
func canonicalHeader(name string) string {
	switch strings.ToLower(name) {
	case "v":
		return "via"
	case "f":
		return "from"
	case "t":
		return "to"
	case "i":
		return "call-id"
	case "m":
		return "contact"
	case "l":
		return "content-length"
	default:
		return strings.ToLower(name)
	}
}

// parseDigest parses a "Digest key=value, key=value" header into a map, handling
// quoted and unquoted values. Every value comes from a stranger; a malformed
// pair is skipped rather than fatal.
func parseDigest(auth string) map[string]string {
	out := map[string]string{}
	rest := strings.TrimSpace(auth)
	if i := strings.IndexByte(rest, ' '); i >= 0 && strings.EqualFold(rest[:i], "Digest") {
		rest = rest[i+1:]
	}
	for _, pair := range splitParams(rest) {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"`)
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// splitParams splits a digest parameter list on commas that are not inside
// quotes, because a quoted value (a URI, a realm) may itself contain a comma.
func splitParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// fromUser and toUser pull the user part out of a From/To header, which is the
// extension an attacker is enumerating or spoofing.
func (r sipRequest) fromUser() string { return uriUser(r.from) }
func (r sipRequest) toUser() string   { return uriUser(r.to) }

// toHost is the host part of the To URI, used as the informational server field
// in the hashcat line.
func (r sipRequest) toHost() string {
	_, host := userAndHost(r.to)
	return host
}

// uriUser extracts the user from a header like `"1001" <sip:1001@pbx>;tag=x`.
func uriUser(header string) string {
	user, _ := userAndHost(header)
	return user
}

func userAndHost(header string) (user, host string) {
	i := strings.Index(header, "sip:")
	if i < 0 {
		i = strings.Index(header, "sips:")
		if i < 0 {
			return "", ""
		}
		i += len("sips:")
	} else {
		i += len("sip:")
	}
	rest := header[i:]
	// Stop at the first delimiter that ends the URI's user@host part.
	if j := strings.IndexAny(rest, ">;? "); j >= 0 {
		rest = rest[:j]
	}
	if at := strings.IndexByte(rest, '@'); at >= 0 {
		return rest[:at], rest[at+1:]
	}
	return "", rest
}
