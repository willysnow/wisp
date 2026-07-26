package imdssvc

import (
	"fmt"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

// The instance's fabricated identity.
//
// Every credential below is well-formed and authenticates to nothing. That is
// deliberate rather than a limitation: the request *after* the credential
// request is the one that says what the intruder meant to do, and an error at
// this step ends the conversation before they get there.
//
// The shapes are the real ones. Tooling checks for `"Code": "Success"` and a
// key beginning `ASIA`, and something that fails to parse is treated as a dead
// endpoint rather than a live one.

const (
	accountID  = "471820938104"
	instanceID = "i-0a4c2f9e18b73d6f5"
	imageID    = "ami-0c7217cdde317cfec"
)

// sessionToken is what a PUT to /latest/api/token returns. IMDSv2 tokens are
// opaque to the client, so any stable string of the right shape will do.
const sessionToken = "AQAEAJ1fK2mQx7Vn8pLtRc3bYdW0sHgZi5uOa6TjE9NrXwPvBk4lQg=="

func (s *Service) credentials() map[string]any {
	seed := s.role + s.region

	return map[string]any{
		"Code":            "Success",
		"LastUpdated":     stamp(-2 * time.Hour),
		"Type":            "AWS-HMAC",
		"AccessKeyId":     "ASIA" + strings.ToUpper(httpdecoy.StableID(seed, 16)),
		"SecretAccessKey": secretKey(seed),
		"Token":           sessionCredential(seed),
		"Expiration":      stamp(4 * time.Hour),
	}
}

// secretKey renders 40 characters in the alphabet AWS uses for secret keys.
func secretKey(seed string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	hex := httpdecoy.StableID("secret"+seed, 40)
	out := make([]byte, 0, 40)
	for i := 0; i < 40; i++ {
		out = append(out, alphabet[(int(hex[i])*7+i*13)%len(alphabet)])
	}
	return string(out)
}

// sessionCredential is the long opaque STS token that accompanies temporary
// credentials. Real ones run to a few hundred characters; anything obviously
// short would be the tell.
func sessionCredential(seed string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	hex := httpdecoy.StableID("session"+seed, 360)
	out := make([]byte, 0, 360)
	for i := 0; i < len(hex); i++ {
		out = append(out, alphabet[(int(hex[i])*11+i*5)%len(alphabet)])
	}
	return "IQoJb3JpZ2luX2VjE" + string(out) + "="
}

func (s *Service) identityDocument() map[string]any {
	return map[string]any{
		"accountId":               accountID,
		"architecture":            "x86_64",
		"availabilityZone":        s.region + "a",
		"billingProducts":         nil,
		"devpayProductCodes":      nil,
		"marketplaceProductCodes": nil,
		"imageId":                 imageID,
		"instanceId":              instanceID,
		"instanceType":            "m5.large",
		"kernelId":                nil,
		"pendingTime":             "2026-06-02T11:04:18Z",
		"privateIp":               "10.0.4.31",
		"ramdiskId":               nil,
		"region":                  s.region,
		"version":                 "2017-09-30",
	}
}

const metaDataIndex = `ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
iam/
identity-credentials/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-keys/
reservation-id
security-groups
services/
`

// metaData is the flat key/value half of the EC2 API. Every value is a scalar
// served as text/plain, which is why the map holds strings rather than a
// document.
func (s *Service) metaData() map[string]string {
	hostname := "ip-10-0-4-31." + s.region + ".compute.internal"

	return map[string]string{
		"ami-id":                         imageID,
		"ami-launch-index":               "0",
		"ami-manifest-path":              "(unknown)",
		"hostname":                       hostname,
		"instance-action":                "none",
		"instance-id":                    instanceID,
		"instance-life-cycle":            "on-demand",
		"instance-type":                  "m5.large",
		"local-hostname":                 hostname,
		"local-ipv4":                     "10.0.4.31",
		"mac":                            "0a:3f:6c:12:8e:44",
		"profile":                        "default-hvm",
		"reservation-id":                 "r-04b8e1c93f7a25d60",
		"security-groups":                "app-tier\ninternal-ssh\n",
		"iam":                            "info\nsecurity-credentials/\n",
		"iam/":                           "info\nsecurity-credentials/\n",
		"placement/availability-zone":    s.region + "a",
		"placement/region":               s.region,
		"placement/availability-zone-id": "use1-az4",
		"network/interfaces/macs/":       "0a:3f:6c:12:8e:44/",
		"public-keys/":                   "0=app-deploy",
		"public-keys/0/openssh-key":      deployKey,
	}
}

// userData is the boot script. In practice this is where deployment secrets
// end up, which is why reading it is recorded as a resource_read rather than a
// probe — and why the fabricated one has to look like it might contain some.
const userData = `#cloud-config
package_update: false
write_files:
  - path: /etc/payments/env
    permissions: '0640'
    owner: app:app
    content: |
      APP_ENV=production
      DB_HOST=payments-db.internal
      AWS_REGION=us-east-1
      SENTRY_DSN=https://8c1f4a2e@sentry.internal/7
runcmd:
  - [ systemctl, enable, --now, payments-api ]
`

// deployKey is the public half of a key pair that does not exist. A public key
// gives away nothing — it is here because an instance with no key in its
// metadata is an instance nobody ever logged into.
const deployKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3vQ2mKp8rLxT9wYc4dNb1sZgViJu6Oa5TkE0NrXwPv app-deploy\n"

const apiVersions = `1.0
2007-01-19
2007-03-01
2011-05-01
2012-01-12
2016-09-02
2018-09-24
2019-10-01
2020-10-27
2021-01-03
2021-03-23
2021-07-15
2022-09-24
latest
`

// notFoundHTML is what a real EC2 metadata service returns for an unknown key.
// Anything that reads the body rather than the status code should see the same
// page it would get from the real one.
const notFoundHTML = `<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>404 - Not Found</title>
 </head>
 <body>
  <h1>404 - Not Found</h1>
 </body>
</html>
`

// googleMissingFlavor reproduces the refusal GCP gives a request without the
// Metadata-Flavor header — the guard that exists specifically to stop a browser
// or a naive SSRF from reaching the metadata server by URL alone.
func googleMissingFlavor(path string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang=en>
  <meta charset=utf-8>
  <title>Error 403 (Forbidden)!!1</title>
  <p><b>403.</b> <ins>That’s an error.</ins>
  <p>Your client does not have permission to get URL <code>%s</code> from this server.
  Missing Metadata-Flavor:Google header. <ins>That’s all we know.</ins>
`, path)
}

const googleAccessToken = "ya29.c.b0Aaekm1KpQ7vXn2Lr8TdYc4bWs0ZgHiJu6Oa5TkE9NrXwPvBk4lQgM3fS8dRt1yUvCxAe7ZoIpKjNmLbHgFdSaQwErTyUiOpAsDfGhJkLzXcVbNm"

// googleIdentityToken is the instance identity JWT. The header and payload are
// real base64 of plausible claims so that anything which decodes it sees what
// it expects; the signature is not a signature.
const googleIdentityToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhmMmExYzA3NGQzZTRhMTk5YzZiN2UwZDFmNWEyYjgzIiwidHlwIjoiSldUIn0." +
	"eyJhdWQiOiJodHRwczovL2ludGVybmFsLmV4YW1wbGUiLCJhenAiOiIxMDQ4MjM3MTA5ODM3NDIxOTg3MzQiLCJlbWFpbCI6" +
	"ImFwcC1ydW50aW1lQHByb2plY3QtYXBwLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwiZXhwIjoxNzg0NTE0ODQwfQ." +
	"signature-is-not-a-signature"

// googleMetadata is the GCP flat namespace. The service-account listing is the
// one an intruder walks first: it names every identity the instance can borrow.
func (s *Service) googleMetadata() map[string]string {
	return map[string]string{
		"":                                  "instance/\nproject/\n",
		"instance":                          instanceIndex,
		"instance/id":                       "4821730948217309482",
		"instance/name":                     "app-runtime-01",
		"instance/hostname":                 "app-runtime-01.c.project-app.internal",
		"instance/zone":                     "projects/104823710983/zones/us-central1-a",
		"instance/machine-type":             "projects/104823710983/machineTypes/e2-standard-4",
		"instance/cpu-platform":             "Intel Broadwell",
		"instance/service-accounts":         "default/\napp-runtime@project-app.iam.gserviceaccount.com/\n",
		"instance/service-accounts/default": "aliases\nemail\nidentity\nscopes\ntoken\n",
		"instance/service-accounts/default/email":  "app-runtime@project-app.iam.gserviceaccount.com",
		"instance/service-accounts/default/scopes": "https://www.googleapis.com/auth/cloud-platform\n",
		"instance/attributes":                      "startup-script\nssh-keys\n",
		"instance/attributes/startup-script":       googleStartupScript,
		"instance/network-interfaces/0/ip":         "10.128.0.19",
		"project/project-id":                       "project-app",
		"project/numeric-project-id":               "104823710983",
	}
}

const instanceIndex = `attributes/
cpu-platform
description
disks/
hostname
id
image
machine-type
maintenance-event
name
network-interfaces/
scheduling/
service-accounts/
tags
zone
`

const googleStartupScript = `#!/bin/bash
set -euo pipefail
gcloud secrets versions access latest --secret=payments-db-password > /run/payments-db-password
systemctl enable --now payments-api
`

// azureAccessToken is a managed-identity bearer token. Same shape as a real
// one, signed by nothing.
const azureAccessToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9." +
	"eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzcyZjk4OGJmLTg2" +
	"ZjEtNDFhZi05MWFiLTJkN2NkMDExZGI0Ny8iLCJvaWQiOiI4ZjJhMWMwNy00ZDNlLTRhMTktOWM2Yi03ZTBkMWY1YTJiODMifQ." +
	"signature-is-not-a-signature"

const azureAttestedSignature = "MIIEEgYJKoZIhvcNAQcCoIIEAzCCA/8CAQExDzANBgkqhkiG9w0BAQsFADCCAWQGCSqGSIb3DQEHAaCCAVUEggFR"

var azureAPIVersions = []string{
	"2017-04-02", "2017-08-01", "2017-12-01", "2018-02-01", "2018-04-02",
	"2018-10-01", "2019-02-01", "2019-03-11", "2019-04-30", "2019-06-01",
	"2019-08-01", "2019-08-15", "2019-11-01", "2020-06-01", "2020-07-15",
	"2020-09-01", "2020-10-01", "2020-12-01", "2021-01-01", "2021-02-01",
	"2021-03-01", "2021-05-01", "2021-10-01", "2021-12-13", "2023-07-01",
}

func (s *Service) azureInstance() map[string]any {
	return map[string]any{
		"compute": map[string]any{
			"azEnvironment":     "AzurePublicCloud",
			"location":          "eastus",
			"name":              "app-runtime-01",
			"offer":             "0001-com-ubuntu-server-jammy",
			"osType":            "Linux",
			"publisher":         "Canonical",
			"resourceGroupName": "rg-payments-prod",
			"resourceId": "/subscriptions/3f1a8c40-2b7e-4d69-9a05-c81e7f2d4b93" +
				"/resourceGroups/rg-payments-prod/providers/Microsoft.Compute/virtualMachines/app-runtime-01",
			"sku":            "22_04-lts-gen2",
			"subscriptionId": "3f1a8c40-2b7e-4d69-9a05-c81e7f2d4b93",
			"tags":           "env:production;owner:platform",
			"version":        "22.04.202606100",
			"vmId":           "9d2e7f31-58ac-4d0e-9a17-1c6bb2f4de08",
			"vmSize":         "Standard_D2s_v3",
			"zone":           "1",
		},
		"network": map[string]any{
			"interface": []map[string]any{{
				"ipv4": map[string]any{
					"ipAddress": []map[string]any{
						{"privateIpAddress": "10.1.0.14", "publicIpAddress": ""},
					},
					"subnet": []map[string]any{{"address": "10.1.0.0", "prefix": "24"}},
				},
				"macAddress": "0A3F6C128E44",
			}},
		},
	}
}
