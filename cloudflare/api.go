package cloudflare

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/ViRb3/wgcf/v2/config"
	"github.com/ViRb3/wgcf/v2/openapi"
	"github.com/ViRb3/wgcf/v2/util"
	"github.com/ViRb3/wgcf/v2/wireguard"
	"github.com/cockroachdb/errors"
)

const (
	ApiUrl     = "https://api.cloudflareclient.com"
	ApiVersion = "v0a1922"
)

var (
	DefaultHeaders = map[string]string{
		"User-Agent":        "okhttp/3.12.1",
		"CF-Client-Version": "a-6.3-1922",
	}
	DefaultTransport = &http.Transport{
		// Match app's TLS config or API will reject us with code 403 error 1020
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: false,
		// Dynamically resolve current active proxy from our managed pool
		Proxy: func(req *http.Request) (*url.URL, error) {
			if GlobalProxyManager.HasProxies() {
				return GlobalProxyManager.GetProxy(req)
			}
			return http.ProxyFromEnvironment(req)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
)

var apiClient = MakeApiClient(nil)
var apiClientAuth *openapi.APIClient

func MakeApiClient(authToken *string) *openapi.APIClient {
	httpClient := http.Client{Transport: DefaultTransport}
	apiClient := openapi.NewAPIClient(&openapi.Configuration{
		DefaultHeader: DefaultHeaders,
		UserAgent:     DefaultHeaders["User-Agent"],
		Debug:         false,
		Servers: []openapi.ServerConfiguration{
			{URL: ApiUrl},
		},
		HTTPClient: &httpClient,
	})
	if authToken != nil {
		apiClient.GetConfig().DefaultHeader["Authorization"] = "Bearer " + *authToken
	}
	return apiClient
}

func Register(publicKey *wireguard.Key, deviceModel string) (*openapi.Register200Response, error) {
	// Force initial state to Direct Connection for the first attempt
	GlobalProxyManager.SetEnabled(false)

	maxRetries := 5
	if !GlobalProxyManager.HasProxies() {
		maxRetries = 1
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		timestamp := util.GetTimestamp()

		if attempt > 1 && GlobalProxyManager.HasProxies() {
			// Turn proxy mode ON starting from second attempt onwards
			GlobalProxyManager.SetEnabled(true)
			log.Printf("Cloudflare API: [PROXY MODE] Register attempt %d/%d using Proxy: %s", attempt, maxRetries, GlobalProxyManager.GetCurrentProxyStr())
		} else {
			log.Printf("Cloudflare API: [DIRECT MODE] Register attempt %d/%d using Direct Connection", attempt, maxRetries)
		}

		result, _, err := apiClient.DefaultAPI.
			Register(nil, ApiVersion).
			RegisterRequest(openapi.RegisterRequest{
				FcmToken:  "", // not empty on actual client
				InstallId: "", // not empty on actual client
				Key:       publicKey.String(),
				Locale:    "en_US",
				Model:     deviceModel,
				Tos:       timestamp,
				Type:      "Android",
			}).Execute()

		if err == nil {
			log.Printf("Cloudflare API: Registration SUCCESSFUL on attempt %d!", attempt)
			return result, nil
		}

		lastErr = err
		log.Printf("Cloudflare API: Register failed (Attempt %d/%d): %v", attempt, maxRetries, err)

		if attempt < maxRetries {
			if attempt == 1 {
				log.Printf("Cloudflare API: Direct connection failed. Activating dynamic proxy fallback pool for next retries...")
			} else if GlobalProxyManager.HasProxies() {
				log.Printf("Cloudflare API: Active proxy failed. Triggering rotation to next URL...")
				GlobalProxyManager.Rotate()
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	return nil, errors.WithStack(lastErr)
}


type SourceDevice openapi.GetSourceDevice200Response

func GetSourceDevice(ctx *config.Context) (*SourceDevice, error) {
	result, _, err := globalClientAuth(ctx.AccessToken).DefaultAPI.
		GetSourceDevice(nil, ApiVersion, ctx.DeviceId).
		Execute()
	return (*SourceDevice)(result), errors.WithStack(err)
}

func globalClientAuth(authToken string) *openapi.APIClient {
	return MakeApiClient(&authToken)
}

type Account openapi.Account

func GetAccount(ctx *config.Context) (*Account, error) {
	result, _, err := globalClientAuth(ctx.AccessToken).DefaultAPI.
		GetAccount(nil, ctx.DeviceId, ApiVersion).
		Execute()
	castResult := (*Account)(result)
	return castResult, errors.WithStack(err)
}

func UpdateLicenseKey(ctx *config.Context) (*openapi.UpdateAccount200Response, error) {
	result, _, err := globalClientAuth(ctx.AccessToken).DefaultAPI.
		UpdateAccount(nil, ctx.DeviceId, ApiVersion).
		UpdateAccountRequest(openapi.UpdateAccountRequest{License: ctx.LicenseKey}).
		Execute()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

type BoundDevice openapi.BoundDevice

func GetBoundDevices(ctx *config.Context) ([]BoundDevice, error) {
	result, _, err := globalClientAuth(ctx.AccessToken).DefaultAPI.
		GetBoundDevices(nil, ctx.DeviceId, ApiVersion).
		Execute()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var castResult []BoundDevice
	for _, device := range result {
		castResult = append(castResult, BoundDevice(device))
	}
	return castResult, nil
}

func GetSourceBoundDevice(ctx *config.Context) (*BoundDevice, error) {
	result, err := GetBoundDevices(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return FindDevice(result, ctx.DeviceId)
}

func UpdateSourceBoundDeviceName(ctx *config.Context, targetDeviceId string, newName string) (*BoundDevice, error) {
	return updateSourceBoundDevice(ctx, targetDeviceId, openapi.UpdateBoundDeviceRequest{
		Name: &newName,
	})
}

func UpdateSourceBoundDeviceActive(ctx *config.Context, targetDeviceId string, active bool) (*BoundDevice, error) {
	return updateSourceBoundDevice(ctx, targetDeviceId, openapi.UpdateBoundDeviceRequest{
		Active: &active,
	})
}

func updateSourceBoundDevice(ctx *config.Context, targetDeviceId string, data openapi.UpdateBoundDeviceRequest) (*BoundDevice, error) {
	result, _, err := globalClientAuth(ctx.AccessToken).DefaultAPI.
		UpdateBoundDevice(nil, ctx.DeviceId, ApiVersion, targetDeviceId).
		UpdateBoundDeviceRequest(data).
		Execute()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var castResult []BoundDevice
	for _, device := range result {
		castResult = append(castResult, BoundDevice(device))
	}
	return FindDevice(castResult, ctx.DeviceId)
}

func DeleteBoundDevice(ctx *config.Context, targetDeviceId string) error {
	if _, err := globalClientAuth(ctx.AccessToken).DefaultAPI.
		DeleteBoundDevice(nil, ctx.DeviceId, ApiVersion, targetDeviceId).
		Execute(); err != nil {
		return err
	}
	return nil
}
