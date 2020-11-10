/*
Copyright 2020 The KubeSphere Authors.

author:Nanjo_Fan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmictoauth

import (
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/identityprovider"
	"kubesphere.io/kubesphere/pkg/apiserver/authentication/oauth"
)

type CmictOauth struct {
	// ClientID is the application's ID.
	ClientID string `json:"clientID" yaml:"clientID"`

	// ClientSecret is the application's secret.
	ClientSecret string `json:"-" yaml:"clientSecret"`

	// Endpoint contains the resource server's token endpoint
	// URLs. These are constants specific to each server and are
	// often available via site-specific packages, such as
	// google.Endpoint or github.Endpoint.
	Endpoint Endpoint `json:"endpoint" yaml:"endpoint"`

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string `json:"redirectURL" yaml:"redirectURL"`

	// Scope specifies optional requested permissions.
	Scopes []string `json:"scopes" yaml:"scopes"`
}

// Endpoint represents an OAuth 2.0 provider's authorization and token
// endpoint URLs.
type Endpoint struct {
	AuthURL     string `json:"authURL" yaml:"authURL"`
	TokenURL    string `json:"tokenURL" yaml:"tokenURL"`
	UserInfoURL string `json:"user_info_url" yaml:"userInfoUrl"`
}

// CmictIdentity is custom data
type CmictIdentity struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

func init() {
	identityprovider.RegisterOAuthProvider(&CmictOauth{})
}

func (a *CmictOauth) Type() string {
	return "CmictOauthProvider"
}

func (a *CmictOauth) Setup(options *oauth.DynamicOptions) (identityprovider.OAuthProvider, error) {
	data, err := yaml.Marshal(options)
	if err != nil {
		return nil, err
	}
	var provider CmictOauth
	err = yaml.Unmarshal(data, &provider)
	if err != nil {
		return nil, err
	}
	return &provider, nil
}

func (a CmictIdentity) GetName() string {
	return a.Username
}

func (a CmictIdentity) GetEmail() string {
	return a.Email
}

// IdentityExchange does data analysis
func (a *CmictOauth) IdentityExchange(code string) (identityprovider.Identity, error) {
	config := oauth2.Config{
		ClientID:     a.ClientID,
		ClientSecret: a.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   a.Endpoint.AuthURL,
			TokenURL:  a.Endpoint.TokenURL,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: a.RedirectURL,
		Scopes:      a.Scopes,
	}
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}

	resp, err := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token)).Get(a.Endpoint.UserInfoURL)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)

	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var cmictIdentity CmictIdentity
	err = json.Unmarshal(data, &cmictIdentity)
	if err != nil {
		return nil, err
	}

	return cmictIdentity, nil
}
