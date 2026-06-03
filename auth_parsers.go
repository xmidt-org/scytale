// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"regexp"
	"strings"

	jwtv4 "github.com/golang-jwt/jwt/v4"
	"github.com/xmidt-org/bascule"
	"github.com/xmidt-org/bascule/basculehttp"
	"github.com/xmidt-org/clortho"
	gozap "go.uber.org/zap"
)

const jwtTokenType = "jwt"

type tokenType interface {
	TokenType() string
}

type jwtToken struct {
	principal string
	claims    map[string]interface{}
}

func (t *jwtToken) Principal() string {
	return t.principal
}

func (t *jwtToken) Get(key string) (any, bool) {
	if t == nil || t.claims == nil {
		return nil, false
	}

	value, ok := t.claims[key]
	return value, ok
}

func (t *jwtToken) TokenType() string {
	return jwtTokenType
}

type jwtTokenParser struct {
	resolver clortho.Resolver
	logger   *gozap.Logger
	leeway   Leeway
}

func (jtp *jwtTokenParser) Parse(ctx context.Context, raw string) (bascule.Token, error) {
	if raw == "" {
		return nil, bascule.ErrMissingCredentials
	}

	claims := jwtv4.MapClaims{}
	parser := jwtv4.Parser{SkipClaimsValidation: true}
	token, err := parser.ParseWithClaims(raw, claims, func(token *jwtv4.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtv4.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing or invalid key ID in JWT header")
		}

		clorthoKey, err := jtp.resolver.Resolve(ctx, keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve JWT signing key: %w", err)
		}

		var publicKey interface{}
		switch k := clorthoKey.(type) {
		case interface{ PublicKey() *rsa.PublicKey }:
			publicKey = k.PublicKey()
		case interface{ Key() interface{} }:
			publicKey = k.Key()
		default:
			return nil, fmt.Errorf("unsupported key type: %T", clorthoKey)
		}

		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected RSA public key, got %T", publicKey)
		}

		return rsaKey, nil
	})

	if err != nil {
		if jtp.logger != nil {
			jtp.logger.Error("JWT parsing failed", gozap.Error(err))
		}
		return nil, bascule.ErrInvalidCredentials
	}

	if !token.Valid {
		return nil, bascule.ErrBadCredentials
	}

	if err := validateTimeClaimsWithLeeway(claims, jtp.leeway); err != nil {
		if jtp.logger != nil {
			jtp.logger.Error("JWT temporal claim validation failed", gozap.Error(err))
		}

		return nil, bascule.ErrBadCredentials
	}

	parsedClaims, ok := token.Claims.(jwtv4.MapClaims)
	if !ok {
		return nil, bascule.ErrInvalidCredentials
	}

	principal, _ := parsedClaims["sub"].(string)
	if principal == "" {
		if user, ok := parsedClaims["user"].(string); ok {
			principal = user
		} else if username, ok := parsedClaims["username"].(string); ok {
			principal = username
		}
	}

	claimsMap := make(map[string]interface{}, len(parsedClaims))
	for k, v := range parsedClaims {
		claimsMap[k] = v
	}

	return &jwtToken{principal: principal, claims: claimsMap}, nil
}

func validateTimeClaimsWithLeeway(claims jwtv4.MapClaims, leeway Leeway) error {
	now := jwtv4.TimeFunc().Unix()

	if !claims.VerifyExpiresAt(now+leeway.EXP, false) {
		return fmt.Errorf("token is expired")
	}

	if !claims.VerifyIssuedAt(now-leeway.IAT, false) {
		return fmt.Errorf("token used before issued")
	}

	if !claims.VerifyNotBefore(now-leeway.NBF, false) {
		return fmt.Errorf("token is not valid yet")
	}

	return nil
}

type basicAllowedTokenParser struct {
	allowed map[string]string
}

func (batp basicAllowedTokenParser) Parse(ctx context.Context, raw string) (bascule.Token, error) {
	token, err := (basculehttp.BasicTokenParser{}).Parse(ctx, raw)
	if err != nil {
		return nil, err
	}

	var basicToken basculehttp.BasicToken
	if !bascule.TokenAs(token, &basicToken) {
		return nil, bascule.ErrInvalidCredentials
	}

	expectedPassword, ok := batp.allowed[basicToken.UserName()]
	if !ok || basicToken.Password() != expectedPassword {
		return nil, bascule.ErrBadCredentials
	}

	return token, nil
}

type endpointRegexCheck struct {
	prefixToMatch   *regexp.Regexp
	acceptAllMethod string
}

func newEndpointRegexCheck(prefix, acceptAllMethod string) (endpointRegexCheck, error) {
	matchPrefix, err := regexp.Compile("^" + prefix + "(.+):(.+?)$")
	if err != nil {
		return endpointRegexCheck{}, fmt.Errorf("failed to compile prefix [%v]: %w", prefix, err)
	}

	return endpointRegexCheck{
		prefixToMatch:   matchPrefix,
		acceptAllMethod: acceptAllMethod,
	}, nil
}

func (r endpointRegexCheck) authorized(capability, urlToMatch, methodToMatch string) bool {
	matches := r.prefixToMatch.FindStringSubmatch(capability)
	if matches == nil || len(matches) < 3 {
		return false
	}

	method := matches[2]
	if method != r.acceptAllMethod && method != strings.ToLower(methodToMatch) {
		return false
	}

	re, err := regexp.Compile(urlPathNormalization(matches[1]))
	if err != nil {
		return false
	}

	matchIdxs := re.FindStringIndex(urlPathNormalization(urlToMatch))
	if matchIdxs == nil || matchIdxs[0] != 0 {
		return false
	}

	return true
}

func urlPathNormalization(url string) string {
	if url == "" {
		return "/"
	}

	if url[0] == '/' {
		return url
	}

	return "/" + url
}

func trimVersionPrefix(path string) string {
	for _, prefix := range []string{"/" + apiBase + "/", "/api/" + prevAPIVersion + "/"} {
		if strings.HasPrefix(path, prefix) {
			return "/" + strings.TrimPrefix(path, prefix)
		}
	}

	return path
}

func determinePartnerMetric(partners []string) string {
	if len(partners) < 1 {
		return "none"
	}

	if len(partners) == 1 {
		if partners[0] == "*" {
			return "wildcard"
		}

		return partners[0]
	}

	for _, partner := range partners {
		if partner == "*" {
			return "wildcard"
		}
	}

	return "many"
}

func determineEndpointMetric(endpoints []*regexp.Regexp, urlHit string) string {
	for _, re := range endpoints {
		idxs := re.FindStringIndex(urlHit)
		if idxs == nil {
			continue
		}

		if idxs[0] == 0 {
			return re.String()
		}
	}

	return "not_recognized"
}
