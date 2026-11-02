// Package server assembles the HTTP stack: request id / logging / panic recovery, body limit, IP rate limits,
// OpenAPI request validation (kin-openapi), the generated chi router and the strict handlers with per-operation
// authentication. cmd/api and the e2e tests build the server through New.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cryptoapp/api/internal/apigen"
	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/auth"
	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/config"
	"github.com/cryptoapp/api/internal/handlers"
	"github.com/cryptoapp/api/internal/lockout"
	"github.com/cryptoapp/api/internal/pin"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/ratelimit"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

const MaxBody = 16 << 10

func init() {
	// kin-openapi ignores unregistered formats: register `uuid` so header/path parameters declared `format: uuid` (which
	// carry no pattern in the contract) are really checked (lowercase canonical form, like the Uuid schema).
	openapi3.DefineStringFormatValidator("uuid", openapi3.NewRegexpFormatValidator(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`))
}

type Options struct {
	Cfg      *config.Config
	Pool     *pgxpool.Pool
	Clk      clock.Clock
	Log      *slog.Logger
	AuditLog *slog.Logger
	Hasher   *pin.Hasher // optional override (tests use tiny Argon2 params)
	Hooks    handlers.Hooks
}

type App struct {
	Handler http.Handler
	Server  *handlers.Server
	Store   *store.Store
	Hasher  *pin.Hasher
	Limiter *ratelimit.Limiter
	Doc     *openapi3.T
}

// NewHasher builds the pepper-aware hasher from config.
func NewHasher(cfg *config.Config) (*pin.Hasher, error) {
	peppers := map[int16][]byte{cfg.PepperVersion: cfg.Pepper}
	if len(cfg.PepperOld) > 0 {
		peppers[cfg.PepperOldVersion] = cfg.PepperOld
	}
	return pin.NewHasher(peppers, cfg.PepperVersion, pin.Params{MemoryKiB: cfg.Argon2.MemoryKiB, Time: cfg.Argon2.Time, Parallelism: cfg.Argon2.Parallelism},
		cfg.Argon2.Concurrency, 2*time.Second)
}

func New(o Options) (*App, error) {
	st := store.New(o.Pool)
	hasher := o.Hasher
	if hasher == nil {
		var err error
		if hasher, err = NewHasher(o.Cfg); err != nil {
			return nil, err
		}
	}
	tokens, err := auth.NewTokens(o.Cfg.SigningSeed, o.Clk, o.Cfg.AccessTTL)
	if err != nil {
		return nil, err
	}
	aw := audit.New(st, o.AuditLog, o.Clk, o.Cfg.AuditChain)
	ac := auth.DefaultConfig()
	ac.UnlockWindow, ac.IdleWindow = o.Cfg.UnlockWindow, o.Cfg.IdleWindow
	as := &auth.Service{St: st, Tok: tokens, Clk: o.Clk, Cfg: ac, Audit: aw}
	lk := &lockout.Service{St: st, Hasher: hasher, Clk: o.Clk, Audit: aw, Schedule: o.Cfg.LockSchedule}
	lim := ratelimit.New(o.Clk)
	hs := handlers.New(handlers.Server{Cfg: o.Cfg, St: st, Clk: o.Clk, Log: o.Log, Audit: aw, Auth: as, Lock: lk, Hasher: hasher, Lim: lim, Hooks: o.Hooks})

	doc, err := apigen.GetSpec()
	if err != nil {
		return nil, err
	}
	router, err := validatorRouter()
	if err != nil {
		return nil, err
	}

	b := &builder{o: o, hs: hs, auth: as, aw: aw, lim: lim, router: router}
	strict := apigen.NewStrictHandlerWithOptions(hs, []apigen.StrictMiddlewareFunc{b.authMiddleware}, apigen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  func(w http.ResponseWriter, r *http.Request, err error) { httpx.Validation().Write(w) },
		ResponseErrorHandlerFunc: b.writeErr,
	})
	api := chi.NewRouter()
	api.Use(routeCapture)
	apigen.HandlerWithOptions(strict, apigen.ChiServerOptions{
		BaseURL: "/v1", BaseRouter: api,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) { httpx.Validation().Write(w) },
	})
	nf := func(w http.ResponseWriter, r *http.Request) { httpx.NotFound().Write(w) }
	api.NotFound(nf)
	api.MethodNotAllowed(nf)

	root := chi.NewRouter()
	root.Use(httpx.Base(o.Log, o.Cfg.TrustedProxy), b.requireHTTPSInProd, httpx.BodyLimit(MaxBody), b.ipLimits, b.validate)
	root.Handle("/v1/*", api)
	root.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/v1/healthz"
		api.ServeHTTP(w, r2)
	})
	root.NotFound(nf)
	root.MethodNotAllowed(nf)
	return &App{Handler: root, Server: hs, Store: st, Hasher: hasher, Limiter: lim, Doc: doc}, nil
}

// validatorRouter builds the kin-openapi router used for request validation. The validator gets its own copy of the
// document: servers are cleared (paths are matched after stripping /v1; the spec's server URL is relative) and security
// requirements are dropped (authentication is done by authMiddleware, so a malformed Authorization header must end in
// 401, not in a validation 400).
func validatorRouter() (routers.Router, error) {
	vdoc, err := apigen.GetSpec()
	if err != nil {
		return nil, err
	}
	vdoc.Servers, vdoc.Security = nil, nil
	for _, item := range vdoc.Paths.Map() {
		for _, op := range item.Operations() {
			op.Security = &openapi3.SecurityRequirements{}
		}
	}
	return legacy.NewRouter(vdoc)
}

// requireHTTPSInProd (M-05): with ENV=prod the server only trusts a TLS-terminating proxy; plain-HTTP requests are refused.
func (b *builder) requireHTTPSInProd(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.o.Cfg.Env == "prod" && r.TLS == nil && !(b.o.Cfg.TrustedProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")) {
			httpx.Validation().Write(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// routeCapture records the matched route template for the request log after the handler returns.
func routeCapture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if rc := chi.RouteContext(r.Context()); rc != nil {
			route := strings.Replace(rc.RoutePattern(), "/v1/v1/", "/v1/", 1)
			if strings.HasPrefix(route, "/healthz") {
				route = "/healthz"
			}
			httpx.InfoFrom(r.Context()).Route = route
		}
	})
}

type builder struct {
	o      Options
	hs     *handlers.Server
	auth   *auth.Service
	aw     *audit.Writer
	lim    *ratelimit.Limiter
	router routers.Router
}

func (b *builder) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpx.Error
	if errors.As(err, &he) {
		he.Write(w)
		return
	}
	b.o.Log.ErrorContext(r.Context(), "unhandled error", "component", "http", "err_class", "unhandled")
	httpx.Internal().Write(w)
}

// validate checks every request against the canonical OpenAPI document (types, patterns, enums, additionalProperties,
// required headers, oneOf). Any failure is the generic 400 VALIDATION_ERROR.
func (b *builder) validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		vr := r.Clone(r.Context())
		u := *r.URL
		u.Path = strings.TrimPrefix(r.URL.Path, "/v1")
		u.RawPath = ""
		vr.URL = &u
		route, params, err := b.router.FindRoute(vr)
		if err != nil {
			next.ServeHTTP(w, r) // unknown route: chi answers 404
			return
		}
		in := &openapi3filter.RequestValidationInput{Request: vr, PathParams: params, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc}}
		if err := openapi3filter.ValidateRequest(r.Context(), in); err != nil {
			httpx.Validation().Write(w)
			return
		}
		r.Body = vr.Body
		next.ServeHTTP(w, r)
	})
}

// ipLimits applies the per-IP rows of SEC-057 before anything is hashed or written.
func (b *builder) ipLimits(next http.Handler) http.Handler {
	l := b.o.Cfg.Limits
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ip := httpx.InfoFrom(ctx).IP
		check := func(class string, lim config.Limit, headers bool) bool {
			if lim.N <= 0 {
				return true
			}
			res := b.lim.Allow(class+":"+ip, lim)
			if res.Allowed {
				if headers {
					w.Header().Set("RateLimit-Limit", itoa(res.Limit))
					w.Header().Set("RateLimit-Remaining", itoa(res.Remaining))
					w.Header().Set("RateLimit-Reset", itoa(res.ResetSec))
				}
				return true
			}
			b.aw.Emit(ctx, audit.Event{Type: audit.RateLimited, Result: "fail", Meta: map[string]any{"limit_class": class}})
			httpx.RateLimited(res.RetryAfter, &httpx.RateInfo{Limit: res.Limit, Remaining: 0, Reset: res.ResetSec}).Write(w)
			return false
		}
		if !check("ip-global", l.GlobalIP, false) {
			return
		}
		if r.Method == http.MethodPost {
			switch r.URL.Path {
			case "/v1/auth/demo-login":
				// Per-IP rules FIRST: only requests that passed them feed the global breaker (M-04), so one IP cannot open it for everyone.
				if !check("demo-ip-min", l.DemoLoginIPMin, true) || !check("demo-ip-hour", l.DemoLoginIPHour, false) {
					return
				}
				if br := b.lim.Breaker(l.DemoLoginGlobal, l.DemoBreakerOpenFor); !br.Allowed {
					b.aw.Emit(ctx, audit.Event{Type: audit.RateLimited, Result: "fail", Meta: map[string]any{"limit_class": "demo-breaker"}})
					httpx.RateLimited(br.RetryAfter, &httpx.RateInfo{Limit: br.Limit, Remaining: 0, Reset: br.ResetSec}).Write(w)
					return
				}
			case "/v1/auth/pin/verify":
				if !check("pinverify-ip", l.PinVerifyIP, true) {
					return
				}
			case "/v1/auth/biometric/challenge":
				if !check("bio-challenge-ip", l.BioChallengeIP, false) {
					return
				}
			case "/v1/auth/biometric/verify":
				if !check("bio-verify-ip", l.BioVerifyIP, false) {
					return
				}
			case "/v1/auth/refresh":
				if !check("refresh-ip", l.RefreshIP, false) {
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authMiddleware authenticates per operation (the contract's security schemes) before the handler runs.
func (b *builder) authMiddleware(next apigen.StrictHandlerFunc, op string) apigen.StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req interface{}) (interface{}, error) {
		tok := auth.BearerToken(r.Header.Get("Authorization"))
		var p *auth.Principal
		var herr *httpx.Error
		switch op {
		case "Healthz", "DemoLogin":
		case "RegisterDevice":
			p, herr = b.auth.Bootstrap(ctx, tok, "pin-setup", "pin-verify", "pin-reset")
		case "SetPin":
			p, herr = b.auth.Bootstrap(ctx, tok, "pin-setup")
		case "ResetPin":
			p, herr = b.auth.Bootstrap(ctx, tok, "pin-reset")
		case "VerifyPin":
			rq, _ := req.(apigen.VerifyPinRequestObject)
			if rq.Body == nil {
				return nil, httpx.Validation()
			}
			p, herr = b.auth.DeviceCredential(ctx, tok, uuid.UUID(rq.Body.DeviceId))
		case "BiometricChallenge": // contract v1.1 (D-18): device credential required, no side effects on the token
			rq, _ := req.(apigen.BiometricChallengeRequestObject)
			if rq.Body == nil {
				return nil, httpx.Validation()
			}
			p, herr = b.auth.DeviceCredential(ctx, tok, uuid.UUID(rq.Body.DeviceId))
		case "BiometricVerify":
			rq, _ := req.(apigen.BiometricVerifyRequestObject)
			if rq.Body == nil {
				return nil, httpx.Validation()
			}
			p, herr = b.auth.DeviceCredential(ctx, tok, uuid.UUID(rq.Body.DeviceId))
		case "Refresh":
			ctx = handlers.WithBearer(ctx, tok)
		case "ChangePin":
			p, herr = b.auth.Access(ctx, tok, true)
		default:
			p, herr = b.auth.Access(ctx, tok, false)
		}
		if herr != nil {
			return nil, herr
		}
		if p != nil {
			ctx = handlers.WithPrincipal(ctx, p)
			if p.DeviceID != uuid.Nil {
				httpx.InfoFrom(ctx).SetActor(p.UserID.String(), p.DeviceID.String())
			} else {
				httpx.InfoFrom(ctx).SetActor(p.UserID.String(), "")
			}
		}
		return next(ctx, w, r, req)
	}
}

// SeedDemo creates the configured demo users with mock balances (idempotent).
func SeedDemo(ctx context.Context, st *store.Store, cfg *config.Config, clk clock.Clock) error {
	for _, name := range cfg.Usernames() {
		id, err := st.Q.SeedUser(ctx, db.SeedUserParams{ID: uuid.New(), Username: name, CreatedAt: clk.Now()})
		if err != nil {
			return err
		}
		for asset, amt := range map[string]string{"BTC": "0.15", "ETH": "1.2", "USDC": "93.2"} {
			if err := st.Q.SeedBalance(ctx, db.SeedBalanceParams{UserID: id, Asset: asset, Amount: numeric(amt)}); err != nil {
				return err
			}
		}
	}
	return nil
}
