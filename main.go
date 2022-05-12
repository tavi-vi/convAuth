package main

import (
	_ "embed"

	"github.com/adrg/xdg"
	"golang.org/x/term"

	"context"
	"errors"
	"flag"
	"fmt"
	"html/template"
	_ "io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"
)

var authProxyStateDir string
var authProxyDB string
var authProxySock string
var authProxyConfigDir string
var authProxyConfig string

func init() {
	var err error
	authProxyStateDir, err = xdg.DataFile("convAuth")
	if err != nil {
		panic(err)
	}
	authProxyDB = path.Join(authProxyStateDir, "db.json")
	authProxySock = path.Join(authProxyStateDir, "socket")
	authProxyConfigDir, err = xdg.ConfigFile("convAuth")
	authProxyConfig = path.Join(authProxyConfigDir, "config")

}

//go:embed logout.html
var logoutFile []byte

//go:embed login.html
var loginFile string

var loginTemplate = template.Must(template.New("login").Parse(loginFile))

const loginLocation = template.URL("/login")
const cookieName = "go-auth-proxy_session"

type loginTemplateData struct {
	LoginFailure bool
}

type loginRequest struct {
	keeplogged bool
	username   string
	password   string
}

func extractLoginRequest(f url.Values) (loginRequest, bool) {
	var req loginRequest

	un, ok := f["username"]
	if !ok {
		return req, false
	}
	pw, ok := f["password"]
	if !ok {
		return req, false
	}
	kl, ok := f["keeplogged"]
	if !ok {
		kl = []string{"false"}
	}

	// Make sure each field was defined exactly once
	if len(un) != 1 && len(pw) != 1 && len(kl) != 1 && len(un) != 1 {
		return req, false
	}

	req.username = un[0]
	req.password = pw[0]
	if kl[0] == "1" {
		req.keeplogged = true
	} else {
		req.keeplogged = false
	}
	return req, true
}

func cookieAuthz(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	err = authz(cookie.Value, r.Host, r.URL)
	if err == expiredToken {
		log.Printf("Failed token authentication, expired: %s tried to authenticate", r.RemoteAddr)
	} else if err != nil {
		log.Printf("Failed token authentication: %s tried to authenticate", r.RemoteAddr)
	}

	return err == nil
}

func setCookie(w http.ResponseWriter, content string, expires *time.Time) {
	c := http.Cookie{
		Name:  cookieName,
		Value: content,

		Domain:   serverConfig.cookieDomain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if expires != nil {
		c.Expires = *expires
	}
	w.Header().Add("Set-Cookie", c.String())
}

func badRequest(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprint(w, "Bad Request")
	return
}

func serveHttp(ctx context.Context) error {
	h := http.NewServeMux()
	h.HandleFunc(string(loginLocation), func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if cookieAuthz(r) {
				w.Write(logoutFile)
			} else {
				loginTemplate.Execute(w, loginTemplateData{false})
			}
		case "POST":
			r.ParseForm()
			formRequest, ok := r.Form["submit"]
			if !ok {
				badRequest(w)
				return
			}
			switch formRequest[0] {
			case "Log in":
				lr, ok := extractLoginRequest(r.Form)
				if !ok {
					badRequest(w)
					return
				}
				if authn(lr.username, lr.password) {
					log.Printf("Successful password authentication: %s authenticated as %s", r.RemoteAddr, lr.username)

					var expires *time.Time
					cookie, maxExpires := issueToken(lr.username)
					if lr.keeplogged {
						expires = &maxExpires
					} else {
						expires = nil
					}
					setCookie(w, cookie, expires)
					if redir, ok := r.Form["redirect"]; ok {
						http.Redirect(w, r, redir[0], http.StatusSeeOther)
					} else {
						http.Redirect(w, r, r.URL.String(), http.StatusSeeOther)
					}
				} else {
					log.Printf("Failed password authentication: %s tried to authenticate as %s", r.RemoteAddr, lr.username)

					loginTemplate.Execute(w, loginTemplateData{true})
				}
			case "Log out":
				epoch := time.Unix(60, 0)
				setCookie(w, "", &epoch)
				http.Redirect(w, r, r.URL.String(), http.StatusSeeOther)
			case "Log out everywhere":
				if cookieAuthz(r) {
					http.Redirect(w, r, r.URL.String(), http.StatusSeeOther)
				} else {
					http.Redirect(w, r, r.URL.String(), http.StatusSeeOther)
				}
			default:
				badRequest(w)
				return
			}
		default:
			badRequest(w)
			return
		}
	})

	h.HandleFunc("/checkToken", func(w http.ResponseWriter, r *http.Request) {
		if cookieAuthz(r) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Success")
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Failure")
		}
	})

	s := &http.Server{
		Addr:           serverConfig.listenAddress,
		Handler:        h,
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   3 * time.Second,
		MaxHeaderBytes: 1 << 15,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.Shutdown(shutdownCtx)
	}()
	err := s.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

var ExitDeferWaitGroup sync.WaitGroup
var ExitDeferExitCode int = 130

func init() {
	go func() {
		sigChan := make(chan os.Signal)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)

		<-sigChan
		ExitDeferWaitGroup.Wait()
		os.Exit(ExitDeferExitCode)
	}()
}

type ExitDefer struct {
	exitOnce   sync.Once
	sigChan    chan os.Signal
	funcsMutex sync.Mutex
	funcs      []func()
	cancel     func()
}

func NewExitDefer() *ExitDefer {
	ExitDeferWaitGroup.Add(1)
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	ed := ExitDefer{
		cancel:  cancel,
		sigChan: sigChan,
	}
	go func() {
		defer cancel()
		select {
		case <-ctx.Done():
		case <-sigChan:
		}
		ed.Exit()
	}()
	return &ed
}

func (ed *ExitDefer) Exit() {
	ed.exitOnce.Do(func() {
		for i := 1; i <= len(ed.funcs); i++ {
			ed.funcs[len(ed.funcs)-i]()
		}
		ed.cancel()
		signal.Stop(ed.sigChan)
		ExitDeferWaitGroup.Done()
	})
}

func (ed *ExitDefer) Defer(f func()) {
	ed.funcsMutex.Lock()
	defer ed.funcsMutex.Unlock()

	ed.funcs = append(ed.funcs, f)
}

func passwordPrompt() (userEntry, error) {
	edefer := NewExitDefer()
	defer edefer.Exit()

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	edefer.Defer(func() {
		term.Restore(int(os.Stdin.Fd()), oldState)
	})
	t := term.NewTerminal(os.Stdin, "")
	password, err := t.ReadPassword("Password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to read password")
		return userEntry{}, errors.New("Unable to read password")
	}
	algo, hash := passHash(password)
	return userEntry{algo, hash}, nil
}

func setPasswordOffline(username string, force bool) int {
	if !force {
		_, err := os.Stat(authProxySock)
		if !errors.Is(err, os.ErrNotExist) {
			println("Server appears to be running, not updating database.")
			return 75
		}
	} else {
		fmt.Fprintln(os.Stderr, "Any forced changes may be lost or corrupt the database.")
	}
	err := fsUserEntries.Update(authProxyDB)
	if err != nil {
		panic(err)
	}
	entry, err := passwordPrompt()
	if err != nil {
		return 1
	}
	fsUserEntries.Insert(username, entry)
	return 0
}

func subcommand(command string, args []string) int {
	switch command {
	case "passwd":
		fset := flag.NewFlagSet("", flag.ContinueOnError)
		fset.Usage = func() {
			fmt.Fprintf(fset.Output(), "Usage: convauth %s [flag]... [--] <username>\n", command)
			fset.PrintDefaults()
		}
		offline := fset.Bool("offline", false, "Update database directly")
		force := fset.Bool("force", false, "Force database update")
		err := fset.Parse(args)
		if err != nil {
			return 2
		}
		if fset.NArg() != 1 {
			fset.Usage()
			return 2
		}
		username := fset.Arg(0)

		if *offline {
			setPasswordOffline(username, *force)
		} else {
			setPasswordOnline(username)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s", command)
		return 1
	}
	return 0
}

func serve() int {
	sc := make(chan os.Signal)
	signal.Notify(sc, os.Interrupt)

	err := fsUserEntries.Update(authProxyDB)
	if err != nil {
		panic(err)
	}

	err = updateConfig(os.Args[1:])
	if err != nil {
		log.Println("Configuration error:", err)
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	exitCodeChan := make(chan int)

	wg.Add(1)
	go func() {
		err := serveAdminSocket(ctx)
		if err != nil {
			exitCodeChan <- 111
			log.Println("Admin socket server exited with error:", err)
		} else {
			log.Println("Admin socket server exited successfully")
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		err := serveHttp(ctx)
		if err != nil {
			exitCodeChan <- 111
			log.Println("HTTP server exited with error:", err)
		} else {
			log.Println("HTTP socket server exited successfully")
		}
		wg.Done()
	}()

	allExited := make(chan struct{})
	go func() {
		wg.Wait()
		allExited <- struct{}{}
	}()

	var i int
	var exitCode int = 0
EventLoop:
	for {
		select {
		case <-sc:
			if i > 0 {
				return 1
			}
			i++
			println("sigterm")
			cancel()
			// LOG
		case ec := <-exitCodeChan:
			if exitCode == 0 {
				exitCode = ec
			}
		case <-allExited:
			break EventLoop
		}
	}
	return exitCode
}

func main() {
	time.Local = time.UTC // Don't leak our timezone.
	syscall.Umask(0077)   // Make all files default to inaccessible to everyone else.

	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		os.Exit(subcommand(os.Args[1], os.Args[2:]))
	}
	os.Exit(serve())
}