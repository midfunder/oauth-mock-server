package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/pedro-r-marques/auth0-integration-test/auth-mock/pkg/server"
)

type options struct {
	Port             int
	StaticDir        string
	CertificatesPath string
	Debug            bool
}

func (opt *options) Register() {
	execDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal().Err(err)
	}

	flag.IntVar(&opt.Port, "port", 443, "authentication server port")
	flag.StringVar(&opt.StaticDir, "static", path.Join(execDir, "static"), "Directory for static html/css files")
	flag.StringVar(&opt.CertificatesPath, "cert", "localhost", "Pathname containing {.key,.crt} certificate files")
	flag.BoolVar(&opt.Debug, "debug", false, "Enable debug level logging")
}

type FileOpener struct {
	root    string
	pattern *regexp.Regexp
}

func newFileOpener(root string) *FileOpener {
	return &FileOpener{
		root:    root,
		pattern: regexp.MustCompile(`^[[:alpha:]]\w+(\.[a-zA-Z0-9]+)?$`),
	}
}

func (d *FileOpener) Open(name string) (http.File, error) {
	if !strings.HasPrefix(name, "/static/") {
		return nil, os.ErrPermission
	}
	name = name[len("/static/"):]
	if !d.pattern.MatchString(name) {
		return nil, os.ErrPermission
	}
	return os.Open(path.Join(d.root, name))
}

func main() {
	var opt options
	opt.Register()
	flag.Parse()

	if opt.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	srv := server.NewAuthServer(&server.AuthServerOptions{StaticDir: opt.StaticDir})
	mux := http.NewServeMux()
	mux.Handle("/", srv)
	mux.Handle("/static/", http.FileServer(newFileOpener(opt.StaticDir)))

	log.Info().Msg("Starting auth server...")
	certFile := opt.CertificatesPath + ".crt"
	keyFile := opt.CertificatesPath + ".key"
	log.Fatal().Err(
		http.ListenAndServeTLS(fmt.Sprintf(":%d", opt.Port), certFile, keyFile, mux)).
		Msg("ListenAndServe")
}
