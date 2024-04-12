package main

import (
	"errors"
	"os"
	"strings"

	"github.com/buger/jsonparser"

	"flag"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var router = mux.NewRouter()
var trivy_file string

var aptVuln = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "trivy_apt_vulnerability",
		Help: "Current number of vulnerability for a package",
	},
	[]string{"id", "package", "url", "severity", "installedversion", "hostname", "cvss_v2score", "cvss_v3score"},
)

func handler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("bla"))
	if err != nil {
		fmt.Printf("cannot send 200 answer → %v", err)
	}
}

func parse_file(file string) {
	data, _ := os.ReadFile(file)
	hostname, _ := os.Hostname()
	split_host := strings.Split(hostname, ".")
	_, _ = jsonparser.ArrayEach(data, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		id, _ := jsonparser.GetString(value, "VulnerabilityID")
		pkg, _ := jsonparser.GetString(value, "PkgName")
		url, _ := jsonparser.GetString(value, "PrimaryURL")
		severity, _ := jsonparser.GetString(value, "Severity")
		installed_version, _ := jsonparser.GetString(value, "InstalledVersion")
		v3score, _ := jsonparser.GetFloat(value, "CVSS", "nvd", "V3Score")
		v2score, _ := jsonparser.GetFloat(value, "CVSS", "nvd", "V2Score")
		s_v2score := fmt.Sprintf("%g", v2score)
		s_v3score := fmt.Sprintf("%g", v3score)
		if s_v3score == "0" {
			s_v3score = ""
		}
		if s_v2score == "0" {
			s_v2score = ""
		}
		aptVuln.WithLabelValues(id, pkg, url, severity, installed_version, split_host[0], s_v2score, s_v3score).Set(1)
	}, "Results", "[0]", "Vulnerabilities")
}

func reloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			t, err := route.GetPathTemplate()
			if err != nil {
				return err
			}
			fmt.Println(t)
			aptVuln.Reset()
			parse_file(trivy_file)
			return nil
		})
		if err != nil {
			fmt.Println(err)
		}
	} else {
		_, err := w.Write([]byte("Method is not allowed"))
		if err != nil {
			fmt.Printf("cannot send 200 answer → %v", err)
		}
	}
}

func main() {
	flag.StringVar(&trivy_file, "trivy_file", "/tmp/vuln.json", "a string")
	flag.Parse()
	parse_file(trivy_file)

	prometheus.MustRegister(aptVuln)

	router.HandleFunc("/", handler)
	router.HandleFunc("/reload", reloadHandler)
	router.Handle("/metrics", promhttp.Handler())

	err := http.ListenAndServe(":9150", router)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
