// Live demo app - a real net/http server guarded by the Go SDK middleware.
package main

import (
	"net/http"
	"os"

	nemesis "github.com/eobi/nemesis_shield_sdks/go"
)

func main() {
	c := nemesis.NewWithEndpoint(os.Getenv("NEMESIS_TOKEN"), os.Getenv("NEMESIS_ENDPOINT"))
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	http.ListenAndServe("127.0.0.1:"+os.Getenv("PORT"), h)
}
