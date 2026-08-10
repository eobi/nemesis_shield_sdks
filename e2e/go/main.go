// E2E live round-trip for the Go SDK. Builds a real sketch per fixed route via the SDK's own
// BuildSketch, prints the shape hash, then POSTs the batch to the LIVE sketches endpoint.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	nemesis "github.com/eobi/nemesis_shield_sdks/go"
)

func main() {
	token := os.Getenv("NEMESIS_TOKEN")
	c := nemesis.New(token)
	routes := [][2]string{
		{"GET", "/app/incidents/inc_ip_1_2_3_4_1786400000000"},
		{"GET", "/app/network/autogon.ai"},
		{"GET", "/app/applications/f47ac10b-58cc-4372-a567-0e02b2c3d479"},
	}
	var sketches []nemesis.Sketch
	for _, r := range routes {
		s := c.BuildSketch(r[0], r[1], nil, false, 200)
		fmt.Printf("SHAPE %s route=%s hash=%s\n", r[1], s.Route, s.Shape)
		sketches = append(sketches, s)
	}
	body, _ := json.Marshal(map[string]any{"sketches": sketches})
	req, _ := http.NewRequest("POST", "https://shield.nemesislabs.xyz/api/v1/sketches", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("POST_STATUS ERR %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("POST_STATUS %d\n", resp.StatusCode)
}
