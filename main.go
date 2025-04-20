package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"

	"github.com/caarlos0/env"
	"github.com/dghubble/oauth1"
	"github.com/google/go-github/v71/github"
)

const name = "sponsorship-notify"

const version = "0.0.4"

var revision = "HEAD"

type config struct {
	ClientToken   string `env:"SPONSORSHIP_NOTIFY_CLIENT_TOKEN,required"`
	ClientSecret  string `env:"SPONSORSHIP_NOTIFY_CLIENT_SECRET,required"`
	AccessToken   string `env:"SPONSORSHIP_NOTIFY_ACCESS_TOKEN,required"`
	AccessSecret  string `env:"SPONSORSHIP_NOTIFY_ACCESS_SECRET,required"`
	WebHookSecret string `env:"SPONSORSHIP_WEBHOOK_SECRET,required"`
}

const (
	UploadMediaEndpoint = "https://upload.twitter.com/1.1/media/upload.json"
	ManageTweetEndpoint = "https://api.twitter.com/2/tweets"
)

//go:embed image.png
var imageBytes []byte

func post(ctx context.Context, cfg *config) error {
	config := oauth1.NewConfig(cfg.ClientToken, cfg.ClientSecret)
	token := oauth1.NewToken(cfg.AccessToken, cfg.AccessSecret)
	httpClient := config.Client(oauth1.NoContext, token)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("media", "image.png")
	if err != nil {
		log.Fatal("Error creating form file:", err)
		return err
	}

	_, err = part.Write(imageBytes)
	if err != nil {
		log.Fatal("Error copying file content:", err)
		return err
	}

	err = writer.Close()
	if err != nil {
		log.Fatal("Error closing writer:", err)
		return err
	}

	req, err := http.NewRequest("POST", UploadMediaEndpoint, &body)
	if err != nil {
		log.Fatal("Error creating request:", err)
		return err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatal("Error sending request:", err)
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading response:", err)
		return err
	}

	mediaID, err := extractMediaID(string(respBody))
	if err != nil {
		log.Fatal("Failed to extract media ID:", err)
		return err
	}

	tweetBody, err := json.Marshal(map[string]any{
		"text": "ありがとうございます 🤗 #GitHubSponsors",
		"media": map[string]any{
			"media_ids": []string{mediaID},
		},
	})
	if err != nil {
		log.Fatal("Error marshaling tweet data:", err)
		return err
	}

	req, err = http.NewRequest("POST", ManageTweetEndpoint, bytes.NewBuffer(tweetBody))
	if err != nil {
		log.Fatal("Error creating tweet request:", err)
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err = httpClient.Do(req)
	if err != nil {
		log.Fatal("Error sending tweet request:", err)
		return err
	}
	defer resp.Body.Close()

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading tweet response:", err)
		return err
	}

	return nil
}

type UploadMediaResponse struct {
	MediaIDString string `json:"media_id_string"`
}

func extractMediaID(respBody string) (string, error) {
	var uploadResponse UploadMediaResponse
	err := json.Unmarshal([]byte(respBody), &uploadResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}
	return uploadResponse.MediaIDString, nil
}

func verifySignature(message []byte, messageMAC string, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(message)
	expectedMAC := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(messageMAC), []byte(expectedMAC))
}

func handleWebhook(cfg *config) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintln(w, "only POST is supported")
			return
		}

		sig := req.Header.Get("X-Hub-Signature-256")
		if sig == "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Missing X-Hub-Signature-256")
			return
		}

		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Failed to read request body")
			return
		}

		if !verifySignature(bodyBytes, sig, cfg.WebHookSecret) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(w, "Wrong signature")
			return
		}

		var sponsorShipEvent github.SponsorshipEvent
		if err = json.Unmarshal(bodyBytes, &sponsorShipEvent); err != nil {
			fmt.Println("Failed to parse request body", err)
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Failed to parse request body")
			return
		}

		if sponsorShipEvent.Action != nil && *sponsorShipEvent.Action == "created" {
			err = post(context.Background(), cfg)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, "Failed to send notify")
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	}
}
func main() {
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "show version")
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", handleWebhook(&cfg))

	log.Println("Listening on port", 5000)
	log.Fatal(http.ListenAndServe(":5000", nil))
}
