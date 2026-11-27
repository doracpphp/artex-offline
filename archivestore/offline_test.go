package archivestore

import (
	"strings"
	"testing"

	"github.com/doracpphp/artex-offline/offline"
)

// TestOfflineRefusesCloudArchive: in offline mode a cloud bucket endpoint is
// refused at configuration time, while a loopback store (MinIO) is accepted.
func TestOfflineRefusesCloudArchive(t *testing.T) {
	t.Setenv(offline.Env, "1")
	for _, ep := range []string{"https://s3.us-east-1.amazonaws.com", "https://203.0.113.50"} {
		_, err := New(Config{Endpoint: ep, Bucket: "b", AccessKey: "k", SecretKey: "s"})
		if err == nil || !strings.Contains(err.Error(), "offline mode") {
			t.Errorf("%s: want an offline refusal, got %v", ep, err)
		}
	}
	if _, err := New(Config{Endpoint: "http://127.0.0.1:9000", Bucket: "b", AccessKey: "k", SecretKey: "s", PathStyle: true}); err != nil {
		t.Errorf("a loopback archive store must be accepted: %v", err)
	}
}
