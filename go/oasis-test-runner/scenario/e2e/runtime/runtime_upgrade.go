package runtime

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
)

// RuntimeUpgrade is the runtime upgrade scenario.
var RuntimeUpgrade scenario.Scenario = newRuntimeUpgradeImpl()

const versionActivationTimeout = 15 * time.Second

type runtimeUpgradeImpl struct {
	Scenario

	upgradedRuntimeIndex int
}

func newRuntimeUpgradeImpl() scenario.Scenario {
	return &runtimeUpgradeImpl{
		Scenario: *NewScenario(
			"runtime-upgrade",
			NewTestClient().WithScenario(InsertRemoveEncWithSecretsScenario),
		),
	}
}

func (sc *runtimeUpgradeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	if sc.upgradedRuntimeIndex, err = sc.UpgradeComputeRuntimeFixture(f, true); err != nil {
		return nil, err
	}

	return f, nil
}

func (sc *runtimeUpgradeImpl) Clone() scenario.Scenario {
	return &runtimeUpgradeImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *runtimeUpgradeImpl) Run(ctx context.Context, childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Start the network and run the test client.
	if err := sc.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}
	if err := sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return err
	}

	// Discover bundles.
	bundles, err := findBundles(sc.Net.BasePath())
	if err != nil {
		return err
	}

	// Determine the port on which the nodes are trying to fetch bundles.
	rawURL := sc.Net.Clients()[0].Config.Runtime.Repositories[0]
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	port := parsedURL.Port()

	// Start serving bundles.
	server := newBundleServer(port, bundles, sc.Logger)
	server.Start()
	defer server.Stop()

	// Upgrade the compute runtime.
	if err := sc.UpgradeComputeRuntime(ctx, childEnv, cli, sc.upgradedRuntimeIndex, 0); err != nil {
		return err
	}

	// Verify that all client and compute nodes requested bundle from the server.
	n := 2 * (len(sc.Net.Clients()) + len(sc.Net.ComputeWorkers()))
	if m := server.getRequestCount(); m != n {
		return fmt.Errorf("invalid number of bundle requests (got: %d, expected: %d)", m, n)
	}

	// Run client again.
	sc.Logger.Info("starting a second client to check if runtime works")
	sc.Scenario.TestClient = NewTestClient().WithSeed("seed2").WithScenario(InsertRemoveEncWithSecretsScenarioV2)
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}

type bundleServer struct {
	startOne cmSync.One

	port   string
	server *http.Server

	bundles map[string]string

	requestCount uint64

	logger *logging.Logger
}

func newBundleServer(port string, bundles map[string]string, logger *logging.Logger) *bundleServer {
	return &bundleServer{
		startOne: cmSync.NewOne(),
		port:     port,
		bundles:  bundles,
		logger:   logger,
	}
}

func (s *bundleServer) Start() {
	s.startOne.TryStart(s.run)
}

func (s *bundleServer) Stop() {
	s.startOne.TryStop()
}

func (s *bundleServer) run(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	s.server = &http.Server{
		Addr:              ":" + s.port,
		Handler:           mux,
		ReadHeaderTimeout: time.Minute,
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = s.server.ListenAndServe()
	}()

	<-ctx.Done()

	s.server.Close()
}

func (s *bundleServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	s.logger.Info("handling request",
		"path", r.URL.Path,
	)

	if strings.HasSuffix(r.URL.Path, bundle.FileExtension) {
		s.handleGetBundle(w, r)
	} else {
		s.handleGetMetadata(w, r)
	}
}

func (s *bundleServer) handleGetMetadata(w http.ResponseWriter, r *http.Request) {
	manifestHash := path.Base(r.URL.Path)
	content := []byte(fmt.Sprintf("http://127.0.0.1:%s/%s%s\n", s.port, manifestHash, bundle.FileExtension))

	w.Header().Set("Content-Disposition", "attachment; filename=metadata.txt")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)

	atomic.AddUint64(&s.requestCount, 1)
}

func (s *bundleServer) handleGetBundle(w http.ResponseWriter, r *http.Request) {
	filename := path.Base(r.URL.Path)

	path, ok := s.bundles[filename]
	if !ok {
		http.Error(w, "Bundle not found", http.StatusNotFound)
		return
	}

	content, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "Error reading bundle", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=bundle.orc")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)

	atomic.AddUint64(&s.requestCount, 1)
}

func (s *bundleServer) getRequestCount() int {
	return int(atomic.LoadUint64(&s.requestCount))
}

func findBundles(dir string) (map[string]string, error) {
	bundles := make(map[string]string)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "runtime-") {
			subDir := filepath.Join(dir, entry.Name())

			runtimeBundles, err := findBundlesIn(subDir)
			if err != nil {
				return nil, err
			}

			maps.Insert(bundles, maps.All(runtimeBundles))
		}
	}

	return bundles, nil
}

func findBundlesIn(dir string) (map[string]string, error) {
	bundles := make(map[string]string)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), bundle.FileExtension) {
			continue
		}

		path := filepath.Join(dir, entry.Name())

		bnd, err := bundle.Open(path)
		if err != nil {
			return nil, err
		}

		bundles[bnd.GenerateFilename()] = path
	}

	return bundles, nil
}
