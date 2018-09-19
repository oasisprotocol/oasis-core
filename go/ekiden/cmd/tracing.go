package cmd

import (
	"io"

	"github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"
)

func initTracing(serviceName string) (io.Closer, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, err
	}

	return cfg.InitGlobalTracer(serviceName, config.Logger(jaeger.StdLogger))
}
