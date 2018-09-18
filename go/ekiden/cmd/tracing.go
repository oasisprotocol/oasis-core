package cmd

import (
	"io"

	jaeger "github.com/uber/jaeger-client-go"
	jaegercfg "github.com/uber/jaeger-client-go/config"
)

func initTracing(serviceName string) (io.Closer, error) {
	cfg, err := jaegercfg.FromEnv()
	if err != nil {
		return nil, err
	}

	return cfg.InitGlobalTracer(serviceName, jaegercfg.Logger(jaeger.StdLogger))
}
