package proxy

import (
	"context"
)

type Logger interface {
	Log(ctx context.Context, format string, args ...interface{})
}

func SetLogger(lg Logger) { default_logger = lg }

/* mute log by default */
var default_logger Logger = LogFn(func(context.Context, string, ...interface{}) {})

type LogFn func(ctx context.Context, format string, args ...interface{})

func (f LogFn) Log(ctx context.Context, format string, args ...interface{}) {
	f(ctx, format, args...)
}

func log(ctx context.Context, format string, args ...interface{}) {
	if val, ok := ctx.Value(traceLogId).(string); ok {
		format = `[` + val + `]` + format
	}
	default_logger.Log(ctx, format, args...)
}

const traceLogId = "$proxy-trace-tag"

func withTraceTag(ctx context.Context, tag string) context.Context {
	return context.WithValue(ctx, traceLogId, tag)
}
