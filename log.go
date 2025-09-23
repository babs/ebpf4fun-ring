package main

import (
	"github.com/fatih/color"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func initLog(cli *cliOpts) {
	var zapconfig zap.Config
	if cli.logDev {
		zapconfig = zap.NewDevelopmentConfig()
		color.NoColor = false
		zapconfig.EncoderConfig.EncodeLevel = func(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
			colfunc := func(s string, _ ...interface{}) string { return s }
			switch l {
			case zap.DebugLevel:
				colfunc = color.BlueString
			case zap.InfoLevel:
				colfunc = color.GreenString
				// colfunc = color.New(color.FgHiGreen, color.Bold).SprintfFunc()
			case zapcore.WarnLevel:
				colfunc = color.New(color.FgHiYellow, color.Bold).SprintfFunc()
			case zapcore.ErrorLevel | zapcore.DPanicLevel | zapcore.PanicLevel | zapcore.FatalLevel:
				colfunc = color.New(color.FgRed, color.Bold).SprintfFunc()
			}
			enc.AppendString(colfunc(l.CapitalString()))
		}
	} else {
		zapconfig = zap.NewProductionConfig()
	}

	zapconfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	if !cli.logStacktraces {
		zapconfig.DisableStacktrace = true
	}

	// Parse log level from string
	level, err := zapcore.ParseLevel(cli.logLevel)
	if err != nil {
		level = zapcore.InfoLevel
	}
	zapconfig.Level.SetLevel(level)

	logger, _ = zapconfig.Build()
}
