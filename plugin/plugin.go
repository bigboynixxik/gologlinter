package main

import (
	"loglinter"

	"golang.org/x/tools/go/analysis"
)

type analyzerPlugin struct{}

func (*analyzerPlugin) GetAnalyzers() []*analysis.Analyzer {
	return []*analysis.Analyzer{
		loglinter.Analyzer,
	}
}

var AnalyzerPlugin analyzerPlugin
