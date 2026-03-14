package loglinter

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
)

var sensitiveWords string

var Analyzer = &analysis.Analyzer{
	Name: "loglinter",
	Doc:  "checks log messages for specific rules",
	Run:  run,
}

func init() {
	Analyzer.Flags.StringVar(&sensitiveWords, "sensitive", "password,api_key,token", "comma-separated sensitive words")
}

func run(pass *analysis.Pass) (interface{}, error) {
	badWords := strings.Split(sensitiveWords, ",")

	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selExpFun, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}

			obj := pass.TypesInfo.Uses[selExpFun.Sel]
			if obj == nil {
				return true
			}
			pkg := obj.Pkg()
			if pkg == nil {
				return true
			}

			if pkg.Path() == "log/slog" || pkg.Path() == "go.uber.org/zap" {
				ast.Inspect(call, func(nn ast.Node) bool {
					var textToCheck string
					switch x := nn.(type) {
					case *ast.BasicLit:
						if x.Kind == token.STRING {
							textToCheck = x.Value
						}
					case *ast.Ident:
						textToCheck = x.Name
					}

					if textToCheck != "" {
						lowerText := strings.ToLower(textToCheck)
						for _, w := range badWords {
							if strings.Contains(lowerText, strings.TrimSpace(w)) {
								pass.Reportf(call.Pos(), "log message contains sensitive data")
								return false
							}
						}
					}
					return true
				})

				callFirst, ok := call.Args[0].(*ast.BasicLit)
				if !ok || callFirst.Kind != token.STRING {
					return true
				}

				msg, err := strconv.Unquote(callFirst.Value)
				if err != nil || len(msg) == 0 {
					return true
				}

				runesMsg := []rune(msg)

				if unicode.IsUpper(runesMsg[0]) {

					runesMsg[0] = unicode.ToLower(runesMsg[0])
					fixedString := strconv.Quote(string(runesMsg))

					pass.Report(analysis.Diagnostic{
						Pos:     callFirst.Pos(),
						Message: "log message must start with a lowercase letter",
						SuggestedFixes: []analysis.SuggestedFix{{
							Message: "Make lowercase",
							TextEdits: []analysis.TextEdit{{
								Pos:     callFirst.Pos(),
								End:     callFirst.End(),
								NewText: []byte(fixedString),
							}},
						}},
					})
				}
				if !isValidLogText(runesMsg) {
					pass.Reportf(callFirst.Pos(), "log message must contain only English letters, spaces, and digits")
				}
			}
			return true
		})
	}
	return nil, nil
}

func isValidLogText(msg []rune) bool {
	for _, r := range msg {
		if unicode.Is(unicode.Latin, r) || unicode.IsSpace(r) || unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}
