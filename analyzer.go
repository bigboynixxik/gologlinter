package loglinter

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
)

var Analyzer = &analysis.Analyzer{
	Name: "logLinter",
	Doc:  "checks log messages for specific rules",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
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

			callFirst, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				return true
			}
			if callFirst.Kind != token.STRING {
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
				badWords := []string{"password", "api_key", "token"}

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
							if strings.Contains(lowerText, w) {
								pass.Reportf(nn.Pos(), "log message contains sensitive data")
								return false
							}
						}
					}
					return true
				})
				msg, err := strconv.Unquote(callFirst.Value)
				if err != nil {
					return true
				}
				if len(msg) == 0 {
					return true
				}
				runesMsg := []rune(msg)
				if unicode.IsUpper(runesMsg[0]) {
					pass.Reportf(callFirst.Pos(), "log message must start with a lowercase letter")
					return true
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
		if unicode.Is(unicode.Latin, r) || unicode.Is(unicode.Space, r) || unicode.Is(unicode.Digit, r) {
			continue
		}
		return false
	}
	return true
}
