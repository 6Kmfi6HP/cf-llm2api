package main

import (
	"fmt"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	_ "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator/builtin"
)

func probeMain() {
	fmts := []sdktranslator.Format{sdktranslator.FormatOpenAI, sdktranslator.FormatClaude, sdktranslator.FormatOpenAIResponse}
	fmt.Println("== Request transformers (from->to) ==")
	for _, f := range fmts {
		for _, t := range fmts {
			fmt.Printf("%s -> %s : %v\n", f, t, sdktranslator.HasRequestTransformer(f, t))
		}
	}
	fmt.Println("== NonStream Response transformers (from->to per CPA store) ==")
	for _, f := range fmts {
		for _, t := range fmts {
			fmt.Printf("%s -> %s : %v\n", f, t, sdktranslator.HasNonStreamResponseTransformer(f, t))
		}
	}
	fmt.Println("== Stream Response transformers ==")
	for _, f := range fmts {
		for _, t := range fmts {
			fmt.Printf("%s -> %s : %v\n", f, t, sdktranslator.HasStreamResponseTransformer(f, t))
		}
	}
}
