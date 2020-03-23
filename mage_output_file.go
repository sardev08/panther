// +build ignore

package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	mage_mageimport "github.com/panther-labs/panther/tools/mage"
	
)

func main() {
	// Use local types and functions in order to avoid name conflicts with additional magefiles.
	type arguments struct {
		Verbose       bool          // print out log statements
		List          bool          // print out a list of targets
		Help          bool          // print out help for a specific target
		Timeout       time.Duration // set a timeout to running the targets
		Args          []string      // args contain the non-flag command-line arguments
	}

	parseBool := func(env string) bool {
		val := os.Getenv(env)
		if val == "" {
			return false
		}		
		b, err := strconv.ParseBool(val)
		if err != nil {
			log.Printf("warning: environment variable %s is not a valid bool value: %v", env, val)
			return false
		}
		return b
	}

	parseDuration := func(env string) time.Duration {
		val := os.Getenv(env)
		if val == "" {
			return 0
		}		
		d, err := time.ParseDuration(val)
		if err != nil {
			log.Printf("warning: environment variable %s is not a valid duration value: %v", env, val)
			return 0
		}
		return d
	}
	args := arguments{}
	fs := flag.FlagSet{}
	fs.SetOutput(os.Stdout)

	// default flag set with ExitOnError and auto generated PrintDefaults should be sufficient
	fs.BoolVar(&args.Verbose, "v", parseBool("MAGEFILE_VERBOSE"), "show verbose output when running targets")
	fs.BoolVar(&args.List, "l", parseBool("MAGEFILE_LIST"), "list targets for this binary")
	fs.BoolVar(&args.Help, "h", parseBool("MAGEFILE_HELP"), "print out help for a specific target")
	fs.DurationVar(&args.Timeout, "t", parseDuration("MAGEFILE_TIMEOUT"), "timeout in duration parsable format (e.g. 5m30s)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stdout, `
%s [options] [target]

Commands:
  -l    list targets in this binary
  -h    show this help

Options:
  -h    show description of a target
  -t <string>
        timeout in duration parsable format (e.g. 5m30s)
  -v    show verbose output when running targets
 `[1:], filepath.Base(os.Args[0]))
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		// flag will have printed out an error already.
		return
	}
	args.Args = fs.Args()
	if args.Help && len(args.Args) == 0 {
		fs.Usage()
		return
	}
	  
	list := func() error {
		
		targets := map[string]string{
			"build:api": "Generate Go client/models from Swagger specs in api/",
			"build:all": "Build all deployment artifacts",
			"build:cfn": "Generate CloudFormation templates in out/deployments folder",
			"build:devtools": "Compile developer tools from source",
			"build:lambda": "Compile Go Lambda function source",
			"build:opstools": "Compile Go operational tools from source",
			"doc:cfn": "Generate user documentation from deployment CloudFormation",
			"glue:sync": "Sync glue table partitions after schema change",
			"glue:update": "Updates the panther-app-databases cloudformation template (used for schema migrations)",
			"setup:all": "Install all development dependencies",
			"setup:go": "Install goimports, go-swagger, and golangci-lint",
			"setup:python": "Install the Python virtual env",
			"setup:swagger": "Install go-swagger for SDK generation",
			"setup:web": "Npm install",
			"test:ci": "Run all required checks (build:all, test:cfn, test:go, test:python, test:web)",
			"test:cfn": "Lint CloudFormation templates",
			"test:cover": "Run Go unit tests and view test coverage in HTML",
			"test:go": "Test Go source",
			"test:integration": "Run integration tests (integration_test.go,integration.py)",
			"test:python": "Test Python source",
			"test:web": "Test web source",
			"clean": "Remove auto-generated build artifacts",
			"deploy": "Deploy application infrastructure",
			"fmt": "Format source files",
			"showSchemas": "returns a JSON representation each supported log type",
			"teardown": "Destroy all Panther infrastructure",
		}

		keys := make([]string, 0, len(targets))
		for name := range targets {
			keys = append(keys, name)
		}
		sort.Strings(keys)

		fmt.Println("Targets:")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 4, ' ', 0)
		for _, name := range keys {
			fmt.Fprintf(w, "  %v\t%v\n", name, targets[name])
		}
		err := w.Flush()
		return err
	}

	var ctx context.Context
	var ctxCancel func()

	getContext := func() (context.Context, func()) {
		if ctx != nil {
			return ctx, ctxCancel
		}

		if args.Timeout != 0 {
			ctx, ctxCancel = context.WithTimeout(context.Background(), args.Timeout)
		} else {
			ctx = context.Background()
			ctxCancel = func() {}
		}
		return ctx, ctxCancel
	}

	runTarget := func(fn func(context.Context) error) interface{} {
		var err interface{}
		ctx, cancel := getContext()
		d := make(chan interface{})
		go func() {
			defer func() {
				err := recover()
				d <- err
			}()
			err := fn(ctx)
			d <- err
		}()
		select {
		case <-ctx.Done():
			cancel()
			e := ctx.Err()
			fmt.Printf("ctx err: %v\n", e)
			return e
		case err = <-d:
			cancel()
			return err
		}
	}
	// This is necessary in case there aren't any targets, to avoid an unused
	// variable error.
	_ = runTarget

	handleError := func(logger *log.Logger, err interface{}) {
		if err != nil {
			logger.Printf("Error: %+v\n", err)
			type code interface {
				ExitStatus() int
			}
			if c, ok := err.(code); ok {
				os.Exit(c.ExitStatus())
			}
			os.Exit(1)
		}
	}
	_ = handleError

	log.SetFlags(0)
	if !args.Verbose {
		log.SetOutput(ioutil.Discard)
	}
	logger := log.New(os.Stderr, "", 0)
	if args.List {
		if err := list(); err != nil {
			log.Println(err)
			os.Exit(1)
		}
		return
	}

	targets := map[string]bool {
		
		
		
			
			
			"build:api": true,
			"build:all": true,
			"build:cfn": true,
			"build:devtools": true,
			"build:lambda": true,
			"build:opstools": true,
			"doc:cfn": true,
			"glue:sync": true,
			"glue:update": true,
			"setup:all": true,
			"setup:go": true,
			"setup:python": true,
			"setup:swagger": true,
			"setup:web": true,
			"test:ci": true,
			"test:cfn": true,
			"test:cover": true,
			"test:go": true,
			"test:integration": true,
			"test:python": true,
			"test:web": true,
			"clean": true,
			"deploy": true,
			"fmt": true,
			"showschemas": true,
			"teardown": true,
			
		
	}

	var unknown []string
	for _, arg := range args.Args {
		if !targets[strings.ToLower(arg)] {
			unknown = append(unknown, arg)
		}
	}
	if len(unknown) == 1 {
		logger.Println("Unknown target specified:", unknown[0])
		os.Exit(2)
	}
	if len(unknown) > 1 {
		logger.Println("Unknown targets specified:", strings.Join(unknown, ", "))
		os.Exit(2)
	}

	if args.Help {
		if len(args.Args) < 1 {
			logger.Println("no target specified")
			os.Exit(1)
		}
		switch strings.ToLower(args.Args[0]) {
			
			default:
				logger.Printf("Unknown target: %q\n", args.Args[0])
				os.Exit(1)
		}
	}
	if len(args.Args) < 1 {
		if err := list(); err != nil {
			logger.Println("Error:", err)
			os.Exit(1)
		}
		return
	}
	for _, target := range args.Args {
		switch strings.ToLower(target) {
		
		}
		switch strings.ToLower(target) {
		
		
		
			
				case "build:api":
					if args.Verbose {
						logger.Println("Running target:", "Build:API")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Build{}.API()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "build:all":
					if args.Verbose {
						logger.Println("Running target:", "Build:All")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Build{}.All()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "build:cfn":
					if args.Verbose {
						logger.Println("Running target:", "Build:Cfn")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Build{}.Cfn()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "build:devtools":
					if args.Verbose {
						logger.Println("Running target:", "Build:Devtools")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Build{}.Devtools()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "build:lambda":
					if args.Verbose {
						logger.Println("Running target:", "Build:Lambda")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Build{}.Lambda()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "build:opstools":
					if args.Verbose {
						logger.Println("Running target:", "Build:Opstools")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Build{}.Opstools()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "doc:cfn":
					if args.Verbose {
						logger.Println("Running target:", "Doc:Cfn")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Doc{}.Cfn()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "glue:sync":
					if args.Verbose {
						logger.Println("Running target:", "Glue:Sync")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Glue{}.Sync()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "glue:update":
					if args.Verbose {
						logger.Println("Running target:", "Glue:Update")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Glue{}.Update()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "setup:all":
					if args.Verbose {
						logger.Println("Running target:", "Setup:All")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Setup{}.All()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "setup:go":
					if args.Verbose {
						logger.Println("Running target:", "Setup:Go")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Setup{}.Go()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "setup:python":
					if args.Verbose {
						logger.Println("Running target:", "Setup:Python")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Setup{}.Python()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "setup:swagger":
					if args.Verbose {
						logger.Println("Running target:", "Setup:Swagger")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Setup{}.Swagger()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "setup:web":
					if args.Verbose {
						logger.Println("Running target:", "Setup:Web")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Setup{}.Web()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "test:ci":
					if args.Verbose {
						logger.Println("Running target:", "Test:CI")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Test{}.CI()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "test:cfn":
					if args.Verbose {
						logger.Println("Running target:", "Test:Cfn")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Test{}.Cfn()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "test:cover":
					if args.Verbose {
						logger.Println("Running target:", "Test:Cover")
					}
								wrapFn := func(ctx context.Context) error {
				return mage_mageimport.Test{}.Cover()
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "test:go":
					if args.Verbose {
						logger.Println("Running target:", "Test:Go")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Test{}.Go()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "test:integration":
					if args.Verbose {
						logger.Println("Running target:", "Test:Integration")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Test{}.Integration()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "test:python":
					if args.Verbose {
						logger.Println("Running target:", "Test:Python")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Test{}.Python()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "test:web":
					if args.Verbose {
						logger.Println("Running target:", "Test:Web")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Test{}.Web()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "clean":
					if args.Verbose {
						logger.Println("Running target:", "Clean")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Clean()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "deploy":
					if args.Verbose {
						logger.Println("Running target:", "Deploy")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Deploy()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "fmt":
					if args.Verbose {
						logger.Println("Running target:", "Fmt")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Fmt()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "showschemas":
					if args.Verbose {
						logger.Println("Running target:", "ShowSchemas")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.ShowSchemas()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
				case "teardown":
					if args.Verbose {
						logger.Println("Running target:", "Teardown")
					}
								wrapFn := func(ctx context.Context) error {
				mage_mageimport.Teardown()
				return nil
			}
			err := runTarget(wrapFn)
					handleError(logger, err)
		default:
			// should be impossible since we check this above.
			logger.Printf("Unknown target: %q\n", args.Args[0])
			os.Exit(1)
		}
	}
}




