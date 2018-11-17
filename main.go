package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/picatz/doh/core"
	"github.com/picatz/doh/core/sources"

	"github.com/spf13/cobra"
)

func init() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			os.Exit(0)
		}
	}()
}

type result struct {
	Label string         `json:"label"`
	Resp  *core.Response `json:"resp"`
}

func main() {
	results := make(chan result)
	jobs := sync.WaitGroup{}

	// ctrl+C exit
	exit := func(reason string, code int) {
		if reason != "" {
			fmt.Println("exiting:", reason)
		}
		os.Exit(0)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			exit("", 0)
		}
	}()

	// enumerate command options
	var (
		ctx    context.Context
		cancel context.CancelFunc

		cmdQueryVerboseOpt   bool
		cmdQueryLabelsOpt    bool
		cmdQueryJoinedOpt    bool
		cmdQueryTimeoutOpt   int64
		cmdQueryLockOpt      int64
		cmdQueryNoTimeoutOpt bool
		cmdQuerySourcesOpt   []string
		cmdQueryQueryTypeOpt string

		defaultQuerySources = []string{"google", "cloudflare", "quad9"}
		defaultLockValue    = int64(runtime.GOMAXPROCS(0))
		defaultQueryType    = core.IPv4Type

		querySources = core.Sources{}
	)

	var cmdQuery = &cobra.Command{
		Use:   "query [domains]",
		Short: "Query domains for DNS records in JSON",
		Args:  cobra.MinimumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			sharedLock := semaphore.NewWeighted(cmdQueryLockOpt)

			for _, sourceStr := range cmdQuerySourcesOpt {
				switch sourceStr {
				case "google":
					querySources = append(querySources, &sources.Google{sharedLock})
				case "cloudflare":
					querySources = append(querySources, &sources.Cloudflare{sharedLock})
				case "quad9":
					querySources = append(querySources, &sources.Quad9{sharedLock})
				}
			}

			if len(querySources) == 0 {
				exit("no query sources", 1)
			}

			if cmdQueryNoTimeoutOpt {
				ctx, cancel = context.WithCancel(context.Background())
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), time.Second*time.Duration(cmdQueryTimeoutOpt))
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			jobs.Add(len(args))

			for _, arg := range args {
				go func(queryName core.Domain, queryType core.Type) {
					defer cancel()
					defer jobs.Done()
					defer close(results)
					for _, src := range querySources {
						if ctx.Err() != nil {
							return
						}

						resp, err := src.Query(ctx, queryName, queryType)

						if err != nil && cmdQueryVerboseOpt {
							fmt.Println("error:", err)
							continue
						}

						if resp != nil {
							select {
							case <-ctx.Done():
								return
							case results <- result{Label: src.String(), Resp: resp}:
								continue
							}
						}
					}
				}(arg, cmdQueryQueryTypeOpt)
			}
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			defer cancel()

			jobs.Add(1)

			go func() {
				defer jobs.Done()

				var joined = []interface{}{}

				if cmdQueryJoinedOpt {
					defer func() {
						b, err := json.Marshal(joined)
						if err != nil {
							fmt.Println(err)
							return
							//exit("error: failed to marshal joined results as json", 1)
						}
						fmt.Println(string(b))
					}()
				}

				for result := range results {
					var (
						b   []byte
						err error
					)

					if cmdQueryJoinedOpt {
						if cmdQueryLabelsOpt {
							joined = append(joined, result)
						} else {
							joined = append(joined, result.Resp)
						}
						continue
					}

					if cmdQueryLabelsOpt {
						b, err = json.Marshal(result)
					} else {
						b, err = json.Marshal(result.Resp)
					}

					if err != nil && cmdQueryVerboseOpt {
						fmt.Println("error:", err)
						continue
					}
					fmt.Println(string(b))
				}
			}()

			jobs.Wait()
		},
	}

	cmdQuery.Flags().StringVar(&cmdQueryQueryTypeOpt, "type", defaultQueryType, "dns record type to query for (\"A\", \"AAAA\", \"MX\" ...)")
	cmdQuery.Flags().StringSliceVar(&cmdQuerySourcesOpt, "sources", defaultQuerySources, "sources to use for query")
	cmdQuery.Flags().Int64Var(&cmdQueryTimeoutOpt, "timeout", 30, "number of seconds until timeout")
	cmdQuery.Flags().BoolVar(&cmdQueryNoTimeoutOpt, "no-timeout", false, "do not timeout")
	cmdQuery.Flags().Int64Var(&cmdQueryLockOpt, "lock", defaultLockValue, "number of concurrent workers")
	cmdQuery.Flags().BoolVar(&cmdQueryVerboseOpt, "verbose", false, "show errors and other available diagnostic information")
	cmdQuery.Flags().BoolVar(&cmdQueryLabelsOpt, "labels", false, "show source of the dns record")
	cmdQuery.Flags().BoolVar(&cmdQueryJoinedOpt, "joined", false, "join results into a JSON object")

	var rootCmd = &cobra.Command{Use: "doh"}
	rootCmd.AddCommand(cmdQuery)
	rootCmd.Execute()
}
