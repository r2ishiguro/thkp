package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"time"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto"
	"github.com/google/trillian/examples/ct"
	"github.com/google/trillian/util"
	"google.golang.org/grpc"

	"./trillian_http"
)

var logIDFlag = flag.Int64("log_id", 1, "The log id (tree id) to send to the backend")
var rpcBackendFlag = flag.String("log_rpc_server", "localhost:8090", "Backend Log RPC server to use")
var rpcDeadlineFlag = flag.Duration("rpc_deadline", time.Second*10, "Deadline for backend RPC requests")
var serverPortFlag = flag.Int("port", 6962, "Port to serve CT log requests on")

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*rpcBackendFlag, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		glog.Fatalf("Could not connect to rpc server: %v", err)
	}

	defer conn.Close()
	client := trillian.NewTrillianLogClient(conn)

	// Create and register the handlers using the RPC client we just set up
	logContext := trillian_http.NewLogContext(*logIDFlag, client, *rpcDeadlineFlag, new(util.SystemTimeSource))
	logContext.RegisterHandlers()

	// Bring up the HTTP server and serve until we get a signal not to.
	go awaitSignal()
	server := http.Server{Addr: fmt.Sprintf("localhost:%d", *serverPortFlag), Handler: nil}
	err = server.ListenAndServe()
	glog.Warningf("Server exited: %v", err)
	glog.Flush()
}
