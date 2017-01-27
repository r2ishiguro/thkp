package main

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
	"errors"

	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/util"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// appHandler holds a LogContext and a handler function that uses it, and is
// an implementation of the http.Handler interface.
type appHandler struct {
	context LogContext
	handler func(context.Context, LogContext, http.ResponseWriter, *http.Request) (int, error)
	name    string
	method  string
}

// ServeHTTP for an appHandler invokes the underlying handler function but
// does additional common error processing.
func (a appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != a.method {
		http.Error(w, fmt.Sprintf("method not allowed: %s", r.Method), http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodGet {
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("failed to parse form data: %v", err), http.StatusBadRequest)
			return
		}
	}
	ctx, cancel := context.WithDeadline(r.Context(), a.context.timeSource.Now().Add(a.context.rpcDeadline))
	defer cancel()
	status, err := a.handler(ctx, a.context, w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("handler error: %v", err), status)
		return
	}
	if status != http.StatusOK {
		http.Error(w, fmt.Sprintf("handler status error: %d", status), status)
		return
	}
}

// LogContext holds information for a specific log instance.
type LogContext struct {
	// logID is the tree ID that identifies this log in node storage
	logID int64
	// logPrefix is a pre-formatted string identifying the log for diagnostics.
	logPrefix string
	// rpcClient is the client used to communicate with the trillian backend
	rpcClient trillian.TrillianLogClient
	// rpcDeadline is the deadline that will be set on all backend RPC requests
	rpcDeadline time.Duration
	// timeSource is a util.TimeSource that can be injected for testing
	timeSource util.TimeSource
}

type AddLeafResponse struct {
	Status uint64 `json:"status"`
}

type GetSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`           // Number of certs in the current tree
	Timestamp         uint64 `json:"timestamp"`           // Time that the tree was created
	SHA256RootHash    []byte `json:"sha256_root_hash"`    // Root hash of the tree
	TreeHeadSignature []byte `json:"tree_head_signature"` // Log signature for this STH
}

type GetEntryAndProofResponse struct {
	LeafInput []byte   `json:"leaf_input"` // the entry itself
	ExtraData []byte   `json:"extra_data"` // any chain provided when the entry was added to the log
	AuditPath [][]byte `json:"audit_path"` // the corresponding proof
}

type GetProofByHashResponse struct {
	LeafIndex int64    `json:"leaf_index"` // The 0-based index of the end entity corresponding to the "hash" parameter.
	AuditPath [][]byte `json:"audit_path"` // An array of base64-encoded Merkle Tree nodes proving the inclusion of the chosen certificate.
}

// NewLogContext creates a new instance of LogContext.
func NewLogContext(logID int64, rpcClient trillian.TrillianLogClient, rpcDeadline time.Duration, timeSource util.TimeSource) *LogContext {
	return &LogContext{
		logID:         logID,
		logPrefix:     fmt.Sprintf("{%d}", logID),
		rpcClient:     rpcClient,
		rpcDeadline:   rpcDeadline,
		timeSource:    timeSource}
}

func addLeaf(ctx context.Context, c LogContext, w http.ResponseWriter, r *http.Request) (int, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return http.StatusBadRequest, err
	}
	leafHash := sha256.Sum256(body)
	leaf := trillian.LogLeaf{
		LeafValueHash: leafHash[:],
		LeafValue: body,
	}
	req := trillian.QueueLeavesRequest{LogId: c.logID, Leaves: []*trillian.LogLeaf{&leaf}}
	rsp, err := c.rpcClient.QueueLeaves(ctx, &req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	status := rsp.GetStatus()
	if status == nil || status.StatusCode != trillian.TrillianApiStatusCode_OK {
		return http.StatusInternalServerError, fmt.Errorf("trillian server error: %v", status)
	}
	res := AddLeafResponse{
		Status: 0,
	}
	w.Header().Set("Content-Type", "applicatioin/json")
	jsonData, err := json.Marshal(&res)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	_, err = w.Write(jsonData)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getSTH(ctx context.Context, c LogContext, w http.ResponseWriter, r *http.Request) (int, error) {
	req := trillian.GetLatestSignedLogRootRequest{LogId: c.logID}
	rsp, err := c.rpcClient.GetLatestSignedLogRoot(ctx, &req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	status := rsp.GetStatus()
	if status == nil || status.StatusCode != trillian.TrillianApiStatusCode_OK {
		return http.StatusInternalServerError, fmt.Errorf("trillian server error: %v", status)
	}
	slr := rsp.GetSignedLogRoot()
	if slr == nil {
		return http.StatusInternalServerError, fmt.Errorf("no log root returned")
	}
	jsonRsp := GetSTHResponse{
		TreeSize: uint64(slr.TreeSize),
		SHA256RootHash: slr.RootHash,
		Timestamp: uint64(slr.TimestampNanos / 1000 / 1000),
		// no TreeHeadSignature for now
	}
	w.Header().Set("Content-Type", "application/json")
	jsonData, err := json.Marshal(&jsonRsp)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	_, err = w.Write(jsonData)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// auditPathFromProto converts the path from proof proto to a format we can return in the JSON
// response
func auditPathFromProto(path []*trillian.Node) [][]byte {
	result := make([][]byte, 0, len(path))
	for _, node := range path {
		result = append(result, node.NodeHash)
	}
	return result
}

func getProofByHash(ctx context.Context, c LogContext, w http.ResponseWriter, r *http.Request) (int, error) {
	hash := r.FormValue("hash")
	if len(hash) == 0 {
		return http.StatusBadRequest, errors.New("get-proof-by-hash: missing / empty hash param")
	}
	leafHash, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return http.StatusBadRequest, err
	}
	treeSize, err := strconv.ParseInt(r.FormValue("tree_size"), 10, 64)
	if err != nil {
		return http.StatusBadRequest, err
	}
	req := trillian.GetInclusionProofByHashRequest {
		LogId: c.logID,
		LeafHash: leafHash,
		TreeSize: treeSize,
		OrderBySequence: true,
	}
	rsp, err := c.rpcClient.GetInclusionProofByHash(ctx, &req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	status := rsp.GetStatus()
	if status == nil || status.StatusCode != trillian.TrillianApiStatusCode_OK {
		return http.StatusInternalServerError, fmt.Errorf("trillian server error: %v", status)
	}
	var jsonRsp GetProofByHashResponse
	if len(rsp.Proof) > 0 {
		jsonRsp = GetProofByHashResponse{
			LeafIndex: rsp.Proof[0].LeafIndex,
			AuditPath: auditPathFromProto(rsp.Proof[0].ProofNode),
		}
	} else {
		jsonRsp = GetProofByHashResponse{
			LeafIndex: -1,
		}
	}
		
	w.Header().Set("Content-Type", "application/json")
	jsonData, err := json.Marshal(&jsonRsp)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	_, err = w.Write(jsonData)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getEntryAndProof(ctx context.Context, c LogContext, w http.ResponseWriter, r *http.Request) (int, error) {
	leafIndex, err := strconv.ParseInt(r.FormValue("leaf_index"), 10, 64)
	if err != nil {
		return http.StatusBadRequest, err
	}
	treeSize, err := strconv.ParseInt(r.FormValue("tree_size"), 10, 64)
	if err != nil {
		return http.StatusBadRequest, err
	}
	req := trillian.GetEntryAndProofRequest{LogId: c.logID, LeafIndex: leafIndex, TreeSize: treeSize}
	rsp, err := c.rpcClient.GetEntryAndProof(ctx, &req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	status := rsp.GetStatus()
	if status == nil || status.StatusCode != trillian.TrillianApiStatusCode_OK {
		return http.StatusInternalServerError, fmt.Errorf("trillian server error: %v", status)
	}
	jsonRsp := GetEntryAndProofResponse{
		LeafInput: rsp.Leaf.LeafValue,
		ExtraData: rsp.Leaf.ExtraData,
		AuditPath: auditPathFromProto(rsp.Proof.ProofNode),
	}
	w.Header().Set("Content-Type", "application/json")
	jsonData, err := json.Marshal(&jsonRsp)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	_, err = w.Write(jsonData)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func (c LogContext) RegisterHandlers() {
	http.Handle("/gt/v1/add-leaf", appHandler{context: c, handler: addLeaf, name: "AddLeaf", method: http.MethodPost})
	http.Handle("/gt/v1/get-sth", appHandler{context: c, handler: getSTH, name: "GetSTH", method: http.MethodGet})
	http.Handle("/gt/v1/get-proof-by-hash", appHandler{context: c, handler: getProofByHash, name: "GetProofByHash", method: http.MethodGet})
	http.Handle("/gt/v1/get-entry-and-proof", appHandler{context: c, handler: getEntryAndProof, name: "GetEntryAndProof", method: http.MethodGet})
}


var logIDFlag = flag.Int64("log_id", 1, "The log id (tree id) to send to the backend")
var rpcBackendFlag = flag.String("log_rpc_server", "localhost:8090", "Backend Log RPC server to use")
var rpcDeadlineFlag = flag.Duration("rpc_deadline", time.Second*10, "Deadline for backend RPC requests")
var serverPortFlag = flag.Int("port", 6962, "Port to serve CT log requests on")

func awaitSignal() {
	// Arrange notification for the standard set of signals used to terminate a server
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Now block main and wait for a signal
	sig := <-sigs
	glog.Warningf("Signal received: %v", sig)
	glog.Flush()

	// Terminate the process
	os.Exit(1)
}

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*rpcBackendFlag, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		glog.Fatalf("Could not connect to rpc server: %v", err)
	}

	defer conn.Close()
	client := trillian.NewTrillianLogClient(conn)

	// Create and register the handlers using the RPC client we just set up
	logContext := NewLogContext(*logIDFlag, client, *rpcDeadlineFlag, new(util.SystemTimeSource))
	logContext.RegisterHandlers()

	// Bring up the HTTP server and serve until we get a signal not to.
	go awaitSignal()
	server := http.Server{Addr: fmt.Sprintf("localhost:%d", *serverPortFlag), Handler: nil}
	err = server.ListenAndServe()
	glog.Warningf("Server exited: %v", err)
	glog.Flush()
}
