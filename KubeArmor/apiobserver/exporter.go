// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"sync"

	"github.com/google/uuid"
	pb "github.com/kubearmor/KubeArmor/KubeArmor/apiobserver/sentryflow"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// clientList represents a list of gRPC clients and their associated channels
type clientList struct {
	*sync.Mutex
	client map[string]chan *pb.APIEvent
}

// APIEventExporter implements the gRPC streaming server for API events
type APIEventExporter struct {
	pb.UnimplementedSentryFlowServer
	apiEvents chan *pb.APIEvent
	clients   *clientList
}

// NewAPIEventExporter creates a new API event exporter
func NewAPIEventExporter(eventChan chan *pb.APIEvent) *APIEventExporter {
	exporter := &APIEventExporter{
		apiEvents: eventChan,
		clients: &clientList{
			Mutex:  &sync.Mutex{},
			client: make(map[string]chan *pb.APIEvent),
		},
	}

	// Start forwarding events to clients
	go exporter.forwardEventsToClients()

	return exporter
}

// GetAPIEvent streams API events to connected clients
func (e *APIEventExporter) GetAPIEvent(clientInfo *pb.ClientInfo, stream grpc.ServerStreamingServer[pb.APIEvent]) error {
	uid := uuid.Must(uuid.NewRandom()).String()

	connChan := e.addClientToList(uid)
	defer e.deleteClientFromList(uid, connChan)

	// Log client connection (using simple print for now)
	// TODO: Use proper logger
	println("API Observer client connected:", uid, clientInfo.HostName, clientInfo.IPAddress)

	for {
		select {
		case <-stream.Context().Done():
			println("API Observer client disconnected:", uid)
			return stream.Context().Err()
		case apiEvent, ok := <-connChan:
			if !ok {
				println("Channel closed for client:", uid)
				return nil
			}
			if status, ok := grpcstatus.FromError(stream.Send(apiEvent)); !ok {
				if status.Code() == codes.Canceled {
					println("Client cancelled operation:", uid)
					return nil
				}
				return status.Err()
			}
		}
	}
}

// addClientToList adds a new client to the client list
func (e *APIEventExporter) addClientToList(uid string) chan *pb.APIEvent {
	e.clients.Lock()
	connChan := make(chan *pb.APIEvent, 1000)
	e.clients.client[uid] = connChan
	e.clients.Unlock()
	return connChan
}

// deleteClientFromList removes a client from the client list
func (e *APIEventExporter) deleteClientFromList(uid string, connChan chan *pb.APIEvent) {
	e.clients.Lock()
	close(connChan)
	delete(e.clients.client, uid)
	e.clients.Unlock()
}

// forwardEventsToClients forwards events from the observer to all connected clients
func (e *APIEventExporter) forwardEventsToClients() {
	for apiEvent := range e.apiEvents {
		eventToSend := apiEvent
		e.clients.Lock()
		for uid, clientChan := range e.clients.client {
			select {
			case clientChan <- eventToSend:
			default:
				// Channel full, drop oldest event
				<-clientChan
				println("Client channel full, dropping oldest event for:", uid)
				clientChan <- eventToSend
			}
		}
		e.clients.Unlock()
	}
}
