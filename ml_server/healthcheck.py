#!/usr/bin/env python3
"""
Healthcheck script for ML Sidecar container.
Checks gRPC server connectivity and service health.
"""

import sys

import grpc
import ml_service_pb2
import ml_service_pb2_grpc


def main():
    try:
        channel = grpc.insecure_channel("localhost:50051")

        # Wait for channel to be ready (5 second timeout)
        grpc.channel_ready_future(channel).result(timeout=5)

        # Call the actual HealthCheck RPC
        stub = ml_service_pb2_grpc.MlServiceStub(channel)
        response = stub.HealthCheck(ml_service_pb2.Empty(), timeout=5)

        if response.healthy:
            print(f"ML Sidecar healthy (version: {response.version})")
            sys.exit(0)
        else:
            print("ML Sidecar reported unhealthy")
            sys.exit(1)

    except grpc.FutureTimeoutError:
        print("Healthcheck failed: gRPC channel not ready")
        sys.exit(1)
    except grpc.RpcError as e:
        print(f"Healthcheck failed: gRPC error - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Healthcheck failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
