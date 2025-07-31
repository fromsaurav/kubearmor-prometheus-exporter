package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"log"
	"net/http"
	"path/filepath"
	"sync"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	"github.com/kubearmor/kubearmor-prometheus-exporter/pkg/policy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
totalAlertsRequestsinHost = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kubearmor_alerts_in_host_total",
		Help: "Total number of alerts based on HostName",
	}, []string{"HostName"})

totalAlertsRequestsinNamespace = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kubearmor_alerts_in_namespace_total",
		Help: "Total number of alerts based on Namespace",
	}, []string{"NamespaceName"})

totalAlertsRequestsinPod = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kubearmor_alerts_in_pod_total",
		Help: "Total number of alerts based on PodName",
	}, []string{"PodName"})

totalAlertsRequestsinContainer = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kubearmor_alerts_in_container_total",
		Help: "Total number of alerts based on Container",
	}, []string{"ContainerName"})

totalAlertsWithPolicy = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kubearmor_alerts_with_policy_total",
		Help: "Total number of alerts based on Policy",
	}, []string{"PolicyName"})

totalAlertsWithSeverity = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kubearmor_alerts_with_severity_total",
		Help: "Total number of alerts with X severity or above",
	}, []string{"Severity"})

totalAlertsWithType = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kubearmor_alerts_with_type_total",
		Help: "Total number of alerts based on Type",
	}, []string{"Type"})

totalAlertsWithOperation = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kubearmor_alerts_with_operation_total",
		Help: "Total number of alerts based on Operation",
	}, []string{"Operation"})

totalAlertsWithAction = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "kubearmor_alerts_with_action_total",
		Help: "Total number of alerts based on Action",
	}, []string{"Action"})

totalPolicies = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kubearmor_policies_total",
		Help: "Total number of KubeArmor policies by type",
	}, []string{"type"})

policyInfo = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kubearmor_policy_info",
		Help: "Information about KubeArmor policies",
	}, []string{"name", "namespace", "type", "status"})

policiesByNamespace = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "kubearmor_policies_by_namespace_total",
		Help: "Total number of KubeArmor policies by namespace and type",
	}, []string{"namespace", "type"})
)

func init() {
	prometheus.MustRegister(totalAlertsRequestsinHost)
	prometheus.MustRegister(totalAlertsRequestsinNamespace)
	prometheus.MustRegister(totalAlertsRequestsinPod)
	prometheus.MustRegister(totalAlertsRequestsinContainer)

	prometheus.MustRegister(totalAlertsWithPolicy)
	prometheus.MustRegister(totalAlertsWithSeverity)
	prometheus.MustRegister(totalAlertsWithType)
	prometheus.MustRegister(totalAlertsWithOperation)
	prometheus.MustRegister(totalAlertsWithAction)

	prometheus.MustRegister(totalPolicies)
	prometheus.MustRegister(policyInfo)
	prometheus.MustRegister(policiesByNamespace)
	
	initializePolicyMetrics()
}

func initializePolicyMetrics() {
	totalPolicies.WithLabelValues("KubeArmorPolicy").Set(0)
	totalPolicies.WithLabelValues("KubeArmorHostPolicy").Set(0)
	totalPolicies.WithLabelValues("KubeArmorClusterPolicy").Set(0)
	
	policyInfo.WithLabelValues("example-policy", "default", "KubeArmorPolicy", "active").Set(0)
	policiesByNamespace.WithLabelValues("default", "KubeArmorPolicy").Set(0)
}


func GetPrometheusAlerts(wg *sync.WaitGroup, gRPCAddr string) {
	connection, err := grpc.Dial(gRPCAddr, grpc.WithInsecure())
	if err != nil {
		fmt.Println(err)
	}
	client := pb.NewLogServiceClient(connection)

	req := &pb.RequestMessage{
		Filter: "policy",
	}

	stream, err := client.WatchAlerts(context.Background(), req)
	if err != nil {
		fmt.Printf("Failed to call WatchAlerts() (%s)\n", err.Error())
		wg.Done()
		return
	}

	for {
		alertIn, err := stream.Recv()
		if err != nil {
			fmt.Printf("Failed to receive any alerts (%s)\n", err.Error())
			break
		}

		// fmt.Println(alertIn)

		totalAlertsRequestsinHost.WithLabelValues(alertIn.HostName).Add(1)
		totalAlertsRequestsinNamespace.WithLabelValues(alertIn.NamespaceName).Add(1)
		totalAlertsRequestsinPod.WithLabelValues(alertIn.PodName).Add(1)
		totalAlertsRequestsinContainer.WithLabelValues(alertIn.ContainerName).Add(1)

		totalAlertsWithPolicy.WithLabelValues(alertIn.PolicyName).Add(1)
		totalAlertsWithSeverity.WithLabelValues(alertIn.Severity).Add(1)
		totalAlertsWithType.WithLabelValues(alertIn.Type).Add(1)
		totalAlertsWithOperation.WithLabelValues(alertIn.Operation).Add(1)
		totalAlertsWithAction.WithLabelValues(alertIn.Action).Add(1)
	}

	wg.Done()
}

func createKubeClient() (kubernetes.Interface, dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		config, err = clientcmd.BuildConfigFromFlags("",
			filepath.Join(os.Getenv("HOME"), ".kube", "config"))
		if err != nil {
			return nil, nil, err
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}

	return clientset, dynamicClient, nil
}

func main() {
	var wg sync.WaitGroup

	// == //

	gRPCPtr := flag.String("gRPC", "", "gRPC server information")
	disablePolicyWatcher := flag.Bool("disable-policy-watcher", false, "Disable policy watcher for development")
	flag.Parse()

	// == //

	gRPCAddr := ""

	if *gRPCPtr != "" {
		gRPCAddr = *gRPCPtr
	} else {
		if val, ok := os.LookupEnv("KUBEARMOR_SERVICE"); ok {
			gRPCAddr = val
		} else {
			gRPCAddr = "localhost:32767"
		}
	}

	// == //

	wg.Add(1)
	go GetPrometheusAlerts(&wg, gRPCAddr)

	if !*disablePolicyWatcher {
		clientset, dynamicClient, err := createKubeClient()
		if err != nil {
			log.Printf("Warning: Failed to create Kubernetes client: %v. Policy metrics will not be available.", err)
		} else {
			policyWatcher := policy.NewPolicyWatcher(clientset, dynamicClient)
			if err := policyWatcher.Start(); err != nil {
				log.Printf("Warning: Failed to start policy watcher: %v", err)
			}
			defer policyWatcher.Stop()
		}
	}

	http.Handle("/metrics", promhttp.Handler())
	log.Println("Starting Prometheus exporter on :9100")
	log.Fatal(http.ListenAndServe(":9100", nil))

	wg.Wait()
}
