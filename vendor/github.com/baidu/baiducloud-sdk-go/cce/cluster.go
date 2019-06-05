package cce

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/baidu/baiducloud-sdk-go/bcc"
	"github.com/baidu/baiducloud-sdk-go/bce"
	"strconv"
	"time"
)

const (
	ClusterStatusCreating     string = "CREATING"
	ClusterStatusRunning      string = "RUNNING"
	ClusterStatusDeleting     string = "DELETING"
	ClusterStatusCreateFailed string = "CREATE_FAILED"
	ClusterStatusError        string = "ERROR"
)

type Cluster struct {
	ClusterUUID       string            `json:"clusterUuid"`
	ClusterName       string            `json:"clusterName"`
	Comment           string            `json:"comment"`
	Region            string            `json:"region"`
	SlaveVMCount      int64             `json:"slaveVmCount"`
	MasterVMCount     int64             `json:"masterVmCount"`
	Version           string            `json:"version"`
	VPCID             string            `json:"vpcId"`
	VPCUUID           string            `json:"vpcUuid"`
	VPCCidr           string            `json:"vpcCidr"`
	ZoneSubnetMap     map[string]string `json:"zoneSubnetMap"`
	AdvancedOptions   AdvancedOptions   `json:"advancedOptions"`
	ContainerNet      string            `json:"containerNet"`
	Status            string            `json:"status"`
	CreateTime        time.Time         `json:"createTime"`
	DeleteTime        time.Time         `json:"deleteTime"`
	AllInstanceNormal bool              `json:"allInstanceNormal"`
	InstanceList      []*SimpleNode     `json:"instanceList"`
}

type SimpleNode struct {
	InstanceShortID string `json:"instanceShortId"`
	InstanceUUID    string `json:"instanceUuid"`
	InstanceName    string `json:"instanceName"`
	ClusterUUID     string `json:"clusterUuid"`
	Status          string `json:"status"`
}

type AdvancedOptions struct {
	KubeProxyMode         string `json:"kubeProxyMode"`
	SecureContainerEnable bool   `json:"secureContainerEnable"`
}

type BaseCreateOrderRequestVo struct {
	Items []Item `json:"items"`
}

type Item struct {
	Config interface{} `json:"config"`
}

const (
	InstanceServiceType string = "BCC"
	EIPServiceType      string = "EIP"
	CDSServiceType      string = "CDS"

	PostPayProductType string = "postpay"
)

type ProductConfig struct {
	ProductType    string `json:"productType"`
	Region         string `json:"region"`
	PurchaseNum    int64  `json:"purchaseNum"`
	PurchaseLength int64  `json:"purchaseLength"`
	ServiceType    string `json:"serviceType"`
	SubProductType string `json:"subProductType"`
}

type CDSConfig struct {
	ProductConfig `json:",inline"`
	LogicalZone   string           `json:"logicalZone"`
	CDSDiskSize   []DiskSizeConfig `json:"cdsDiskSize"`
}

type DiskSizeConfig struct {
	SnapshotId string `json:"snapshotId"`
	Size       string `json:"size"`
	VolumeType string `json:"volumeType"`
}

type PreMountInfo struct {
	MountPath string           `json:"mountPath"`
	CdsConfig []DiskSizeConfig `json:"cdsConfig"`
}

type EIPConfig struct {
	ProductConfig   `json:",inline"`
	Name            string `json:"name"`
	BandwidthInMbps int64  `json:"bandwidthInMbps"`
}

type BCCConfig struct {
	ProductConfig       `json:",inline"`
	InstanceType        int64               `json:"instanceType"`
	LogicalZone         string              `json:"logicalZone"`
	BandwidthInMbps     int64               `json:"bandwidthInMbps"`
	GPUCard             string              `json:"gpuCard"`
	GPUCount            int64               `json:"gpuCount"`
	CPU                 int64               `json:"cpu"`
	Memory              int64               `json:"memory"`
	ImageType           string              `json:"imageType"`
	OSType              string              `json:"osType"`
	OSVersion           string              `json:"osVersion"`
	DiskSize            int64               `json:"diskSize"`
	EBSSize             []int64             `json:"ebsSize,omitempty"`
	IfBuyEIP            bool                `json:"ifBuyEip"`
	EIPName             string              `json:"eipName,omitempty"`
	SubnetUUID          string              `json:"subnetUuid"`
	SecurityGroupID     string              `json:"securityGroupId"`
	AdminPass           string              `json:"adminPass"`
	AdminPassConfirm    string              `json:"adminPassConfirm"`
	CreateEphemeralList []bcc.EphemeralDisk `json:"createEphemeralList,omitempty"`
	AutoRenew           bool                `json:"autoRenew"`
	ImageID             string              `json:"imageId"`
	SecurityGroupName   string              `json:"securityGroupName"`
}

type GetClustersArgs struct {
	Marker  string `json:"marker"`
	MaxKeys int64  `json:"maxKeys"`
	Status  string `json:"status"`
}

type GetClusterResponse struct {
	Clusters    []Cluster `json:"clusters"`
	Marker      string    `json:"marker"`
	IsTruncated bool      `json:"isTruncated"`
	NextMarker  string    `json:"nextMarker"`
	MaxKeys     int64     `json:"maxKeys"`
}

func (c *Client) GetClusters(args *GetClustersArgs, option *bce.SignOption) ([]Cluster, error) {
	if args == nil {
		args = &GetClustersArgs{}
	}
	params := map[string]string{
		"marker":  args.Marker,
		"maxKeys": strconv.FormatInt(args.MaxKeys, 10),
		"status":  args.Status,
	}
	req, err := bce.NewRequest("GET", c.GetURL("v1/cluster", params), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.SendRequest(req, option)
	if err != nil {
		return nil, err
	}
	bodyContent, err := resp.GetBodyContent()

	if err != nil {
		return nil, err
	}
	var clusterResponse *GetClusterResponse
	err = json.Unmarshal(bodyContent, &clusterResponse)

	if err != nil {
		return nil, err
	}
	return clusterResponse.Clusters, nil
}

func (c *Client) DescribeCluster(clusterUuid string, option *bce.SignOption) (*Cluster, error) {
	req, err := bce.NewRequest("GET", c.GetURL(fmt.Sprintf("v1/cluster/%s", clusterUuid), nil), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.SendRequest(req, option)
	if err != nil {
		return nil, err
	}

	bodyContent, err := resp.GetBodyContent()
	if err != nil {
		return nil, err
	}

	var cluster *Cluster
	err = json.Unmarshal(bodyContent, &cluster)
	if err != nil {
		return nil, err
	}
	return cluster, nil
}

func (c *Client) DeleteCluster(clusterUuid string, option *bce.SignOption) error {
	req, err := bce.NewRequest("DELETE", c.GetURL(fmt.Sprintf("v1/cluster/%s", clusterUuid), nil), nil)
	if err != nil {
		return err
	}
	_, err = c.SendRequest(req, option)
	if err != nil {
		return err
	}
	return nil
}

type CreateClusterResponse struct {
	ClusterUUID string   `json:"clusterUuid"`
	OrderID     []string `json:"orderId"`
}

type CreateClusterArgs struct {
	ClusterName       string                    `json:"clusterName"`
	Version           string                    `json:"version"`
	MainAvailableZone string                    `json:"mainAvailableZone"`
	ContainerNet      string                    `json:"containerNet"`
	AdvancedOptions   *AdvancedOptions          `json:"advancedOptions"`
	CDSPreMountInfo   *PreMountInfo             `json:"cdsPreMountInfo"`
	Comment           string                    `json:"comment,omitempty"`
	OrderContent      *BaseCreateOrderRequestVo `json:"orderContent"`
}

func (args *CreateClusterArgs) validate() error {
	if args == nil {
		return fmt.Errorf("CreateClusterArgs cannot be nil")
	}
	if args.ClusterName == "" {
		return fmt.Errorf("clusterName cannot be empty")
	}
	if args.Version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if args.MainAvailableZone == "" {
		return fmt.Errorf("mainAvailableZone cannot be empty")
	}
	if args.ContainerNet == "" {
		return fmt.Errorf("containerNet cannot be empty")
	}
	if args.OrderContent == nil {
		return fmt.Errorf("orderContent cannot be empty")
	}
	return nil
}

func (c *Client) CreateCluster(args *CreateClusterArgs, option *bce.SignOption) (string, error) {
	err := args.validate()
	if err != nil {
		return "", err
	}
	postContent, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	req, err := bce.NewRequest("POST", c.GetURL("v1/cluster", nil), bytes.NewBuffer(postContent))
	if err != nil {
		return "", err
	}
	resp, err := c.SendRequest(req, option)
	if err != nil {
		return "", err
	}
	bodyContent, err := resp.GetBodyContent()
	if err != nil {
		return "", err
	}
	var clusterResponse *CreateClusterResponse
	if err := json.Unmarshal(bodyContent, &clusterResponse); err != nil {
		return "", err
	}
	return clusterResponse.ClusterUUID, nil
}

type ScalingUpClusterArgs struct {
	ClusterUUID     string                    `json:"clusterUuid"`
	CDSPreMountInfo *PreMountInfo             `json:"cdsPreMountInfo"`
	OrderContent    *BaseCreateOrderRequestVo `json:"orderContent"`
}

func (args *ScalingUpClusterArgs) validate() error {
	if args == nil {
		return fmt.Errorf("ScalingUpClusterArgs cannot be nil")
	}
	if args.ClusterUUID == "" {
		return fmt.Errorf("clusterUuid cannot be empty")
	}
	if args.OrderContent == nil {
		return fmt.Errorf("orderContent cannot be empty")
	}
	return nil
}

func (c *Client) ScalingUpCluster(args *ScalingUpClusterArgs, option *bce.SignOption) (string, error) {
	err := args.validate()
	if err != nil {
		return "", err
	}
	postContent, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	params := map[string]string{
		"scalingUp": "",
	}
	req, err := bce.NewRequest("POST", c.GetURL("v1/cluster", params), bytes.NewBuffer(postContent))
	if err != nil {
		return "", err
	}
	resp, err := c.SendRequest(req, option)
	if err != nil {
		return "", err
	}
	bodyContent, err := resp.GetBodyContent()
	if err != nil {
		return "", err
	}
	var scaleUpResponse *CreateClusterResponse
	if err := json.Unmarshal(bodyContent, &scaleUpResponse); err != nil {
		return "", err
	}
	return scaleUpResponse.ClusterUUID, nil
}

type NodeInfo struct {
	InstanceID string `json:"instanceId"`
}

type ScalingDownClusterArgs struct {
	ClusterUUID string     `json:"clusterUuid"`
	NodeInfo    []NodeInfo `json:"nodeInfo"`
}

func (args *ScalingDownClusterArgs) validate() error {
	if args == nil {
		return fmt.Errorf("scalingDownArgs cannot be nil")
	}
	if args.ClusterUUID == "" {
		return fmt.Errorf("clusterUuid cannot be empty")
	}
	if args.NodeInfo == nil {
		return fmt.Errorf("nodeInfo cannot be empty")
	}
	return nil
}

func (c *Client) ScalingDownCluster(args *ScalingDownClusterArgs, option *bce.SignOption) error {
	err := args.validate()
	if err != nil {
		return err
	}
	postContent, err := json.Marshal(args)
	if err != nil {
		return err
	}
	params := map[string]string{
		"scalingDown": "",
	}
	req, err := bce.NewRequest("POST", c.GetURL("v1/cluster", params), bytes.NewBuffer(postContent))
	if err != nil {
		return err
	}
	_, err = c.SendRequest(req, option)
	if err != nil {
		return err
	}
	return nil
}

type GetClusterNodesArgs struct {
	Marker      string `json:"marker"`
	MaxKeys     int64  `json:"maxKeys"`
	ClusterUUID string `json:"clusterUuid"`
}

type GetClusterNodesResponse struct {
	Marker      string `json:"marker"`
	IsTruncated bool   `json:"isTruncated"`
	NextMarker  string `json:"nextMarker"`
	MaxKeys     int64  `json:"maxKeys"`
	Nodes       []Node `json:"nodes"`
}

type Node struct {
	InstanceShortID string    `json:"instanceShortId"`
	InstanceUUID    string    `json:"instanceUuid"`
	InstanceName    string    `json:"instanceName"`
	ClusterUUID     string    `json:"clusterUuid"`
	AvailableZone   string    `json:"availableZone"`
	VPCID           string    `json:"vpcId"`
	VPCCIDR         string    `json:"vpcCidr"`
	SubnetID        string    `json:"subnetId"`
	EIP             string    `json:"eip"`
	EIPBandwidth    int64     `json:"eipBandwidth"`
	CPU             int64     `json:"cpu"`
	Memory          int64     `json:"memory"`
	DiskSize        int64     `json:"diskSize"`
	SysDisk         int64     `json:"sysDisk"`
	InstanceType    string    `json:"instanceType"`
	FloatingIP      string    `json:"floatingIp"`
	FixIP           string    `json:"fixIp"`
	CreateTime      time.Time `json:"createTime"`
	DeleteTime      time.Time `json:"deleteTime"`
	Status          string    `json:"status"`
	PaymentMethod   string    `json:"paymentMethod"`
}

func (c *Client) GetNodeList(args *GetClusterNodesArgs, option *bce.SignOption) ([]Node, error) {
	if args == nil {
		args = &GetClusterNodesArgs{}
	}
	params := map[string]string{
		"marker":      args.Marker,
		"maxKeys":     strconv.FormatInt(args.MaxKeys, 10),
		"clusterUuid": args.ClusterUUID,
	}
	req, err := bce.NewRequest("GET", c.GetURL("v1/node", params), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.SendRequest(req, option)
	if err != nil {
		return nil, err
	}
	bodyContent, err := resp.GetBodyContent()

	if err != nil {
		return nil, err
	}
	var nodeResponse *GetClusterNodesResponse
	if err := json.Unmarshal(bodyContent, &nodeResponse); err != nil {
		return nil, err
	}
	return nodeResponse.Nodes, nil
}

type KubeConfigResponse struct {
	Data string `json:"data"`
}

func (c *Client) GetKubeConfig(clusterUUID string, option *bce.SignOption) (string, error) {
	parmas := map[string]string{
		"clusterUuid": clusterUUID,
	}
	req, err := bce.NewRequest("GET", c.GetURL("v1/cluster/kubeconfig", parmas), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.SendRequest(req, option)
	if err != nil {
		return "", err
	}
	bodyContent, err := resp.GetBodyContent()

	if err != nil {
		return "", err
	}

	var respArgs *KubeConfigResponse
	if err := json.Unmarshal(bodyContent, &respArgs); err != nil {
		return "", err
	}
	return respArgs.Data, nil
}

type ClusterUpgradeArgs struct {
	ClusterUUID string `json:"clusterUuid"`
	Version     string `json:"version"`
}

func (args *ClusterUpgradeArgs) validate() error {
	if args == nil {
		return fmt.Errorf("CreateClusterArgs cannot be nil")
	}
	if args.ClusterUUID == "" {
		return fmt.Errorf("cluster id cannot be empty")
	}
	if args.Version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	return nil
}

func (c *Client) ClusterUpgrade(clusterUUID, version string, option *bce.SignOption) error {
	args := &ClusterUpgradeArgs{
		ClusterUUID: clusterUUID,
		Version:     version,
	}
	err := args.validate()
	if err != nil {
		return err
	}
	postContent, err := json.Marshal(args)
	if err != nil {
		return err
	}
	req, err := bce.NewRequest("POST", c.GetURL("v1/cluster/cluster_upgrade/upgrade", nil), bytes.NewBuffer(postContent))
	if err != nil {
		return err
	}
	resp, err := c.SendRequest(req, option)
	if err != nil {
		return err
	}

	_, err = resp.GetBodyContent()
	if err != nil {
		return err
	}

	return nil
}
