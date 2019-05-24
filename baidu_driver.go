package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/baidu/baiducloud-sdk-go/bce"
	"github.com/baidu/baiducloud-sdk-go/cce"
	"github.com/baidu/baiducloud-sdk-go/eip"
	"k8s.io/client-go/rest"
	"strings"
	"time"

	"github.com/rancher/kontainer-engine/drivers/options"
	"github.com/rancher/kontainer-engine/drivers/util"
	"github.com/rancher/kontainer-engine/types"
	"github.com/rancher/rke/log"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Driver defines the struct of baidu driver
type Driver struct {
	driverCapabilities types.Capabilities
}

type state struct {
	// The id of the cluster
	ClusterID string
	// The name of the cluster
	ClusterName string
	// The zone to launch the cluster
	Zone string
	// The IP address range of the container pods
	ContainerCidr string
	// An optional description of this clusterO
	Description string
	// the version of cluster
	ClusterVersion string

	AccessKey         string
	SecretKey         string
	Region            string
	OSVersion         string
	OSType            string
	SecurityGroupID   string
	SecurityGroupName string
	ImageID           string
	AdminPass         string
	AdminPassConfirm  string
	SubnetID          string
	DiskSize          int64
	IfBuyEIP          *bool
	EIPName           string
	BandwidthInMbps   int64
	SubProductType    string
	CPU               int64
	Memory            int64
	InstanceType      int64
	CDSConfig         []string

	NodeCount int64
	// cluster info
	ClusterInfo types.ClusterInfo
}

func NewDriver() types.Driver {
	driver := &Driver{
		driverCapabilities: types.Capabilities{
			Capabilities: make(map[int64]bool),
		},
	}

	driver.driverCapabilities.AddCapability(types.GetVersionCapability)
	driver.driverCapabilities.AddCapability(types.SetVersionCapability)
	driver.driverCapabilities.AddCapability(types.GetClusterSizeCapability)
	driver.driverCapabilities.AddCapability(types.SetClusterSizeCapability)

	return driver
}

// GetDriverCreateOptions implements driver interface
func (d *Driver) GetDriverCreateOptions(ctx context.Context) (*types.DriverFlags, error) {
	driverFlag := types.DriverFlags{
		Options: make(map[string]*types.Flag),
	}
	driverFlag.Options["name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the internal name of the cluster in Rancher",
	}
	driverFlag.Options["cluster-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of the cluster that should be displayed to the user",
	}
	driverFlag.Options["project-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "the ID of your project to use when creating a cluster",
	}
	driverFlag.Options["zone"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The zone to launch the cluster",
		Default: &types.Default{
			DefaultString: "zoneC",
		},
	}
	driverFlag.Options["description"] = &types.Flag{
		Type:  types.StringType,
		Usage: "An optional description of this cluster",
	}
	driverFlag.Options["cluster-version"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The version of cluster",
	}
	driverFlag.Options["container-cidr"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The IP address range of the container pods",
	}
	driverFlag.Options["access-key"] = &types.Flag{
		Type:     types.StringType,
		Usage:    "Access key for credential",
		Password: true,
	}
	driverFlag.Options["secret-key"] = &types.Flag{
		Type:     types.StringType,
		Usage:    "Secret key for credential",
		Password: true,
	}
	driverFlag.Options["region"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The ID of the region in which the cluster resides",
		Default: &types.Default{
			DefaultString: "bj",
		},
	}
	driverFlag.Options["os-version"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The os system version for cluster nodes",
	}
	driverFlag.Options["os-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The os system type for cluster nodes",
	}
	driverFlag.Options["security-group-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The security group id",
	}
	driverFlag.Options["security-group-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The security group name",
	}
	driverFlag.Options["image-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The image id of os system",
	}
	driverFlag.Options["admin-pass"] = &types.Flag{
		Type:     types.StringType,
		Usage:    "The admin user password for nodes",
		Password: true,
	}
	driverFlag.Options["admin-pass-confirm"] = &types.Flag{
		Type:     types.StringType,
		Usage:    "Confirm password for admin user",
		Password: true,
	}
	driverFlag.Options["subnet-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The subnet for node",
	}
	driverFlag.Options["if-buy-eip"] = &types.Flag{
		Type:  types.BoolPointerType,
		Usage: "Choose if you need an EIP for your nodes",
		Default: &types.Default{
			DefaultBool: false,
		},
	}
	driverFlag.Options["eip-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of EIP",
	}
	driverFlag.Options["bandwidth-in-mbps"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The bandwidth of your eip",
	}
	driverFlag.Options["sub-product-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Subproduct type",
	}
	driverFlag.Options["node-count"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The number of nodes to create in this cluster",
		Default: &types.Default{
			DefaultInt: 3,
		},
	}
	driverFlag.Options["instance-type"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Instance type for BCC config",
	}
	driverFlag.Options["cpu"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The size of cpu",
	}
	driverFlag.Options["memory"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The size of memory",
	}
	driverFlag.Options["cds-config"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "Mount CDS disks for your cluster",
		Default: &types.Default{
			DefaultStringSlice: &types.StringSlice{Value: []string{}}, //avoid nil value for init
		},
	}

	return &driverFlag, nil
}

// GetDriverUpdateOptions implements driver interface
func (d *Driver) GetDriverUpdateOptions(ctx context.Context) (*types.DriverFlags, error) {
	driverFlag := types.DriverFlags{
		Options: make(map[string]*types.Flag),
	}
	driverFlag.Options["zone"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The zone to launch the cluster",
		Default: &types.Default{
			DefaultString: "zoneC",
		},
	}
	driverFlag.Options["region"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The ID of the region in which the cluster resides",
		Default: &types.Default{
			DefaultString: "bj",
		},
	}
	driverFlag.Options["os-version"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The os system version for cluster nodes",
	}
	driverFlag.Options["os-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The os system type for cluster nodes",
	}
	driverFlag.Options["security-group-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The security group id",
	}
	driverFlag.Options["security-group-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The security group name",
	}
	driverFlag.Options["image-id"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The image id of os system",
	}
	driverFlag.Options["admin-pass"] = &types.Flag{
		Type:     types.StringType,
		Usage:    "The admin user password for nodes",
		Password: true,
	}
	driverFlag.Options["admin-pass-confirm"] = &types.Flag{
		Type:     types.StringType,
		Usage:    "Confirm password for admin user",
		Password: true,
	}
	driverFlag.Options["sub-product-type"] = &types.Flag{
		Type:  types.StringType,
		Usage: "Subproduct type",
	}
	driverFlag.Options["if-buy-eip"] = &types.Flag{
		Type:  types.BoolPointerType,
		Usage: "Choose if you need an EIP for your nodes",
		Default: &types.Default{
			DefaultBool: false,
		},
	}
	driverFlag.Options["eip-name"] = &types.Flag{
		Type:  types.StringType,
		Usage: "The name of EIP",
	}
	driverFlag.Options["bandwidth-in-mbps"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The bandwidth of your eip",
	}
	driverFlag.Options["node-count"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The node number for your cluster to update. 0 means no updates",
	}
	driverFlag.Options["instance-type"] = &types.Flag{
		Type:  types.IntType,
		Usage: "Instance type for BCC config",
	}
	driverFlag.Options["cpu"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The size of cpu",
	}
	driverFlag.Options["memory"] = &types.Flag{
		Type:  types.IntType,
		Usage: "The size of memory",
	}
	driverFlag.Options["cds-config"] = &types.Flag{
		Type:  types.StringSliceType,
		Usage: "Mount CDS disks for your cluster",
		Default: &types.Default{
			DefaultStringSlice: &types.StringSlice{Value: []string{}}, //avoid nil value for init
		},
	}
	return &driverFlag, nil
}

// SetDriverOptions implements driver interface
func getStateFromOpts(driverOptions *types.DriverOptions) (*state, error) {
	d := &state{
		ClusterInfo: types.ClusterInfo{
			Metadata: map[string]string{},
		},
	}

	d.ClusterName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-name", "clusterName").(string)
	d.Zone = options.GetValueFromDriverOptions(driverOptions, types.StringType, "zone").(string)
	d.ContainerCidr = options.GetValueFromDriverOptions(driverOptions, types.StringType, "container-cidr", "containerCidr").(string)
	d.Description = options.GetValueFromDriverOptions(driverOptions, types.StringType, "description").(string)
	d.ClusterVersion = options.GetValueFromDriverOptions(driverOptions, types.StringType, "cluster-version", "clusterVersion").(string)
	d.AccessKey = options.GetValueFromDriverOptions(driverOptions, types.StringType, "access-key", "accessKey").(string)
	d.SecretKey = options.GetValueFromDriverOptions(driverOptions, types.StringType, "secret-key", "secretKey").(string)
	d.Region = options.GetValueFromDriverOptions(driverOptions, types.StringType, "region", "region").(string)
	d.OSVersion = options.GetValueFromDriverOptions(driverOptions, types.StringType, "os-version", "osVersion").(string)
	d.OSType = options.GetValueFromDriverOptions(driverOptions, types.StringType, "os-type", "osType").(string)
	d.SecurityGroupID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "security-group-id", "securityGroupId").(string)
	d.SecurityGroupName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "security-group-name", "securityGroupName").(string)
	d.ImageID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "image-id", "imageId").(string)
	d.AdminPass = options.GetValueFromDriverOptions(driverOptions, types.StringType, "admin-pass", "adminPass").(string)
	d.AdminPassConfirm = options.GetValueFromDriverOptions(driverOptions, types.StringType, "admin-pass-confirm", "adminPassConfirm").(string)
	d.SubnetID = options.GetValueFromDriverOptions(driverOptions, types.StringType, "subnet-id", "subnetId").(string)
	d.CPU = options.GetValueFromDriverOptions(driverOptions, types.IntType, "cpu", "cpu").(int64)
	d.Memory = options.GetValueFromDriverOptions(driverOptions, types.IntType, "memory", "memory").(int64)
	d.NodeCount = options.GetValueFromDriverOptions(driverOptions, types.IntType, "node-count", "nodeCount").(int64)
	d.SubProductType = options.GetValueFromDriverOptions(driverOptions, types.StringType, "sub-product-type", "subProductType").(string)
	d.IfBuyEIP, _ = options.GetValueFromDriverOptions(driverOptions, types.BoolPointerType, "if-buy-eip", "ifBuyEip").(*bool)
	d.EIPName = options.GetValueFromDriverOptions(driverOptions, types.StringType, "eip-name", "eipName").(string)
	d.BandwidthInMbps = options.GetValueFromDriverOptions(driverOptions, types.IntType, "bandwidth-in-mbps", "bandwidthInMbps").(int64)
	d.CDSConfig = options.GetValueFromDriverOptions(driverOptions, types.StringSliceType, "cds-config", "cdsConfig").(*types.StringSlice).Value
	d.InstanceType = options.GetValueFromDriverOptions(driverOptions, types.IntType, "instance-type", "instanceType").(int64)

	return d, d.validate()
}

func (s *state) validate() error {
	if s.AccessKey == "" {
		return fmt.Errorf("accessKey is required")
	} else if s.SecretKey == "" {
		return fmt.Errorf("secretKey is required")
	} else if s.Zone == "" {
		return fmt.Errorf("zone is required")
	} else if s.ClusterName == "" {
		return fmt.Errorf("cluster name is required")
	} else if s.ClusterVersion == "" {
		return fmt.Errorf("cluster version is required")
	} else if s.Region == "" {
		return fmt.Errorf("region is required")
	} else if s.ContainerCidr == "" {
		return fmt.Errorf("container cidr is required")
	} else if s.SubnetID == "" {
		return fmt.Errorf("subnetId is required")
	} else if s.ImageID == "" {
		return fmt.Errorf("imageId is required")
	} else if s.SecurityGroupID == "" {
		return fmt.Errorf("security group id is required")
	}

	return nil
}

// Create implements driver interface
func (d *Driver) Create(ctx context.Context, opts *types.DriverOptions, _ *types.ClusterInfo) (*types.ClusterInfo, error) {
	state, err := getStateFromOpts(opts)
	if err != nil {
		return nil, err
	}

	info := &types.ClusterInfo{}
	defer storeState(info, state)

	client, err := getServiceClient(state)
	if err != nil {
		return info, err
	}

	createArgs := generateClusterCreateRequest(state)

	clusterID, err := client.CreateCluster(createArgs, nil)
	if err != nil {
		return info, err
	}

	state.ClusterID = clusterID
	if err := d.waitBaiduCluster(ctx, client, state); err != nil {
		return info, err
	}
	return info, nil
}

func storeState(info *types.ClusterInfo, state *state) error {
	bytes, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if info.Metadata == nil {
		info.Metadata = map[string]string{}
	}
	info.Metadata["state"] = string(bytes)
	return nil
}

func getState(info *types.ClusterInfo) (*state, error) {
	state := &state{}
	// ignore error
	err := json.Unmarshal([]byte(info.Metadata["state"]), &state)
	return state, err
}

// Update implements driver interface
func (d *Driver) Update(ctx context.Context, info *types.ClusterInfo, opts *types.DriverOptions) (*types.ClusterInfo, error) {
	updateState, err := getStateFromOpts(opts)
	if err != nil {
		return nil, err
	}

	state, err := getState(info)
	if err != nil {
		return nil, err
	}

	if state.NodeCount != updateState.NodeCount {
		client, err := getServiceClient(state)
		if err != nil {
			return info, err
		}
		args := &cce.GetClusterNodesArgs{
			ClusterUUID: state.ClusterID,
			Marker:      "-1",
			MaxKeys:     10000,
		}
		nodeList, err := client.GetNodeList(args, nil)
		clusterNodeCount := int64(len(nodeList))

		currentCount := updateState.NodeCount
		// check to scale up or down
		if updateState.NodeCount > clusterNodeCount {
			logrus.Info("Scaling up cluster")
			scaleNum := updateState.NodeCount - clusterNodeCount
			updateState.NodeCount = scaleNum
			args := generateScalingUpRequest(state.ClusterID, updateState)
			_, err = client.ScalingUpCluster(args, nil)
			if err != nil {
				return nil, err
			}
			logrus.Infof("Scaling up cluster %v success", state.ClusterID)
			if err := d.waitBaiduCluster(ctx, client, state); err != nil {
				return info, err
			}
		} else if updateState.NodeCount < clusterNodeCount {
			logrus.Info("Scaling down cluster")
			deleteCount := state.NodeCount - updateState.NodeCount
			if clusterNodeCount < deleteCount {
				return nil, fmt.Errorf("total count of current cluster nodes is %d, fail to remove requested value of %d",
					clusterNodeCount, deleteCount)
			}
			var instanceIds = make([]cce.NodeInfo, updateState.NodeCount)
			removeNodes := nodeList[:deleteCount]
			for i, node := range removeNodes {
				instanceIds[i].InstanceID = node.InstanceShortID
			}

			req := &cce.ScalingDownClusterArgs{
				ClusterUUID: state.ClusterID,
				NodeInfo:    instanceIds,
			}
			err = client.ScalingDownCluster(req, nil)
			if err != nil {
				return nil, err
			}
			logrus.Infof("delete total %d nodes of cluster %v", deleteCount, state.ClusterID)

			eipClient, err := getEipClient(state)
			if err != nil {
				return nil, err
			}
			// remove unused eip
			for _, n := range removeNodes {
				eipArgs := &eip.EipArgs{
					Ip: n.EIP,
				}
				err = eipClient.UnbindEip(eipArgs, nil)
				if err != nil {
					return nil, err
				}
				err = eipClient.DeleteEip(eipArgs, nil)
				if err != nil {
					return nil, err
				}
			}
			if err := d.waitBaiduCluster(ctx, client, state); err != nil {
				return info, err
			}
		}
		state.NodeCount = currentCount
	}
	return info, storeState(info, state)
}

func generateScalingUpRequest(clusterID string, state *state) *cce.ScalingUpClusterArgs {
	args := &cce.ScalingUpClusterArgs{
		ClusterUUID:  clusterID,
		OrderContent: generateOrderContent(state),
	}
	if len(state.CDSConfig) > 0 {
		args.CDSPreMountInfo = &cce.PreMountInfo{
			MountPath: "/data",
		}
		cdsConfig := []cce.DiskSizeConfig{}
		for _, cds := range state.CDSConfig {
			cdsArray := strings.Split(cds, ":")
			if len(cdsArray) == 2 {
				config := cce.DiskSizeConfig{
					Size:       cdsArray[1],
					VolumeType: cdsArray[0],
				}
				cdsConfig = append(cdsConfig, config)
			}
		}
		args.CDSPreMountInfo.CdsConfig = cdsConfig
	}

	return args
}

func generateClusterCreateRequest(state *state) *cce.CreateClusterArgs {
	request := cce.CreateClusterArgs{
		ClusterName:       state.ClusterName,
		Version:           state.ClusterVersion,
		MainAvailableZone: state.Zone,
		ContainerNet:      state.ContainerCidr,
		Comment:           state.Description,
		AdvancedOptions: &cce.AdvancedOptions{
			KubeProxyMode:         "iptables",
			SecureContainerEnable: false,
		},
	}

	if len(state.CDSConfig) > 0 {
		request.CDSPreMountInfo = &cce.PreMountInfo{
			MountPath: "/data",
		}
		cdsConfig := []cce.DiskSizeConfig{}
		for _, cds := range state.CDSConfig {
			cdsArray := strings.Split(cds, ":")
			if len(cdsArray) == 2 {
				config := cce.DiskSizeConfig{
					Size:       cdsArray[1],
					VolumeType: cdsArray[0],
				}
				cdsConfig = append(cdsConfig, config)
			}
		}
		request.CDSPreMountInfo.CdsConfig = cdsConfig
	}

	request.OrderContent = generateOrderContent(state)

	return &request
}

func generateOrderContent(state *state) *cce.BaseCreateOrderRequestVo {
	content := &cce.BaseCreateOrderRequestVo{
		Items: []cce.Item{},
	}

	bccRequest := &cce.BCCConfig{
		LogicalZone:       state.Zone,
		InstanceType:      state.InstanceType,
		CPU:               state.CPU,
		Memory:            state.Memory,
		ImageType:         "common",
		EBSSize:           []int64{},
		OSType:            state.OSType,
		OSVersion:         state.OSVersion,
		SecurityGroupID:   state.SecurityGroupID,
		SecurityGroupName: state.SecurityGroupName,
		AdminPass:         state.AdminPass,
		AdminPassConfirm:  state.AdminPassConfirm,
		ImageID:           state.ImageID,
		SubnetUUID:        state.SubnetID,
		DiskSize:          state.DiskSize,
		IfBuyEIP:          *state.IfBuyEIP,
		EIPName:           state.EIPName,
		BandwidthInMbps:   state.BandwidthInMbps,
		AutoRenew:         false,
	}
	bccRequest.ProductType = cce.PostPayProductType
	bccRequest.Region = state.Region
	bccRequest.PurchaseNum = state.NodeCount
	bccRequest.ServiceType = cce.InstanceServiceType

	content.Items = append(content.Items, cce.Item{
		Config: bccRequest,
	})

	if state.IfBuyEIP != nil && *state.IfBuyEIP {
		eipRequest := &cce.EIPConfig{
			Name:            state.EIPName,
			BandwidthInMbps: state.BandwidthInMbps,
		}
		eipRequest.ProductType = cce.PostPayProductType
		eipRequest.Region = state.Region
		eipRequest.PurchaseNum = state.NodeCount
		eipRequest.ServiceType = cce.EIPServiceType
		eipRequest.SubProductType = state.SubProductType

		content.Items = append(content.Items, cce.Item{
			Config: eipRequest,
		})
	}

	if len(state.CDSConfig) > 0 {
		cdsConfig := []cce.DiskSizeConfig{}
		for _, cds := range state.CDSConfig {
			cdsArray := strings.Split(cds, ":")
			if len(cdsArray) == 2 {
				config := cce.DiskSizeConfig{
					Size:       cdsArray[1],
					VolumeType: cdsArray[0],
				}
				cdsConfig = append(cdsConfig, config)
			}
		}
		cdsRequest := &cce.CDSConfig{
			LogicalZone: state.Zone,
			CDSDiskSize: cdsConfig,
		}
		cdsRequest.ProductType = cce.PostPayProductType
		cdsRequest.Region = state.Region
		cdsRequest.PurchaseNum = state.NodeCount
		cdsRequest.ServiceType = cce.CDSServiceType

		content.Items = append(content.Items, cce.Item{
			Config: cdsRequest,
		})
	}

	return content
}

func (d *Driver) PostCheck(ctx context.Context, info *types.ClusterInfo) (*types.ClusterInfo, error) {
	clientset, err := getClientset(info)
	if err != nil {
		return nil, err
	}
	serviceAccountToken, err := util.GenerateServiceAccountToken(clientset)
	if err != nil {
		return nil, err
	}
	info.ServiceAccountToken = serviceAccountToken

	return info, nil
}

// Remove implements driver interface
func (d *Driver) Remove(ctx context.Context, info *types.ClusterInfo) error {
	state, err := getState(info)
	if err != nil {
		return err
	}

	svc, err := getServiceClient(state)
	if err != nil {
		return err
	}

	// Get node list
	args := &cce.GetClusterNodesArgs{
		ClusterUUID: state.ClusterID,
		Marker:      "-1",
		MaxKeys:     10000,
	}
	nodeList, err := svc.GetNodeList(args, nil)
	if err != nil {
		return err
	}

	eipClient, err := getEipClient(state)
	if err != nil {
		return err
	}

	// Unbind all eips and remove them
	for _, node := range nodeList {
		eipArgs := &eip.EipArgs{
			Ip: node.EIP,
		}
		err = eipClient.UnbindEip(eipArgs, nil)
		if err != nil {
			return err
		}
		err = eipClient.DeleteEip(eipArgs, nil)
		if err != nil {
			return err
		}
	}

	logrus.Debugf("Removing cluster %v from Region %v, zone %v", state.ClusterName, state.Region, state.Zone)
	err = svc.DeleteCluster(state.ClusterID, nil)
	if err != nil {
		return err
	}

	return nil
}

func getServiceClient(state *state) (*cce.Client, error) {
	cred := bce.NewCredentials(state.AccessKey, state.SecretKey)
	bceConf := &bce.Config{
		Credentials: cred,
		Checksum:    true,
		Timeout:     20 * time.Second,
		Region:      state.Region,
		Protocol:    "https",
	}
	client := cce.NewClient(bceConf)
	return client, nil
}

func getEipClient(state *state) (*eip.Client, error) {
	cred := bce.NewCredentials(state.AccessKey, state.SecretKey)
	bceConf := &bce.Config{
		Credentials: cred,
		Checksum:    true,
		Timeout:     20 * time.Second,
		Region:      state.Region,
		Protocol:    "https",
	}
	client := eip.NewEIPClient(bceConf)
	return client, nil
}

func getClientset(info *types.ClusterInfo) (*kubernetes.Clientset, error) {
	state, err := getState(info)
	if err != nil {
		return nil, err
	}
	client, err := getServiceClient(state)
	if err != nil {
		return nil, err
	}

	config, err := client.GetKubeConfig(state.ClusterID, nil)
	if err != nil {
		return nil, err
	}

	userConfig, err := clientcmd.Load([]byte(config))
	if err != nil {
		return nil, fmt.Errorf("error get config with config file %v: %v", config, err)
	}
	currentContext := userConfig.Contexts[userConfig.CurrentContext]
	info.Endpoint = userConfig.Clusters[currentContext.Cluster].Server
	info.Version = state.ClusterVersion
	info.RootCaCertificate = base64.StdEncoding.EncodeToString(userConfig.Clusters[currentContext.Cluster].CertificateAuthorityData)
	info.ClientCertificate = base64.StdEncoding.EncodeToString(userConfig.AuthInfos[currentContext.AuthInfo].ClientCertificateData)
	info.ClientKey = base64.StdEncoding.EncodeToString(userConfig.AuthInfos[currentContext.AuthInfo].ClientKeyData)
	info.NodeCount = state.NodeCount

	host := userConfig.Clusters[currentContext.Cluster].Server
	if !strings.HasPrefix(host, "https://") {
		host = fmt.Sprintf("https://%s", host)
	}

	cfg := &rest.Config{
		Host: host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData:   userConfig.Clusters[currentContext.Cluster].CertificateAuthorityData,
			KeyData:  userConfig.AuthInfos[currentContext.AuthInfo].ClientKeyData,
			CertData: userConfig.AuthInfos[currentContext.AuthInfo].ClientCertificateData,
		},
	}

	return kubernetes.NewForConfig(cfg)
}

func (d *Driver) waitBaiduCluster(ctx context.Context, client *cce.Client, state *state) error {
	lastMsg := ""
	for {
		cluster, err := client.DescribeCluster(state.ClusterID, nil)
		if err != nil {
			return err
		}
		if cluster.Status == cce.ClusterStatusRunning {
			log.Infof(ctx, "Cluster %v is running", state.ClusterName)
			return nil
		}
		if cluster.Status != lastMsg {
			log.Infof(ctx, "%v cluster %v......", strings.ToLower(cluster.Status), state.ClusterName)
			lastMsg = cluster.Status
		}
		time.Sleep(time.Second * 5)
	}
}

func (d *Driver) getClusterStats(ctx context.Context, info *types.ClusterInfo) (*cce.Cluster, error) {
	state, err := getState(info)

	if err != nil {
		return nil, err
	}

	client, err := getServiceClient(state)

	if err != nil {
		return nil, err
	}
	cluster, err := client.DescribeCluster(state.ClusterID, nil)

	if err != nil {
		return nil, fmt.Errorf("error getting cluster info: %v", err)
	}

	return cluster, nil
}

func (d *Driver) GetClusterSize(ctx context.Context, info *types.ClusterInfo) (*types.NodeCount, error) {
	state, err := getState(info)
	if err != nil {
		return nil, err
	}
	client, err := getServiceClient(state)
	args := &cce.GetClusterNodesArgs{
		ClusterUUID: state.ClusterID,
		Marker:      "-1",
		MaxKeys:     10000,
	}
	nodeList, err := client.GetNodeList(args, nil)
	nodeCount := &types.NodeCount{Count: int64(len(nodeList))}

	return nodeCount, nil
}

func (d *Driver) SetClusterSize(ctx context.Context, info *types.ClusterInfo, count *types.NodeCount) error {
	logrus.Info("unimplemented")
	return nil
}

func (d *Driver) GetVersion(ctx context.Context, info *types.ClusterInfo) (*types.KubernetesVersion, error) {
	cluster, err := d.getClusterStats(ctx, info)

	if err != nil {
		return nil, err
	}

	version := &types.KubernetesVersion{Version: cluster.Version}

	return version, nil
}

func (d *Driver) SetVersion(ctx context.Context, info *types.ClusterInfo, version *types.KubernetesVersion) error {
	logrus.Info("unimplemented")
	return nil
}

func (d *Driver) GetCapabilities(ctx context.Context) (*types.Capabilities, error) {
	return &d.driverCapabilities, nil
}

func (d *Driver) ETCDSave(ctx context.Context, clusterInfo *types.ClusterInfo, opts *types.DriverOptions, snapshotName string) error {
	return fmt.Errorf("ETCD backup operations are not implemented")
}

func (d *Driver) ETCDRestore(ctx context.Context, clusterInfo *types.ClusterInfo, opts *types.DriverOptions, snapshotName string) error {
	return fmt.Errorf("ETCD backup operations are not implemented")
}

func (d *Driver) GetK8SCapabilities(ctx context.Context, options *types.DriverOptions) (*types.K8SCapabilities, error) {
	capabilities := &types.K8SCapabilities{
		L4LoadBalancer: &types.LoadBalancerCapabilities{
			Enabled:              true,
			Provider:             "Baidu Cloud L4 LB",
			ProtocolsSupported:   []string{"TCP", "UDP"},
			HealthCheckSupported: true,
		},
	}
	capabilities.IngressControllers = []*types.IngressCapabilities{
		{
			IngressProvider:      "Baidu Cloud Ingress",
			CustomDefaultBackend: true,
		},
	}
	return capabilities, nil
}

func (d *Driver) RemoveLegacyServiceAccount(ctx context.Context, info *types.ClusterInfo) error {
	clientset, err := getClientset(info)
	if err != nil {
		return err
	}

	err = util.DeleteLegacyServiceAccountAndRoleBinding(clientset)
	if err != nil {
		return err
	}

	return nil
}
