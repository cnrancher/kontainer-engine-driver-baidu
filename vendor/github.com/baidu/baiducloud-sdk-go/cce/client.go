package cce

import (
	"github.com/baidu/baiducloud-sdk-go/bce"
)

// Endpoint contains all endpoints of Baidu Cloud CCE.
var Endpoint = map[string]string{
	"bj": "cce.bj.baidubce.com",
	"gz": "cce.gz.baidubce.com",
	"su": "cce.su.baidubce.com",
	"bd": "cce.bd.baidubce.com",
	"fwh": "cce.fwh.baidubce.com",
	"hkg": "cce.hkg.baidubce.com",
}

// Client is the CCE client implemention for Baidu Cloud CCE API.
type Client struct {
	*bce.Client
}

func NewClient(config *bce.Config) *Client {
	bceClient := bce.NewClient(config)
	return &Client{bceClient}
}

// GetURL generates the full URL of http request for Baidu Cloud CCE API.
func (c *Client) GetURL(objectKey string, params map[string]string) string {
	host := c.Endpoint

	if host == "" {
		host = Endpoint[c.GetRegion()]
	}

	uriPath := objectKey

	return c.Client.GetURL(host, uriPath, params)
}