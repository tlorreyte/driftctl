// GENERATED, DO NOT EDIT THIS FILE
package aws

import "github.com/zclconf/go-cty/cty"

const AwsDefaultSecurityGroupResourceType = "aws_default_security_group"

type AwsDefaultSecurityGroup struct {
	Arn         *string `cty:"arn" computed:"true"`
	Description *string `cty:"description" computed:"true"`
	Egress      *[]struct {
		CidrBlocks     []string `cty:"cidr_blocks"`
		Description    *string  `cty:"description"`
		FromPort       *int     `cty:"from_port"`
		Ipv6CidrBlocks []string `cty:"ipv6_cidr_blocks"`
		PrefixListIds  []string `cty:"prefix_list_ids"`
		Protocol       *string  `cty:"protocol"`
		SecurityGroups []string `cty:"security_groups"`
		Self           *bool    `cty:"self"`
		ToPort         *int     `cty:"to_port"`
	} `cty:"egress" computed:"true"`
	Id      string `cty:"id" computed:"true"`
	Ingress *[]struct {
		CidrBlocks     []string `cty:"cidr_blocks"`
		Description    *string  `cty:"description"`
		FromPort       *int     `cty:"from_port"`
		Ipv6CidrBlocks []string `cty:"ipv6_cidr_blocks"`
		PrefixListIds  []string `cty:"prefix_list_ids"`
		Protocol       *string  `cty:"protocol"`
		SecurityGroups []string `cty:"security_groups"`
		Self           *bool    `cty:"self"`
		ToPort         *int     `cty:"to_port"`
	} `cty:"ingress" computed:"true"`
	Name                *string           `cty:"name" computed:"true"`
	OwnerId             *string           `cty:"owner_id" computed:"true"`
	RevokeRulesOnDelete *bool             `cty:"revoke_rules_on_delete" diff:"-"`
	Tags                map[string]string `cty:"tags"`
	VpcId               *string           `cty:"vpc_id" computed:"true"`
	CtyVal              *cty.Value        `diff:"-"`
}

func (r *AwsDefaultSecurityGroup) TerraformId() string {
	return r.Id
}

func (r *AwsDefaultSecurityGroup) TerraformType() string {
	return AwsDefaultSecurityGroupResourceType
}

func (r *AwsDefaultSecurityGroup) CtyValue() *cty.Value {
	return r.CtyVal
}
