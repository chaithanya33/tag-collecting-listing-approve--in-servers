​"""
AWS Tag Compliance Checker & Auto-Tagger  —  Prod-Safe with Approval Gate
==========================================================================

HOW IT WORKS  (exactly like Terraform plan → approve → apply):

  PHASE 1  SCAN     Read every resource across ALL regions. ZERO writes.
                    Builds a full plan of what tags are missing on what resource.

  APPROVAL GATE     Prints a table of every resource that will be tagged.
                    Waits for you to type  yes  before touching anything.

  PHASE 2  APPLY    Only runs after your approval. Tags every resource in
                    the plan and prints a live log as each one is done.

REQUIRED TAGS:
  Cost Center   = prod-Cost
  Region        = <dynamic: resource's own AWS region>
  Project       = caspa-enterprise
  Owner         = developer
  map-migrated  = migM9SPIUCDZT
  AWSService    = <dynamic: exact resource type e.g. SecurityGroup, EBS …>
  ManagedBy     = Terraform
  Environment   = prod
  Name          = <existing Name tag or resource ID / name as fallback>
  Application   = capsa

USAGE:
  export AWS_ACCESS_KEY_ID=YOUR_KEY
  export AWS_SECRET_ACCESS_KEY=YOUR_SECRET
  export AWS_DEFAULT_REGION=us-east-1
  pip install boto3
  python aws_tag_compliance.py
"""

import sys
import boto3
from collections import defaultdict
from botocore.exceptions import ClientError

# ─────────────────────────────────────────────────────────────────────────────
# STATIC TAG VALUES  —  change here if needed
# ─────────────────────────────────────────────────────────────────────────────
STATIC_TAGS = {
    "Cost Center":  "prod-Cost",
    "Project":      "caspa-enterprise",
    "Owner":        "developer",
    "map-migrated": "migM9SPIUCDZT",
    "ManagedBy":    "Terraform",
    "Environment":  "prod",
    "Application":  "capsa",
}

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL PLAN LIST
# Populated during SCAN (Phase 1). Executed during APPLY (Phase 2).
# Each entry is a dict:
#   type     → human-readable resource type  e.g. "Security Group"
#   id       → resource id / ARN
#   name     → Name tag value (or fallback to id)
#   region   → AWS region or "global"
#   service  → AWSService tag value  e.g. "SecurityGroup"
#   missing  → dict { tag_key: tag_value }  of tags to add
#   apply_fn → zero-arg callable that performs the actual AWS tag write
# ─────────────────────────────────────────────────────────────────────────────
PLAN = []


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def section(title):
    print(f"\n{'═' * 70}", flush=True)
    print(f"  {title}", flush=True)
    print(f"{'═' * 70}", flush=True)

def subsection(title):
    print(f"\n  ── {title} {'─' * max(1, 55 - len(title))}", flush=True)

def scan_log(msg):  print(f"  [SCAN]    {msg}", flush=True)
def ok_log(msg):    print(f"  [OK]      {msg}", flush=True)
def apply_log(msg): print(f"  [APPLY]   {msg}", flush=True)
def warn_log(msg):  print(f"  [WARN]    {msg}", flush=True)
def err_log(msg):   print(f"  [ERROR]   {msg}", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# TAG UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
def build_required(region: str, service: str, name: str) -> dict:
    tags = dict(STATIC_TAGS)
    tags["Region"]     = region
    tags["AWSService"] = service
    tags["Name"]       = name
    return tags

def missing_tags(existing: dict, required: dict) -> dict:
    """Return only tags that are absent or empty in existing."""
    return {k: v for k, v in required.items() if not existing.get(k)}

def kv_to_dict(tag_list) -> dict:
    """[{'Key':k,'Value':v}]  →  {k: v}"""
    return {t["Key"]: t["Value"] for t in (tag_list or [])}

def dict_to_kv(d: dict) -> list:
    """{'k':'v'}  →  [{'Key':'k','Value':'v'}]"""
    return [{"Key": k, "Value": v} for k, v in d.items()]

def get_name(tags: dict, fallback: str) -> str:
    return tags.get("Name") or fallback

def add_to_plan(rtype, rid, name, region, service, missing, apply_fn):
    PLAN.append({
        "type":     rtype,
        "id":       rid,
        "name":     name,
        "region":   region,
        "service":  service,
        "missing":  missing,
        "apply_fn": apply_fn,
    })


# ─────────────────────────────────────────────────────────────────────────────
# GET ALL ACTIVE REGIONS
# ─────────────────────────────────────────────────────────────────────────────
def get_all_regions() -> list:
    ec2  = boto3.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(Filters=[{
        "Name":   "opt-in-status",
        "Values": ["opt-in-not-required", "opted-in"]
    }])
    return sorted(r["RegionName"] for r in resp["Regions"])


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 — SCAN FUNCTIONS   (READ-ONLY, zero AWS writes)
# Every function discovers resources and calls add_to_plan() for those missing
# tags. The apply_fn stored in the plan is a closure — it runs only in Phase 2.
# ═════════════════════════════════════════════════════════════════════════════

# ─── EC2 INSTANCES ───────────────────────────────────────────────────────────
def scan_ec2_instances(region):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                if inst["State"]["Name"] == "terminated":
                    continue
                rid      = inst["InstanceId"]
                existing = kv_to_dict(inst.get("Tags", []))
                name     = get_name(existing, rid)
                required = build_required(region, "EC2", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"EC2 Instance  [{name}]  ({rid})  needs → {list(missing.keys())}")
                    add_to_plan("EC2 Instance", rid, name, region, "EC2", missing,
                                lambda _r=rid, _m=missing, _rg=region:
                                    boto3.client("ec2", region_name=_rg)
                                        .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"EC2 Instance  [{name}]  — fully tagged")

# ─── EBS VOLUMES ─────────────────────────────────────────────────────────────
def scan_ebs_volumes(region):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_volumes").paginate():
        for vol in page["Volumes"]:
            rid      = vol["VolumeId"]
            existing = kv_to_dict(vol.get("Tags", []))
            name     = get_name(existing, rid)
            required = build_required(region, "EBS", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"EBS Volume  [{name}]  ({rid})  needs → {list(missing.keys())}")
                add_to_plan("EBS Volume", rid, name, region, "EBS", missing,
                            lambda _r=rid, _m=missing, _rg=region:
                                boto3.client("ec2", region_name=_rg)
                                    .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
            else:
                ok_log(f"EBS Volume  [{name}]  — fully tagged")

# ─── EBS SNAPSHOTS ───────────────────────────────────────────────────────────
def scan_ebs_snapshots(region):
    ec2     = boto3.client("ec2", region_name=region)
    account = boto3.client("sts").get_caller_identity()["Account"]
    for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=[account]):
        for snap in page["Snapshots"]:
            rid      = snap["SnapshotId"]
            existing = kv_to_dict(snap.get("Tags", []))
            name     = get_name(existing, rid)
            required = build_required(region, "EBSSnapshot", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"EBS Snapshot  [{name}]  ({rid})  needs → {list(missing.keys())}")
                add_to_plan("EBS Snapshot", rid, name, region, "EBSSnapshot", missing,
                            lambda _r=rid, _m=missing, _rg=region:
                                boto3.client("ec2", region_name=_rg)
                                    .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
            else:
                ok_log(f"EBS Snapshot  [{name}]  — fully tagged")

# ─── SECURITY GROUPS ─────────────────────────────────────────────────────────
def scan_security_groups(region):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            rid      = sg["GroupId"]
            existing = kv_to_dict(sg.get("Tags", []))
            name     = get_name(existing, sg.get("GroupName", rid))
            required = build_required(region, "SecurityGroup", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"Security Group  [{name}]  ({rid})  needs → {list(missing.keys())}")
                add_to_plan("Security Group", rid, name, region, "SecurityGroup", missing,
                            lambda _r=rid, _m=missing, _rg=region:
                                boto3.client("ec2", region_name=_rg)
                                    .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
            else:
                ok_log(f"Security Group  [{name}]  — fully tagged")

# ─── VPCs ────────────────────────────────────────────────────────────────────
def scan_vpcs(region):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_vpcs").paginate():
        for vpc in page["Vpcs"]:
            rid      = vpc["VpcId"]
            existing = kv_to_dict(vpc.get("Tags", []))
            name     = get_name(existing, rid)
            required = build_required(region, "VPC", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"VPC  [{name}]  ({rid})  needs → {list(missing.keys())}")
                add_to_plan("VPC", rid, name, region, "VPC", missing,
                            lambda _r=rid, _m=missing, _rg=region:
                                boto3.client("ec2", region_name=_rg)
                                    .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
            else:
                ok_log(f"VPC  [{name}]  — fully tagged")

# ─── SUBNETS ─────────────────────────────────────────────────────────────────
def scan_subnets(region):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_subnets").paginate():
        for sub in page["Subnets"]:
            rid      = sub["SubnetId"]
            existing = kv_to_dict(sub.get("Tags", []))
            name     = get_name(existing, rid)
            required = build_required(region, "Subnet", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"Subnet  [{name}]  ({rid})  needs → {list(missing.keys())}")
                add_to_plan("Subnet", rid, name, region, "Subnet", missing,
                            lambda _r=rid, _m=missing, _rg=region:
                                boto3.client("ec2", region_name=_rg)
                                    .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
            else:
                ok_log(f"Subnet  [{name}]  — fully tagged")

# ─── ROUTE TABLES ────────────────────────────────────────────────────────────
def scan_route_tables(region):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_route_tables").paginate():
        for rt in page["RouteTables"]:
            rid      = rt["RouteTableId"]
            existing = kv_to_dict(rt.get("Tags", []))
            name     = get_name(existing, rid)
            required = build_required(region, "RouteTable", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"Route Table  [{name}]  ({rid})  needs → {list(missing.keys())}")
                add_to_plan("Route Table", rid, name, region, "RouteTable", missing,
                            lambda _r=rid, _m=missing, _rg=region:
                                boto3.client("ec2", region_name=_rg)
                                    .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
            else:
                ok_log(f"Route Table  [{name}]  — fully tagged")

# ─── INTERNET GATEWAYS ───────────────────────────────────────────────────────
def scan_internet_gateways(region):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_internet_gateways").paginate():
        for igw in page["InternetGateways"]:
            rid      = igw["InternetGatewayId"]
            existing = kv_to_dict(igw.get("Tags", []))
            name     = get_name(existing, rid)
            required = build_required(region, "InternetGateway", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"Internet Gateway  [{name}]  ({rid})  needs → {list(missing.keys())}")
                add_to_plan("Internet Gateway", rid, name, region, "InternetGateway", missing,
                            lambda _r=rid, _m=missing, _rg=region:
                                boto3.client("ec2", region_name=_rg)
                                    .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
            else:
                ok_log(f"Internet Gateway  [{name}]  — fully tagged")

# ─── NAT GATEWAYS ────────────────────────────────────────────────────────────
def scan_nat_gateways(region):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_nat_gateways").paginate(
            Filter=[{"Name": "state", "Values": ["available", "pending"]}]):
        for nat in page["NatGateways"]:
            rid      = nat["NatGatewayId"]
            existing = kv_to_dict(nat.get("Tags", []))
            name     = get_name(existing, rid)
            required = build_required(region, "NATGateway", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"NAT Gateway  [{name}]  ({rid})  needs → {list(missing.keys())}")
                add_to_plan("NAT Gateway", rid, name, region, "NATGateway", missing,
                            lambda _r=rid, _m=missing, _rg=region:
                                boto3.client("ec2", region_name=_rg)
                                    .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
            else:
                ok_log(f"NAT Gateway  [{name}]  — fully tagged")

# ─── ELASTIC IPs ─────────────────────────────────────────────────────────────
def scan_elastic_ips(region):
    ec2 = boto3.client("ec2", region_name=region)
    for addr in ec2.describe_addresses()["Addresses"]:
        rid = addr.get("AllocationId")
        if not rid:
            continue
        existing = kv_to_dict(addr.get("Tags", []))
        name     = get_name(existing, addr.get("PublicIp", rid))
        required = build_required(region, "ElasticIP", name)
        missing  = missing_tags(existing, required)
        if missing:
            scan_log(f"Elastic IP  [{name}]  ({rid})  needs → {list(missing.keys())}")
            add_to_plan("Elastic IP", rid, name, region, "ElasticIP", missing,
                        lambda _r=rid, _m=missing, _rg=region:
                            boto3.client("ec2", region_name=_rg)
                                .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
        else:
            ok_log(f"Elastic IP  [{name}]  — fully tagged")

# ─── NETWORK INTERFACES ──────────────────────────────────────────────────────
def scan_network_interfaces(region):
    ec2 = boto3.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        for eni in page["NetworkInterfaces"]:
            rid      = eni["NetworkInterfaceId"]
            existing = kv_to_dict(eni.get("TagSet", []))
            name     = get_name(existing, rid)
            required = build_required(region, "NetworkInterface", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"Network Interface  [{name}]  ({rid})  needs → {list(missing.keys())}")
                add_to_plan("Network Interface", rid, name, region, "NetworkInterface", missing,
                            lambda _r=rid, _m=missing, _rg=region:
                                boto3.client("ec2", region_name=_rg)
                                    .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
            else:
                ok_log(f"Network Interface  [{name}]  — fully tagged")

# ─── KEY PAIRS ───────────────────────────────────────────────────────────────
def scan_key_pairs(region):
    ec2 = boto3.client("ec2", region_name=region)
    for kp in ec2.describe_key_pairs().get("KeyPairs", []):
        rid      = kp["KeyPairId"]
        existing = kv_to_dict(kp.get("Tags", []))
        name     = get_name(existing, kp["KeyName"])
        required = build_required(region, "KeyPair", name)
        missing  = missing_tags(existing, required)
        if missing:
            scan_log(f"Key Pair  [{name}]  ({rid})  needs → {list(missing.keys())}")
            add_to_plan("Key Pair", rid, name, region, "KeyPair", missing,
                        lambda _r=rid, _m=missing, _rg=region:
                            boto3.client("ec2", region_name=_rg)
                                .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
        else:
            ok_log(f"Key Pair  [{name}]  — fully tagged")

# ─── AMIs ────────────────────────────────────────────────────────────────────
def scan_amis(region):
    ec2     = boto3.client("ec2", region_name=region)
    account = boto3.client("sts").get_caller_identity()["Account"]
    for img in ec2.describe_images(Owners=[account])["Images"]:
        rid      = img["ImageId"]
        existing = kv_to_dict(img.get("Tags", []))
        name     = get_name(existing, img.get("Name", rid))
        required = build_required(region, "AMI", name)
        missing  = missing_tags(existing, required)
        if missing:
            scan_log(f"AMI  [{name}]  ({rid})  needs → {list(missing.keys())}")
            add_to_plan("AMI", rid, name, region, "AMI", missing,
                        lambda _r=rid, _m=missing, _rg=region:
                            boto3.client("ec2", region_name=_rg)
                                .create_tags(Resources=[_r], Tags=dict_to_kv(_m)))
        else:
            ok_log(f"AMI  [{name}]  — fully tagged")

# ─── S3 BUCKETS ──────────────────────────────────────────────────────────────
def scan_s3_buckets():
    s3 = boto3.client("s3")
    for bucket in s3.list_buckets().get("Buckets", []):
        bname = bucket["Name"]
        scan_log(f"S3 Bucket  [{bname}]")
        try:
            loc    = s3.get_bucket_location(Bucket=bname)
            region = loc["LocationConstraint"] or "us-east-1"
            try:
                existing = kv_to_dict(s3.get_bucket_tagging(Bucket=bname).get("TagSet", []))
            except ClientError as e:
                existing = {} if e.response["Error"]["Code"] == "NoSuchTagSet" else (_ for _ in ()).throw(e)
            name     = existing.get("Name", bname)
            required = build_required(region, "S3", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"S3 Bucket  [{bname}]  needs → {list(missing.keys())}")
                merged = {**existing, **missing}
                add_to_plan("S3 Bucket", bname, name, region, "S3", missing,
                            lambda _b=bname, _mg=merged:
                                boto3.client("s3")
                                    .put_bucket_tagging(Bucket=_b,
                                                        Tagging={"TagSet": dict_to_kv(_mg)}))
            else:
                ok_log(f"S3 Bucket  [{bname}]  — fully tagged")
        except ClientError as e:
            err_log(f"S3 Bucket  [{bname}]  — {e}")

# ─── LAMBDA ──────────────────────────────────────────────────────────────────
def scan_lambda_functions(region):
    lmb = boto3.client("lambda", region_name=region)
    for page in lmb.get_paginator("list_functions").paginate():
        for fn in page["Functions"]:
            arn   = fn["FunctionArn"]
            fname = fn["FunctionName"]
            scan_log(f"Lambda  [{fname}]")
            try:
                existing = lmb.list_tags(Resource=arn).get("Tags", {})
                name     = existing.get("Name", fname)
                required = build_required(region, "Lambda", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"Lambda  [{fname}]  needs → {list(missing.keys())}")
                    add_to_plan("Lambda", arn, name, region, "Lambda", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("lambda", region_name=_rg)
                                        .tag_resource(Resource=_a, Tags=_m))
                else:
                    ok_log(f"Lambda  [{fname}]  — fully tagged")
            except ClientError as e:
                err_log(f"Lambda  [{fname}]  — {e}")

# ─── RDS INSTANCES ───────────────────────────────────────────────────────────
def scan_rds_instances(region):
    rds = boto3.client("rds", region_name=region)
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            arn   = db["DBInstanceArn"]
            db_id = db["DBInstanceIdentifier"]
            scan_log(f"RDS Instance  [{db_id}]")
            try:
                existing = kv_to_dict(rds.list_tags_for_resource(
                    ResourceName=arn).get("TagList", []))
                name     = existing.get("Name", db_id)
                required = build_required(region, "RDS", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"RDS Instance  [{db_id}]  needs → {list(missing.keys())}")
                    add_to_plan("RDS Instance", arn, name, region, "RDS", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("rds", region_name=_rg)
                                        .add_tags_to_resource(ResourceName=_a,
                                                              Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"RDS Instance  [{db_id}]  — fully tagged")
            except ClientError as e:
                err_log(f"RDS Instance  [{db_id}]  — {e}")

# ─── RDS CLUSTERS ────────────────────────────────────────────────────────────
def scan_rds_clusters(region):
    rds = boto3.client("rds", region_name=region)
    for page in rds.get_paginator("describe_db_clusters").paginate():
        for cluster in page["DBClusters"]:
            arn = cluster["DBClusterArn"]
            cid = cluster["DBClusterIdentifier"]
            scan_log(f"RDS Cluster  [{cid}]")
            try:
                existing = kv_to_dict(rds.list_tags_for_resource(
                    ResourceName=arn).get("TagList", []))
                name     = existing.get("Name", cid)
                required = build_required(region, "RDSCluster", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"RDS Cluster  [{cid}]  needs → {list(missing.keys())}")
                    add_to_plan("RDS Cluster", arn, name, region, "RDSCluster", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("rds", region_name=_rg)
                                        .add_tags_to_resource(ResourceName=_a,
                                                              Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"RDS Cluster  [{cid}]  — fully tagged")
            except ClientError as e:
                err_log(f"RDS Cluster  [{cid}]  — {e}")

# ─── LOAD BALANCERS ──────────────────────────────────────────────────────────
def scan_load_balancers(region):
    elb         = boto3.client("elbv2", region_name=region)
    lb_type_map = {"application": "ALB", "network": "NLB", "gateway": "GWLB"}
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for lb in page["LoadBalancers"]:
            arn   = lb["LoadBalancerArn"]
            lname = lb["LoadBalancerName"]
            ltype = lb_type_map.get(lb["Type"], lb["Type"].upper())
            scan_log(f"Load Balancer ({ltype})  [{lname}]")
            try:
                existing = kv_to_dict(
                    elb.describe_tags(ResourceArns=[arn])
                       ["TagDescriptions"][0].get("Tags", []))
                name     = existing.get("Name", lname)
                required = build_required(region, ltype, name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"Load Balancer  [{lname}]  needs → {list(missing.keys())}")
                    add_to_plan(f"Load Balancer ({ltype})", arn, name, region, ltype, missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("elbv2", region_name=_rg)
                                        .add_tags(ResourceArns=[_a], Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"Load Balancer  [{lname}]  — fully tagged")
            except ClientError as e:
                err_log(f"Load Balancer  [{lname}]  — {e}")

# ─── TARGET GROUPS ───────────────────────────────────────────────────────────
def scan_target_groups(region):
    elb = boto3.client("elbv2", region_name=region)
    for page in elb.get_paginator("describe_target_groups").paginate():
        for tg in page["TargetGroups"]:
            arn   = tg["TargetGroupArn"]
            tname = tg["TargetGroupName"]
            scan_log(f"Target Group  [{tname}]")
            try:
                existing = kv_to_dict(
                    elb.describe_tags(ResourceArns=[arn])
                       ["TagDescriptions"][0].get("Tags", []))
                name     = existing.get("Name", tname)
                required = build_required(region, "TargetGroup", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"Target Group  [{tname}]  needs → {list(missing.keys())}")
                    add_to_plan("Target Group", arn, name, region, "TargetGroup", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("elbv2", region_name=_rg)
                                        .add_tags(ResourceArns=[_a], Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"Target Group  [{tname}]  — fully tagged")
            except ClientError as e:
                err_log(f"Target Group  [{tname}]  — {e}")

# ─── ECS CLUSTERS ────────────────────────────────────────────────────────────
def scan_ecs_clusters(region):
    ecs  = boto3.client("ecs", region_name=region)
    arns = [a for page in ecs.get_paginator("list_clusters").paginate()
            for a in page["clusterArns"]]
    for i in range(0, len(arns), 100):
        for cluster in ecs.describe_clusters(clusters=arns[i:i + 100],
                                             include=["TAGS"])["clusters"]:
            arn   = cluster["clusterArn"]
            cname = cluster["clusterName"]
            scan_log(f"ECS Cluster  [{cname}]")
            existing = {t["key"]: t["value"] for t in cluster.get("tags", [])}
            name     = existing.get("Name", cname)
            required = build_required(region, "ECSCluster", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"ECS Cluster  [{cname}]  needs → {list(missing.keys())}")
                add_to_plan("ECS Cluster", arn, name, region, "ECSCluster", missing,
                            lambda _a=arn, _m=missing, _rg=region:
                                boto3.client("ecs", region_name=_rg)
                                    .tag_resource(resourceArn=_a,
                                                  tags=[{"key": k, "value": v}
                                                        for k, v in _m.items()]))
            else:
                ok_log(f"ECS Cluster  [{cname}]  — fully tagged")

# ─── ECS SERVICES ────────────────────────────────────────────────────────────
def scan_ecs_services(region):
    ecs      = boto3.client("ecs", region_name=region)
    clusters = [a for page in ecs.get_paginator("list_clusters").paginate()
                for a in page["clusterArns"]]
    for cluster in clusters:
        svc_arns = [a for page in ecs.get_paginator("list_services")
                                      .paginate(cluster=cluster)
                    for a in page["serviceArns"]]
        for i in range(0, len(svc_arns), 10):
            for svc in ecs.describe_services(cluster=cluster,
                                             services=svc_arns[i:i + 10],
                                             include=["TAGS"])["services"]:
                arn   = svc["serviceArn"]
                sname = svc["serviceName"]
                scan_log(f"ECS Service  [{sname}]")
                existing = {t["key"]: t["value"] for t in svc.get("tags", [])}
                name     = existing.get("Name", sname)
                required = build_required(region, "ECSService", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"ECS Service  [{sname}]  needs → {list(missing.keys())}")
                    add_to_plan("ECS Service", arn, name, region, "ECSService", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("ecs", region_name=_rg)
                                        .tag_resource(resourceArn=_a,
                                                      tags=[{"key": k, "value": v}
                                                            for k, v in _m.items()]))
                else:
                    ok_log(f"ECS Service  [{sname}]  — fully tagged")

# ─── EKS CLUSTERS ────────────────────────────────────────────────────────────
def scan_eks_clusters(region):
    eks = boto3.client("eks", region_name=region)
    try:
        for page in eks.get_paginator("list_clusters").paginate():
            for cname in page["clusters"]:
                scan_log(f"EKS Cluster  [{cname}]")
                cluster  = eks.describe_cluster(name=cname)["cluster"]
                arn      = cluster["arn"]
                existing = cluster.get("tags", {})
                name     = existing.get("Name", cname)
                required = build_required(region, "EKS", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"EKS Cluster  [{cname}]  needs → {list(missing.keys())}")
                    add_to_plan("EKS Cluster", arn, name, region, "EKS", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("eks", region_name=_rg)
                                        .tag_resource(resourceArn=_a, tags=_m))
                else:
                    ok_log(f"EKS Cluster  [{cname}]  — fully tagged")
    except ClientError as e:
        warn_log(f"EKS in {region}: {e}")

# ─── ELASTICACHE ─────────────────────────────────────────────────────────────
def scan_elasticache_clusters(region):
    ec = boto3.client("elasticache", region_name=region)
    for page in ec.get_paginator("describe_cache_clusters").paginate():
        for cluster in page["CacheClusters"]:
            arn = cluster["ARN"]
            cid = cluster["CacheClusterId"]
            scan_log(f"ElastiCache  [{cid}]")
            try:
                existing = kv_to_dict(ec.list_tags_for_resource(
                    ResourceName=arn).get("TagList", []))
                name     = existing.get("Name", cid)
                required = build_required(region, "ElastiCache", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"ElastiCache  [{cid}]  needs → {list(missing.keys())}")
                    add_to_plan("ElastiCache", arn, name, region, "ElastiCache", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("elasticache", region_name=_rg)
                                        .add_tags_to_resource(ResourceName=_a,
                                                              Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"ElastiCache  [{cid}]  — fully tagged")
            except ClientError as e:
                err_log(f"ElastiCache  [{cid}]  — {e}")

# ─── DYNAMODB ────────────────────────────────────────────────────────────────
def scan_dynamodb_tables(region):
    ddb     = boto3.client("dynamodb", region_name=region)
    account = boto3.client("sts").get_caller_identity()["Account"]
    for page in ddb.get_paginator("list_tables").paginate():
        for tname in page["TableNames"]:
            arn = f"arn:aws:dynamodb:{region}:{account}:table/{tname}"
            scan_log(f"DynamoDB  [{tname}]")
            try:
                existing = kv_to_dict(ddb.list_tags_of_resource(
                    ResourceArn=arn).get("Tags", []))
                name     = existing.get("Name", tname)
                required = build_required(region, "DynamoDB", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"DynamoDB  [{tname}]  needs → {list(missing.keys())}")
                    add_to_plan("DynamoDB", arn, name, region, "DynamoDB", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("dynamodb", region_name=_rg)
                                        .tag_resource(ResourceArn=_a,
                                                      Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"DynamoDB  [{tname}]  — fully tagged")
            except ClientError as e:
                err_log(f"DynamoDB  [{tname}]  — {e}")

# ─── SQS ─────────────────────────────────────────────────────────────────────
def scan_sqs_queues(region):
    sqs = boto3.client("sqs", region_name=region)
    try:
        for url in sqs.list_queues().get("QueueUrls", []):
            qname = url.split("/")[-1]
            scan_log(f"SQS Queue  [{qname}]")
            try:
                existing = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
                name     = existing.get("Name", qname)
                required = build_required(region, "SQS", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"SQS Queue  [{qname}]  needs → {list(missing.keys())}")
                    add_to_plan("SQS Queue", url, name, region, "SQS", missing,
                                lambda _u=url, _m=missing, _rg=region:
                                    boto3.client("sqs", region_name=_rg)
                                        .tag_queue(QueueUrl=_u, Tags=_m))
                else:
                    ok_log(f"SQS Queue  [{qname}]  — fully tagged")
            except ClientError as e:
                err_log(f"SQS Queue  [{qname}]  — {e}")
    except ClientError as e:
        warn_log(f"SQS in {region}: {e}")

# ─── SNS ─────────────────────────────────────────────────────────────────────
def scan_sns_topics(region):
    sns = boto3.client("sns", region_name=region)
    for page in sns.get_paginator("list_topics").paginate():
        for topic in page["Topics"]:
            arn   = topic["TopicArn"]
            tname = arn.split(":")[-1]
            scan_log(f"SNS Topic  [{tname}]")
            try:
                existing = kv_to_dict(sns.list_tags_for_resource(
                    ResourceArn=arn).get("Tags", []))
                name     = existing.get("Name", tname)
                required = build_required(region, "SNS", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"SNS Topic  [{tname}]  needs → {list(missing.keys())}")
                    add_to_plan("SNS Topic", arn, name, region, "SNS", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("sns", region_name=_rg)
                                        .tag_resource(ResourceArn=_a,
                                                      Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"SNS Topic  [{tname}]  — fully tagged")
            except ClientError as e:
                err_log(f"SNS Topic  [{tname}]  — {e}")

# ─── SECRETS MANAGER ─────────────────────────────────────────────────────────
def scan_secrets_manager(region):
    sm = boto3.client("secretsmanager", region_name=region)
    for page in sm.get_paginator("list_secrets").paginate():
        for secret in page["SecretList"]:
            arn   = secret["ARN"]
            sname = secret["Name"]
            scan_log(f"Secret  [{sname}]")
            try:
                existing = kv_to_dict(secret.get("Tags", []))
                name     = existing.get("Name", sname)
                required = build_required(region, "SecretsManager", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"Secret  [{sname}]  needs → {list(missing.keys())}")
                    add_to_plan("Secret", arn, name, region, "SecretsManager", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("secretsmanager", region_name=_rg)
                                        .tag_resource(SecretId=_a,
                                                      Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"Secret  [{sname}]  — fully tagged")
            except ClientError as e:
                err_log(f"Secret  [{sname}]  — {e}")

# ─── CLOUDWATCH LOG GROUPS ────────────────────────────────────────────────────
def scan_cloudwatch_log_groups(region):
    logs = boto3.client("logs", region_name=region)
    for page in logs.get_paginator("describe_log_groups").paginate():
        for lg in page["logGroups"]:
            lgname = lg["logGroupName"]
            scan_log(f"Log Group  [{lgname}]")
            try:
                existing = logs.list_tags_log_group(logGroupName=lgname).get("tags", {})
                name     = existing.get("Name", lgname)
                required = build_required(region, "CloudWatchLogs", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"Log Group  [{lgname}]  needs → {list(missing.keys())}")
                    add_to_plan("CloudWatch Log Group", lgname, name, region,
                                "CloudWatchLogs", missing,
                                lambda _n=lgname, _m=missing, _rg=region:
                                    boto3.client("logs", region_name=_rg)
                                        .tag_log_group(logGroupName=_n, tags=_m))
                else:
                    ok_log(f"Log Group  [{lgname}]  — fully tagged")
            except ClientError as e:
                err_log(f"Log Group  [{lgname}]  — {e}")

# ─── KINESIS ─────────────────────────────────────────────────────────────────
def scan_kinesis_streams(region):
    kin = boto3.client("kinesis", region_name=region)
    try:
        for stream in kin.list_streams().get("StreamNames", []):
            scan_log(f"Kinesis Stream  [{stream}]")
            try:
                existing = kv_to_dict(kin.list_tags_for_stream(
                    StreamName=stream).get("Tags", []))
                name     = existing.get("Name", stream)
                required = build_required(region, "Kinesis", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"Kinesis Stream  [{stream}]  needs → {list(missing.keys())}")
                    add_to_plan("Kinesis Stream", stream, name, region, "Kinesis", missing,
                                lambda _s=stream, _m=missing, _rg=region:
                                    boto3.client("kinesis", region_name=_rg)
                                        .add_tags_to_stream(StreamName=_s, Tags=_m))
                else:
                    ok_log(f"Kinesis Stream  [{stream}]  — fully tagged")
            except ClientError as e:
                err_log(f"Kinesis Stream  [{stream}]  — {e}")
    except ClientError as e:
        warn_log(f"Kinesis in {region}: {e}")

# ─── STEP FUNCTIONS ──────────────────────────────────────────────────────────
def scan_step_functions(region):
    sfn = boto3.client("stepfunctions", region_name=region)
    for page in sfn.get_paginator("list_state_machines").paginate():
        for sm in page["stateMachines"]:
            arn   = sm["stateMachineArn"]
            sname = sm["name"]
            scan_log(f"Step Function  [{sname}]")
            try:
                existing = kv_to_dict(sfn.list_tags_for_resource(
                    resourceArn=arn).get("tags", []))
                name     = existing.get("Name", sname)
                required = build_required(region, "StepFunctions", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"Step Function  [{sname}]  needs → {list(missing.keys())}")
                    add_to_plan("Step Function", arn, name, region, "StepFunctions", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("stepfunctions", region_name=_rg)
                                        .tag_resource(resourceArn=_a,
                                                      tags=dict_to_kv(_m)))
                else:
                    ok_log(f"Step Function  [{sname}]  — fully tagged")
            except ClientError as e:
                err_log(f"Step Function  [{sname}]  — {e}")

# ─── IAM ROLES ───────────────────────────────────────────────────────────────
def scan_iam_roles():
    iam = boto3.client("iam")
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            rname = role["RoleName"]
            arn   = role["Arn"]
            if rname.startswith("AWS") or "/aws-service-role/" in arn:
                continue
            scan_log(f"IAM Role  [{rname}]")
            try:
                existing = kv_to_dict(iam.list_role_tags(RoleName=rname).get("Tags", []))
                name     = existing.get("Name", rname)
                required = build_required("global", "IAMRole", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"IAM Role  [{rname}]  needs → {list(missing.keys())}")
                    add_to_plan("IAM Role", rname, name, "global", "IAMRole", missing,
                                lambda _n=rname, _m=missing:
                                    boto3.client("iam")
                                        .tag_role(RoleName=_n, Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"IAM Role  [{rname}]  — fully tagged")
            except ClientError as e:
                err_log(f"IAM Role  [{rname}]  — {e}")

# ─── IAM POLICIES ────────────────────────────────────────────────────────────
def scan_iam_policies():
    iam = boto3.client("iam")
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for policy in page["Policies"]:
            pname = policy["PolicyName"]
            arn   = policy["Arn"]
            scan_log(f"IAM Policy  [{pname}]")
            try:
                existing = kv_to_dict(iam.list_policy_tags(PolicyArn=arn).get("Tags", []))
                name     = existing.get("Name", pname)
                required = build_required("global", "IAMPolicy", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"IAM Policy  [{pname}]  needs → {list(missing.keys())}")
                    add_to_plan("IAM Policy", arn, name, "global", "IAMPolicy", missing,
                                lambda _a=arn, _m=missing:
                                    boto3.client("iam")
                                        .tag_policy(PolicyArn=_a, Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"IAM Policy  [{pname}]  — fully tagged")
            except ClientError as e:
                err_log(f"IAM Policy  [{pname}]  — {e}")

# ─── API GATEWAY ─────────────────────────────────────────────────────────────
def scan_api_gateway(region):
    apigw = boto3.client("apigatewayv2", region_name=region)
    try:
        for api in apigw.get_apis().get("Items", []):
            api_id = api["ApiId"]
            aname  = api.get("Name", api_id)
            arn    = f"arn:aws:apigateway:{region}::/apis/{api_id}"
            scan_log(f"API Gateway  [{aname}]")
            existing = api.get("Tags", {})
            name     = existing.get("Name", aname)
            required = build_required(region, "APIGateway", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"API Gateway  [{aname}]  needs → {list(missing.keys())}")
                add_to_plan("API Gateway", arn, name, region, "APIGateway", missing,
                            lambda _a=arn, _m=missing, _rg=region:
                                boto3.client("apigatewayv2", region_name=_rg)
                                    .tag_resource(ResourceArn=_a, Tags=_m))
            else:
                ok_log(f"API Gateway  [{aname}]  — fully tagged")
    except ClientError as e:
        warn_log(f"API Gateway in {region}: {e}")

# ─── CLOUDFRONT ──────────────────────────────────────────────────────────────
def scan_cloudfront_distributions():
    cf = boto3.client("cloudfront")
    try:
        for page in cf.get_paginator("list_distributions").paginate():
            for dist in page.get("DistributionList", {}).get("Items", []):
                arn = dist["ARN"]
                did = dist["Id"]
                scan_log(f"CloudFront Distribution  [{did}]")
                existing = kv_to_dict(
                    cf.list_tags_for_resource(Resource=arn)["Tags"].get("Items", []))
                name     = existing.get("Name", did)
                required = build_required("global", "CloudFront", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"CloudFront  [{did}]  needs → {list(missing.keys())}")
                    add_to_plan("CloudFront", arn, name, "global", "CloudFront", missing,
                                lambda _a=arn, _m=missing:
                                    boto3.client("cloudfront")
                                        .tag_resource(Resource=_a,
                                                      Tags={"Items": dict_to_kv(_m)}))
                else:
                    ok_log(f"CloudFront  [{did}]  — fully tagged")
    except ClientError as e:
        warn_log(f"CloudFront: {e}")

# ─── ECR ─────────────────────────────────────────────────────────────────────
def scan_ecr_repositories(region):
    ecr = boto3.client("ecr", region_name=region)
    for page in ecr.get_paginator("describe_repositories").paginate():
        for repo in page["repositories"]:
            arn   = repo["repositoryArn"]
            rname = repo["repositoryName"]
            scan_log(f"ECR Repository  [{rname}]")
            try:
                existing = kv_to_dict(ecr.list_tags_for_resource(
                    resourceArn=arn).get("tags", []))
                name     = existing.get("Name", rname)
                required = build_required(region, "ECR", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"ECR Repository  [{rname}]  needs → {list(missing.keys())}")
                    add_to_plan("ECR Repository", arn, name, region, "ECR", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("ecr", region_name=_rg)
                                        .tag_resource(resourceArn=_a,
                                                      tags=dict_to_kv(_m)))
                else:
                    ok_log(f"ECR Repository  [{rname}]  — fully tagged")
            except ClientError as e:
                err_log(f"ECR Repository  [{rname}]  — {e}")

# ─── SSM PARAMETERS ──────────────────────────────────────────────────────────
def scan_ssm_parameters(region):
    ssm = boto3.client("ssm", region_name=region)
    for page in ssm.get_paginator("describe_parameters").paginate():
        for param in page["Parameters"]:
            pname = param["Name"]
            scan_log(f"SSM Parameter  [{pname}]")
            try:
                existing = kv_to_dict(ssm.list_tags_for_resource(
                    ResourceType="Parameter",
                    ResourceId=pname).get("TagList", []))
                name     = existing.get("Name", pname)
                required = build_required(region, "SSM", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"SSM Parameter  [{pname}]  needs → {list(missing.keys())}")
                    add_to_plan("SSM Parameter", pname, name, region, "SSM", missing,
                                lambda _n=pname, _m=missing, _rg=region:
                                    boto3.client("ssm", region_name=_rg)
                                        .add_tags_to_resource(
                                            ResourceType="Parameter",
                                            ResourceId=_n,
                                            Tags=dict_to_kv(_m)))
                else:
                    ok_log(f"SSM Parameter  [{pname}]  — fully tagged")
            except ClientError as e:
                err_log(f"SSM Parameter  [{pname}]  — {e}")

# ─── AUTO SCALING GROUPS ─────────────────────────────────────────────────────
def scan_autoscaling_groups(region):
    asg = boto3.client("autoscaling", region_name=region)
    for page in asg.get_paginator("describe_auto_scaling_groups").paginate():
        for group in page["AutoScalingGroups"]:
            gname    = group["AutoScalingGroupName"]
            scan_log(f"Auto Scaling Group  [{gname}]")
            existing = {t["Key"]: t["Value"] for t in group.get("Tags", [])}
            name     = existing.get("Name", gname)
            required = build_required(region, "AutoScaling", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"Auto Scaling Group  [{gname}]  needs → {list(missing.keys())}")
                add_to_plan("Auto Scaling Group", gname, name, region, "AutoScaling", missing,
                            lambda _g=gname, _m=missing, _rg=region:
                                boto3.client("autoscaling", region_name=_rg)
                                    .create_or_update_tags(Tags=[
                                        {"ResourceId": _g,
                                         "ResourceType": "auto-scaling-group",
                                         "Key": k, "Value": v,
                                         "PropagateAtLaunch": True}
                                        for k, v in _m.items()]))
            else:
                ok_log(f"Auto Scaling Group  [{gname}]  — fully tagged")

# ─── OPENSEARCH ──────────────────────────────────────────────────────────────
def scan_opensearch_domains(region):
    osc = boto3.client("opensearch", region_name=region)
    try:
        for domain in osc.list_domain_names().get("DomainNames", []):
            dname = domain["DomainName"]
            scan_log(f"OpenSearch Domain  [{dname}]")
            arn      = osc.describe_domain(DomainName=dname)["DomainStatus"]["ARN"]
            existing = kv_to_dict(osc.list_tags(ARN=arn).get("TagList", []))
            name     = existing.get("Name", dname)
            required = build_required(region, "OpenSearch", name)
            missing  = missing_tags(existing, required)
            if missing:
                scan_log(f"OpenSearch  [{dname}]  needs → {list(missing.keys())}")
                add_to_plan("OpenSearch Domain", arn, name, region, "OpenSearch", missing,
                            lambda _a=arn, _m=missing, _rg=region:
                                boto3.client("opensearch", region_name=_rg)
                                    .add_tags(ARN=_a, TagList=dict_to_kv(_m)))
            else:
                ok_log(f"OpenSearch  [{dname}]  — fully tagged")
    except ClientError as e:
        warn_log(f"OpenSearch in {region}: {e}")

# ─── MSK ─────────────────────────────────────────────────────────────────────
def scan_msk_clusters(region):
    msk = boto3.client("kafka", region_name=region)
    try:
        for page in msk.get_paginator("list_clusters_v2").paginate():
            for cluster in page.get("ClusterInfoList", []):
                arn   = cluster["ClusterArn"]
                cname = cluster["ClusterName"]
                scan_log(f"MSK Cluster  [{cname}]")
                existing = msk.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
                name     = existing.get("Name", cname)
                required = build_required(region, "MSK", name)
                missing  = missing_tags(existing, required)
                if missing:
                    scan_log(f"MSK Cluster  [{cname}]  needs → {list(missing.keys())}")
                    add_to_plan("MSK Cluster", arn, name, region, "MSK", missing,
                                lambda _a=arn, _m=missing, _rg=region:
                                    boto3.client("kafka", region_name=_rg)
                                        .tag_resource(ResourceArn=_a, Tags=_m))
                else:
                    ok_log(f"MSK Cluster  [{cname}]  — fully tagged")
    except ClientError as e:
        warn_log(f"MSK in {region}: {e}")


# ═════════════════════════════════════════════════════════════════════════════
# SCAN ORCHESTRATOR  —  runs all scan functions, populates PLAN
# ═════════════════════════════════════════════════════════════════════════════

REGIONAL_SCANNERS = [
    ("EC2 Instances",         scan_ec2_instances),
    ("EBS Volumes",           scan_ebs_volumes),
    ("EBS Snapshots",         scan_ebs_snapshots),
    ("Security Groups",       scan_security_groups),
    ("VPCs",                  scan_vpcs),
    ("Subnets",               scan_subnets),
    ("Route Tables",          scan_route_tables),
    ("Internet Gateways",     scan_internet_gateways),
    ("NAT Gateways",          scan_nat_gateways),
    ("Elastic IPs",           scan_elastic_ips),
    ("Network Interfaces",    scan_network_interfaces),
    ("Key Pairs",             scan_key_pairs),
    ("AMIs",                  scan_amis),
    ("Lambda Functions",      scan_lambda_functions),
    ("RDS Instances",         scan_rds_instances),
    ("RDS Clusters",          scan_rds_clusters),
    ("Load Balancers",        scan_load_balancers),
    ("Target Groups",         scan_target_groups),
    ("ECS Clusters",          scan_ecs_clusters),
    ("ECS Services",          scan_ecs_services),
    ("EKS Clusters",          scan_eks_clusters),
    ("ElastiCache Clusters",  scan_elasticache_clusters),
    ("DynamoDB Tables",       scan_dynamodb_tables),
    ("SQS Queues",            scan_sqs_queues),
    ("SNS Topics",            scan_sns_topics),
    ("Secrets Manager",       scan_secrets_manager),
    ("CloudWatch Log Groups", scan_cloudwatch_log_groups),
    ("Kinesis Streams",       scan_kinesis_streams),
    ("Step Functions",        scan_step_functions),
    ("API Gateway (v2)",      scan_api_gateway),
    ("ECR Repositories",      scan_ecr_repositories),
    ("SSM Parameters",        scan_ssm_parameters),
    ("Auto Scaling Groups",   scan_autoscaling_groups),
    ("OpenSearch Domains",    scan_opensearch_domains),
    ("MSK Clusters",          scan_msk_clusters),
]

GLOBAL_SCANNERS = [
    ("S3 Buckets",               scan_s3_buckets),
    ("IAM Roles",                scan_iam_roles),
    ("IAM Policies",             scan_iam_policies),
    ("CloudFront Distributions", scan_cloudfront_distributions),
]

def run_scan(regions: list):
    # ── Global services ──────────────────────────────────────────────────────
    section("PHASE 1 — SCANNING GLOBAL SERVICES  (read-only)")
    for label, fn in GLOBAL_SCANNERS:
        subsection(label)
        try:
            fn()
        except Exception as e:
            err_log(f"{label}: {e}")

    # ── Regional services ─────────────────────────────────────────────────────
    for region in regions:
        section(f"PHASE 1 — SCANNING REGION: {region}  (read-only)")
        for label, fn in REGIONAL_SCANNERS:
            subsection(label)
            try:
                fn(region)
            except Exception as e:
                err_log(f"{label} in {region}: {e}")


# ═════════════════════════════════════════════════════════════════════════════
# PLAN DISPLAY  —  Terraform-style table printed before approval
# ═════════════════════════════════════════════════════════════════════════════
def print_plan():
    section("TAG PLAN  —  resources that will be modified")

    if not PLAN:
        print("\n  ✅  All resources are fully tagged. Nothing to do.\n", flush=True)
        return

    # ── Group by resource type for the summary block ──────────────────────────
    by_type = defaultdict(int)
    for item in PLAN:
        by_type[item["type"]] += 1

    print("\n  SUMMARY BY RESOURCE TYPE:", flush=True)
    print(f"  {'─' * 46}", flush=True)
    print(f"  {'Resource Type':<35}  Count", flush=True)
    print(f"  {'─' * 46}", flush=True)
    for rtype, count in sorted(by_type.items()):
        print(f"  {rtype:<35}  {count}", flush=True)
    print(f"  {'─' * 46}", flush=True)
    print(f"  {'TOTAL':<35}  {len(PLAN)}", flush=True)

    # ── Full resource-by-resource table ───────────────────────────────────────
    print(f"\n\n  FULL RESOURCE LIST:", flush=True)
    W_TYPE   = 28
    W_NAME   = 34
    W_REGION = 16
    W_TAGS   = 32
    header   = (f"  {'#':<5}  {'Resource Type':<{W_TYPE}}  "
                f"{'Name / ID':<{W_NAME}}  {'Region':<{W_REGION}}  Missing Tags")
    divider  = f"  {'─'*5}  {'─'*W_TYPE}  {'─'*W_NAME}  {'─'*W_REGION}  {'─'*W_TAGS}"

    print(f"\n{header}", flush=True)
    print(divider, flush=True)

    for idx, item in enumerate(PLAN, 1):
        display_name = (item["name"]
                        if item["name"] != item["id"]
                        else item["id"])[:W_NAME - 1]
        missing_keys = ", ".join(item["missing"].keys())
        # Wrap long missing-tag lists
        if len(missing_keys) > W_TAGS:
            missing_keys = missing_keys[:W_TAGS - 3] + "..."
        print(
            f"  {idx:<5}  "
            f"{item['type']:<{W_TYPE}}  "
            f"{display_name:<{W_NAME}}  "
            f"{item['region']:<{W_REGION}}  "
            f"{missing_keys}",
            flush=True
        )

    print(divider, flush=True)
    print(f"\n  {len(PLAN)} resource(s) will be tagged.\n", flush=True)


# ═════════════════════════════════════════════════════════════════════════════
# APPROVAL GATE  —  nothing is written until the user types  yes
# ═════════════════════════════════════════════════════════════════════════════
def ask_approval() -> bool:
    print("╔══════════════════════════════════════════════════════════════════╗",
          flush=True)
    print("║                    ⚠   APPROVAL REQUIRED   ⚠                   ║",
          flush=True)
    print("║                                                                  ║",
          flush=True)
    print("║  The plan above shows all tag changes that will be applied to    ║",
          flush=True)
    print("║  your PRODUCTION AWS account.  This action cannot be undone      ║",
          flush=True)
    print("║  automatically (tags can be removed manually if needed).         ║",
          flush=True)
    print("║                                                                  ║",
          flush=True)
    print("║  Type  yes  to apply.  Anything else cancels.                   ║",
          flush=True)
    print("╚══════════════════════════════════════════════════════════════════╝",
          flush=True)
    print("", flush=True)
    try:
        answer = input("  Enter value: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n\n  Cancelled by user (Ctrl+C).\n", flush=True)
        return False
    return answer == "yes"


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 — APPLY  —  runs only after approval
# ═════════════════════════════════════════════════════════════════════════════
def apply_plan():
    section("PHASE 2 — APPLYING TAGS")
    total   = len(PLAN)
    success = 0
    failed  = 0

    for idx, item in enumerate(PLAN, 1):
        label = (f"[{idx}/{total}]  {item['type']}  [{item['name']}]"
                 f"  region={item['region']}")
        apply_log(f"{label}")
        apply_log(f"         → Adding tags: {list(item['missing'].keys())}")
        try:
            item["apply_fn"]()
            success += 1
            apply_log(f"         ✅  Done")
        except Exception as e:
            failed += 1
            err_log(f"         ❌  FAILED: {e}")

    # ── Apply summary ──────────────────────────────────────────────────────────
    print(f"\n  {'═' * 40}", flush=True)
    print(f"  ✅  Successfully tagged : {success}", flush=True)
    if failed:
        print(f"  ❌  Failed             : {failed}", flush=True)
    print(f"  {'═' * 40}\n", flush=True)


# ═════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════
def main():
    print("\n" + "═" * 70, flush=True)
    print("  AWS TAG COMPLIANCE CHECKER & AUTO-TAGGER", flush=True)
    print("  Prod-safe mode  —  Scan → Review Plan → Approve → Apply", flush=True)
    print("═" * 70, flush=True)

    # ── Verify credentials ────────────────────────────────────────────────────
    try:
        identity = boto3.client("sts").get_caller_identity()
        print(f"\n  AWS Account : {identity['Account']}", flush=True)
        print(f"  Caller ARN  : {identity['Arn']}", flush=True)
    except Exception as e:
        print(f"\n  [FATAL] Cannot authenticate to AWS: {e}", flush=True)
        sys.exit(1)

    # ── Discover regions ──────────────────────────────────────────────────────
    print("\n  Discovering active AWS regions …", flush=True)
    regions = get_all_regions()
    print(f"  Found {len(regions)} region(s): {', '.join(regions)}", flush=True)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 1  —  SCAN   (read-only, populates global PLAN list)
    # ─────────────────────────────────────────────────────────────────────────
    run_scan(regions)

    # ─────────────────────────────────────────────────────────────────────────
    # PRINT PLAN  —  show what will change
    # ─────────────────────────────────────────────────────────────────────────
    print_plan()

    if not PLAN:
        sys.exit(0)

    # ─────────────────────────────────────────────────────────────────────────
    # APPROVAL GATE  —  nothing written until user types  yes
    # ─────────────────────────────────────────────────────────────────────────
    approved = ask_approval()

    if not approved:
        print("\n  ❌  Apply cancelled. Zero changes were made to your AWS account.\n",
              flush=True)
        sys.exit(0)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 2  —  APPLY  (runs only after approval)
    # ─────────────────────────────────────────────────────────────────────────
    apply_plan()

    section("ALL DONE")
    print(f"  Total resources tagged: {len(PLAN)}\n", flush=True)


if __name__ == "__main__":
    main()