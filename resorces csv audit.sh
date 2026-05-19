NOTE: # audit.sh and csv to excel in in same folder when we execute 

#!/bin/bash
# ============================================================
# AWS Resource Audit Script (NO PROFILE VERSION)
# Uses env credentials (SSO / access keys)
# ============================================================

CUTOFF_DATE="2026-03-10"
OUTPUT_FILE="raw_audit_output.csv"

# ============================================================
# ACCOUNTS + REGIONS
# ============================================================
declare -A ACCOUNT_REGIONS
ACCOUNT_REGIONS["account-dev"]="us-east-2,us-west-2,eu-central-1,mx-central-1"

# ============================================================
# Helpers
# ============================================================
log()  { echo "[INFO]  $*" >&2; }
warn() { echo "[WARN]  $*" >&2; }

# ============================================================
# Collectors
# ============================================================

collect_lambda() {
    local account=$1 region=$2
    log "  Lambda ..."
    aws lambda list-functions \
        --region "$region" \
        --query 'Functions[*].[FunctionName,FunctionArn,LastModified]' \
        --output json 2>/dev/null | python -c "
import sys, json
data = json.load(sys.stdin)
for fn in data:
    name, arn, created = fn
    created_date = created[:10] if created else ''
    if created_date and created_date < '$CUTOFF_DATE':
        print(f'\"$account\",\"$region\",\"Lambda Function\",\"{name}\",\"{arn}\",\"{created_date}\"')
"
}

collect_cloudwatch_alarms() {
    local account=$1 region=$2
    log "  CloudWatch Alarms ..."
    aws cloudwatch describe-alarms \
        --region "$region" \
        --query 'MetricAlarms[*].[AlarmName,AlarmArn,AlarmConfigurationUpdatedTimestamp]' \
        --output json 2>/dev/null | python -c "
import sys, json
data = json.load(sys.stdin)
for a in data:
    name, arn, created = a
    created_date = (created or '')[:10]
    if created_date and created_date < '$CUTOFF_DATE':
        print(f'\"$account\",\"$region\",\"CloudWatch Alarm\",\"{name}\",\"{arn}\",\"{created_date}\"')
"
}

collect_cloudwatch_log_groups() {
    local account=$1 region=$2
    log "  CloudWatch Log Groups ..."
    aws logs describe-log-groups \
        --region "$region" \
        --query 'logGroups[*].[logGroupName,arn,creationTime]' \
        --output json 2>/dev/null | python -c "
import sys, json, datetime
data = json.load(sys.stdin)
for g in data:
    name, arn, ts = g
    if ts:
        created_date = datetime.datetime.utcfromtimestamp(ts/1000).strftime('%Y-%m-%d')
    else:
        created_date = ''
    if created_date and created_date < '$CUTOFF_DATE':
        print(f'\"$account\",\"$region\",\"CloudWatch Log Group\",\"{name}\",\"{arn}\",\"{created_date}\"')
"
}

collect_sns() {
    local account=$1 region=$2
    log "  SNS Topics ..."
    aws sns list-topics \
        --region "$region" \
        --query 'Topics[*].TopicArn' \
        --output json 2>/dev/null | python -c "
import sys, json
arns = json.load(sys.stdin)
for arn in arns:
    name = arn.split(':')[-1]
    print(f'\"$account\",\"$region\",\"SNS Topic\",\"{name}\",\"{arn}\",\"Unknown\"')
"
}

collect_elb() {
    local account=$1 region=$2
    log "  ELB (Classic) ..."
    aws elb describe-load-balancers \
        --region "$region" \
        --query 'LoadBalancerDescriptions[*].[LoadBalancerName,DNSName,CreatedTime]' \
        --output json 2>/dev/null | python -c "
import sys, json
data = json.load(sys.stdin)
for lb in data:
    name, dns, created = lb
    created_date = (created or '')[:10]
    if created_date and created_date < '$CUTOFF_DATE':
        print(f'\"$account\",\"$region\",\"ELB (Classic)\",\"{name}\",\"{dns}\",\"{created_date}\"')
"
}

collect_alb() {
    local account=$1 region=$2
    log "  ALB/NLB ..."
    aws elbv2 describe-load-balancers \
        --region "$region" \
        --query 'LoadBalancers[*].[LoadBalancerName,LoadBalancerArn,CreatedTime,Type]' \
        --output json 2>/dev/null | python -c "
import sys, json
data = json.load(sys.stdin)
for lb in data:
    name, arn, created, lbtype = lb
    created_date = (created or '')[:10]
    lbtype_label = (lbtype or 'ALB').upper()
    if created_date and created_date < '$CUTOFF_DATE':
        print(f'\"$account\",\"$region\",\"{lbtype_label} Load Balancer\",\"{name}\",\"{arn}\",\"{created_date}\"')
"
}

collect_rds() {
    local account=$1 region=$2
    log "  RDS ..."
    aws rds describe-db-instances \
        --region "$region" \
        --query 'DBInstances[*].[DBInstanceIdentifier,DBInstanceArn,InstanceCreateTime]' \
        --output json 2>/dev/null | python -c "
import sys, json
data = json.load(sys.stdin)
for db in data:
    name, arn, created = db
    created_date = (created or '')[:10]
    if created_date and created_date < '$CUTOFF_DATE':
        print(f'\"$account\",\"$region\",\"RDS Instance\",\"{name}\",\"{arn}\",\"{created_date}\"')
"
}

collect_secrets() {
    local account=$1 region=$2
    log "  Secrets Manager ..."
    aws secretsmanager list-secrets \
        --region "$region" \
        --query 'SecretList[*].[Name,ARN,CreatedDate]' \
        --output json 2>/dev/null | python -c "
import sys, json
data = json.load(sys.stdin)
for s in data:
    name, arn, created = s
    created_date = (created or '')[:10]
    if created_date and created_date < '$CUTOFF_DATE':
        print(f'\"$account\",\"$region\",\"Secrets Manager Secret\",\"{name}\",\"{arn}\",\"{created_date}\"')
"
}

collect_ec2() {
    local account=$1 region=$2
    log "  EC2 Instances ..."
    aws ec2 describe-instances \
        --region "$region" \
        --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value|[0],LaunchTime,State.Name]' \
        --output json 2>/dev/null | python -c "
import sys, json
reservations = json.load(sys.stdin)
for reservation in reservations:
    for inst in reservation:
        iid, name, launched, state = inst
        name = name or iid
        launched_date = (launched or '')[:10]
        if launched_date and launched_date < '$CUTOFF_DATE':
            print(f'\"$account\",\"$region\",\"EC2 Instance ({state})\",\"{name}\",\"{iid}\",\"{launched_date}\"')
"
}

# ============================================================
# MAIN
# ============================================================

echo "Account,Region,Resource Type,Resource Name,Resource ID,Creation Date" > "$OUTPUT_FILE"

for account in "${!ACCOUNT_REGIONS[@]}"; do
    IFS=',' read -ra regions <<< "${ACCOUNT_REGIONS[$account]}"

    for region in "${regions[@]}"; do
        log "Scanning: $account | $region"

        collect_lambda "$account" "$region" >> "$OUTPUT_FILE"
        collect_cloudwatch_alarms "$account" "$region" >> "$OUTPUT_FILE"
        collect_cloudwatch_log_groups "$account" "$region" >> "$OUTPUT_FILE"
        collect_sns "$account" "$region" >> "$OUTPUT_FILE"
        collect_elb "$account" "$region" >> "$OUTPUT_FILE"
        collect_alb "$account" "$region" >> "$OUTPUT_FILE"
        collect_rds "$account" "$region" >> "$OUTPUT_FILE"
        collect_secrets "$account" "$region" >> "$OUTPUT_FILE"
        collect_ec2 "$account" "$region" >> "$OUTPUT_FILE"
    done
done

log "Done. Output saved to: $OUTPUT_FILE"
