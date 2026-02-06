#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# run_all_gates_lab2_alb.sh — SEIR Lab 2 (ALB Origin)
#
# Enforces:
#  - CloudFront: enabled, deployed, alias matches DOMAIN_NAME
#  - TLS: ACM cert in us-east-1 is ISSUED and covers DOMAIN_NAME
#  - WAF: associated with CloudFront (optional strict)
#  - Route53: A/AAAA alias points to CloudFront distribution domain
#  - Logging: CloudFront logging enabled (optional strict)
#  - Origin: CloudFront origin uses ALB DNS name
#  - ALB: exists, (prefer) internal, listeners exist, SG not world-open,
#         and allows CloudFront-only access (best effort via prefix list)
#
# Artifacts:
#  - gate_result.json, badge.txt, pr_comment.md
#
# Exit codes:
#   0 = PASS
#   2 = FAIL
#   1 = ERROR
# ============================================================

# ---------- Inputs ----------
ORIGIN_REGION="${ORIGIN_REGION:-us-east-1}"

CF_DISTRIBUTION_ID="${CF_DISTRIBUTION_ID:-}"
DOMAIN_NAME="${DOMAIN_NAME:-}"
ROUTE53_ZONE_ID="${ROUTE53_ZONE_ID:-}"

ACM_CERT_ARN="${ACM_CERT_ARN:-}"
WAF_WEB_ACL_ARN="${WAF_WEB_ACL_ARN:-}"
LOG_BUCKET="${LOG_BUCKET:-}"

# ALB specifics (required for ALB checks)
ALB_ARN="${ALB_ARN:-}"                 # arn:aws:elasticloadbalancing:...
ALB_SG_ID="${ALB_SG_ID:-}"             # sg-...
ALB_LISTENER_PORTS="${ALB_LISTENER_PORTS:-443,80}"   # comma-separated

# Strict toggles
REQUIRE_WAF_ASSOCIATION="${REQUIRE_WAF_ASSOCIATION:-true}"
REQUIRE_LOGGING="${REQUIRE_LOGGING:-true}"
REQUIRE_ALB_INTERNAL="${REQUIRE_ALB_INTERNAL:-true}"         # internal-only is the cleanest
REQUIRE_CLOUDFRONT_ONLY_INGRESS="${REQUIRE_CLOUDFRONT_ONLY_INGRESS:-false}" # stricter, can false-positive if you used CIDRs

# Outputs
OUT_JSON="${OUT_JSON:-gate_result.json}"
BADGE_TXT="${BADGE_TXT:-badge.txt}"
PR_COMMENT_MD="${PR_COMMENT_MD:-pr_comment.md}"

# SLA persistence
SLA_HOURS="${SLA_HOURS:-24}"
STATE_DIR="${STATE_DIR:-.gate_state}"
STATE_FILE="${STATE_FILE:-.gate_state/lab2_alb_first_seen_utc.txt}"

# Constants
CF_ACM_REGION="us-east-1"
CF_ROUTE53_ALIAS_ZONE_ID="Z2FDTNDATAQYW2"

# Helpers
now_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
mkdirp() { mkdir -p "$1" >/dev/null 2>&1 || true; }
json_escape() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'; }
iso_to_epoch() { date -u -d "$1" +%s 2>/dev/null || echo ""; }
epoch_to_iso() { date -u -d "@$1" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo ""; }

details=(); warnings=(); failures=()
add_detail(){ details+=("$1"); }
add_warning(){ warnings+=("$1"); }
add_failure(){ failures+=("$1"); }

make_json_array() {
  if (( $# == 0 )); then echo "[]"; return; fi
  printf '%s\n' "$@" | json_escape | awk 'BEGIN{print "["} {printf "%s\"%s\"", (NR>1?",":""), $0} END{print "]"}'
}

badge_from() {
  local status="$1"; local warn_count="$2"
  if [[ "$status" == "FAIL" ]]; then echo "RED"; return; fi
  if [[ "$warn_count" -gt 0 ]]; then echo "YELLOW"; return; fi
  echo "GREEN"
}

usage(){
  cat <<EOF
Required:
  CF_DISTRIBUTION_ID  CloudFront distribution ID
  DOMAIN_NAME         e.g. chewbacca-growls.com
  ROUTE53_ZONE_ID     hosted zone for domain
  ALB_ARN             Application Load Balancer ARN
  ALB_SG_ID           Security group attached to ALB

Recommended:
  ACM_CERT_ARN         ACM cert ARN (us-east-1)
  WAF_WEB_ACL_ARN      WAFv2 WebACL ARN (CLOUDFRONT scope)
  LOG_BUCKET           S3 bucket for CloudFront logs

Example:
  ORIGIN_REGION=us-east-1 \\
  CF_DISTRIBUTION_ID=E1... \\
  DOMAIN_NAME=chewbacca-growls.com \\
  ROUTE53_ZONE_ID=Z... \\
  ALB_ARN=arn:aws:elasticloadbalancing:us-east-1:200819971986:loadbalancer/app/... \\
  ALB_SG_ID=sg-... \\
  ACM_CERT_ARN=arn:aws:acm:us-east-1:200819971986:certificate/... \\
  LOG_BUCKET=chewbacca-logs \\
  ./run_all_gates_lab2_alb.sh
EOF
}

# Preconditions
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then usage; exit 0; fi
if ! have_cmd aws; then echo "ERROR: aws CLI missing." >&2; exit 1; fi
if [[ -z "$CF_DISTRIBUTION_ID" || -z "$DOMAIN_NAME" || -z "$ROUTE53_ZONE_ID" || -z "$ALB_ARN" || -z "$ALB_SG_ID" ]]; then
  echo "ERROR: missing required inputs." >&2
  usage >&2
  exit 1
fi

ts_now="$(now_utc)"
caller_arn="$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || echo "")"
account_id="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")"

[[ -n "$caller_arn" ]] && add_detail "PASS: AWS credentials OK (caller=$caller_arn)." \
  || add_failure "FAIL: aws sts get-caller-identity failed (credentials/permissions)."

# ---------- CloudFront core ----------
cf_enabled="$(aws cloudfront get-distribution --id "$CF_DISTRIBUTION_ID" --query "Distribution.DistributionConfig.Enabled" --output text 2>/dev/null || echo "Unknown")"
cf_status="$(aws cloudfront get-distribution --id "$CF_DISTRIBUTION_ID" --query "Distribution.Status" --output text 2>/dev/null || echo "Unknown")"
cf_domain="$(aws cloudfront get-distribution --id "$CF_DISTRIBUTION_ID" --query "Distribution.DomainName" --output text 2>/dev/null || echo "")"
cf_aliases="$(aws cloudfront get-distribution --id "$CF_DISTRIBUTION_ID" --query "Distribution.DistributionConfig.Aliases.Items" --output text 2>/dev/null || echo "")"

[[ "$cf_enabled" == "True" ]] && add_detail "PASS: CloudFront Enabled=True." \
  || add_failure "FAIL: CloudFront not enabled (Enabled=$cf_enabled)."

[[ "$cf_status" == "Deployed" ]] && add_detail "PASS: CloudFront Status=Deployed." \
  || add_warning "WARN: CloudFront Status not Deployed yet (Status=$cf_status)."

echo "$cf_aliases" | tr '\t' '\n' | grep -qi "^${DOMAIN_NAME}$" \
  && add_detail "PASS: CloudFront aliases include $DOMAIN_NAME." \
  || add_failure "FAIL: CloudFront aliases missing $DOMAIN_NAME."

viewer_acm_arn="$(aws cloudfront get-distribution --id "$CF_DISTRIBUTION_ID" --query "Distribution.DistributionConfig.ViewerCertificate.ACMCertificateArn" --output text 2>/dev/null || echo "")"
min_tls="$(aws cloudfront get-distribution --id "$CF_DISTRIBUTION_ID" --query "Distribution.DistributionConfig.ViewerCertificate.MinimumProtocolVersion" --output text 2>/dev/null || echo "")"

[[ -n "$viewer_acm_arn" && "$viewer_acm_arn" != "None" ]] \
  && add_detail "PASS: CloudFront ACMCertificateArn present." \
  || add_failure "FAIL: CloudFront ACMCertificateArn missing."

if [[ -n "$min_tls" && "$min_tls" != "None" ]]; then
  echo "$min_tls" | grep -q "TLSv1.2" \
    && add_detail "PASS: Minimum TLS includes TLSv1.2 ($min_tls)." \
    || add_warning "WARN: Minimum TLS not TLSv1.2+ ($min_tls)."
fi

# ---------- ACM validation ----------
acm_to_check="${ACM_CERT_ARN:-$viewer_acm_arn}"
if [[ -n "$acm_to_check" && "$acm_to_check" != "None" ]]; then
  cert_status="$(aws acm describe-certificate --certificate-arn "$acm_to_check" --region "$CF_ACM_REGION" --query "Certificate.Status" --output text 2>/dev/null || echo "Unknown")"
  cert_sans="$(aws acm describe-certificate --certificate-arn "$acm_to_check" --region "$CF_ACM_REGION" --query "Certificate.SubjectAlternativeNames" --output text 2>/dev/null || echo "")"

  [[ "$cert_status" == "ISSUED" ]] && add_detail "PASS: ACM cert ISSUED (us-east-1)." \
    || add_failure "FAIL: ACM cert not ISSUED (Status=$cert_status)."

  echo "$cert_sans" | tr '\t' '\n' | grep -qi "^${DOMAIN_NAME}$" \
    && add_detail "PASS: ACM cert covers $DOMAIN_NAME." \
    || add_warning "WARN: ACM SAN list does not show $DOMAIN_NAME (check wildcard coverage)."
else
  add_warning "WARN: No ACM cert ARN available to validate."
fi

# ---------- WAF association ----------
if [[ "$REQUIRE_WAF_ASSOCIATION" == "true" ]]; then
  if [[ -n "$account_id" ]]; then
    cf_resource_arn="arn:aws:cloudfront::${account_id}:distribution/${CF_DISTRIBUTION_ID}"
    waf_assoc_arn="$(aws wafv2 get-web-acl-for-resource --resource-arn "$cf_resource_arn" --region "$CF_ACM_REGION" --query "WebACL.ARN" --output text 2>/dev/null || echo "")"
    [[ -n "$waf_assoc_arn" && "$waf_assoc_arn" != "None" ]] \
      && add_detail "PASS: WAF WebACL associated with CloudFront." \
      || add_failure "FAIL: WAF WebACL not associated with CloudFront."
  else
    add_failure "FAIL: could not determine account id for WAF association check."
  fi
else
  add_detail "INFO: WAF association check disabled."
fi

# ---------- Route53 alias A/AAAA ----------
check_alias_record() {
  local type="$1"
  local name_fqdn="${DOMAIN_NAME}."
  local target="$cf_domain"

  local found_target
  found_target="$(aws route53 list-resource-record-sets --hosted-zone-id "$ROUTE53_ZONE_ID" \
    --query "ResourceRecordSets[?Type=='$type' && (Name=='$name_fqdn' || Name=='$DOMAIN_NAME')].AliasTarget.DNSName" \
    --output text 2>/dev/null || echo "")"

  local found_zone
  found_zone="$(aws route53 list-resource-record-sets --hosted-zone-id "$ROUTE53_ZONE_ID" \
    --query "ResourceRecordSets[?Type=='$type' && (Name=='$name_fqdn' || Name=='$DOMAIN_NAME')].AliasTarget.HostedZoneId" \
    --output text 2>/dev/null || echo "")"

  [[ -n "$found_target" ]] || { add_failure "FAIL: Route53 $type alias missing for $DOMAIN_NAME."; return; }

  echo "$found_target" | tr '\t' '\n' | grep -qi "^${target}\.?$" \
    && add_detail "PASS: Route53 $type alias points to CloudFront ($target)." \
    || add_failure "FAIL: Route53 $type alias target mismatch (expected=$target actual=$found_target)."

  echo "$found_zone" | tr '\t' '\n' | grep -q "^${CF_ROUTE53_ALIAS_ZONE_ID}$" \
    && add_detail "PASS: Route53 $type alias HostedZoneId is CloudFront ($CF_ROUTE53_ALIAS_ZONE_ID)." \
    || add_warning "WARN: Route53 $type alias HostedZoneId unexpected (expected=$CF_ROUTE53_ALIAS_ZONE_ID actual=$found_zone)."
}

check_alias_record "A"
check_alias_record "AAAA"

# ---------- Logging ----------
logging_bucket="$(aws cloudfront get-distribution --id "$CF_DISTRIBUTION_ID" --query "Distribution.DistributionConfig.Logging.Bucket" --output text 2>/dev/null || echo "")"
if [[ -n "$logging_bucket" && "$logging_bucket" != "None" ]]; then
  add_detail "PASS: CloudFront logging enabled (bucket=$logging_bucket)."
else
  [[ "$REQUIRE_LOGGING" == "true" ]] \
    && add_failure "FAIL: CloudFront logging not enabled." \
    || add_warning "WARN: CloudFront logging not enabled."
fi

# ---------- CloudFront origin uses ALB DNS ----------
alb_dns="$(aws elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" --region "$ORIGIN_REGION" \
  --query "LoadBalancers[0].DNSName" --output text 2>/dev/null || echo "")"
alb_scheme="$(aws elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" --region "$ORIGIN_REGION" \
  --query "LoadBalancers[0].Scheme" --output text 2>/dev/null || echo "")"

[[ -n "$alb_dns" && "$alb_dns" != "None" ]] && add_detail "PASS: ALB exists (DNS=$alb_dns)." \
  || add_failure "FAIL: ALB not found or not accessible (ALB_ARN=$ALB_ARN)."

if [[ "$REQUIRE_ALB_INTERNAL" == "true" ]]; then
  [[ "$alb_scheme" == "internal" ]] && add_detail "PASS: ALB scheme is internal." \
    || add_failure "FAIL: ALB scheme is not internal (scheme=$alb_scheme)."
else
  add_warning "WARN: ALB internal requirement disabled; public ALB weakens 'CloudFront-only' guarantee."
fi

# Verify CF origin domain contains ALB DNS
cf_origins="$(aws cloudfront get-distribution --id "$CF_DISTRIBUTION_ID" \
  --query "Distribution.DistributionConfig.Origins.Items[].DomainName" --output text 2>/dev/null || echo "")"
echo "$cf_origins" | tr '\t' '\n' | grep -qi "^${alb_dns}$" \
  && add_detail "PASS: CloudFront origin includes ALB DNSName." \
  || add_failure "FAIL: CloudFront origin does not reference ALB DNSName (expected=$alb_dns)."

# ---------- ALB listeners exist ----------
IFS=',' read -r -a ports <<< "$ALB_LISTENER_PORTS"
listeners="$(aws elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" --region "$ORIGIN_REGION" 2>/dev/null || echo "")"
if [[ -z "$listeners" ]]; then
  add_failure "FAIL: Could not describe ALB listeners."
else
  for p in "${ports[@]}"; do
    p="$(echo "$p" | tr -d ' ')"
    [[ -z "$p" ]] && continue
    found="$(aws elbv2 describe-listeners --load-balancer-arn "$ALB_ARN" --region "$ORIGIN_REGION" \
      --query "Listeners[?Port==\`${p}\`].ListenerArn" --output text 2>/dev/null || echo "")"
    [[ -n "$found" ]] && add_detail "PASS: ALB has listener on port $p." \
      || add_warning "WARN: ALB missing listener on port $p (Lab may only use 443)."
  done
fi

# ---------- ALB SG ingress: NOT world-open on listener ports ----------
for p in "${ports[@]}"; do
  p="$(echo "$p" | tr -d ' ')"
  [[ -z "$p" ]] && continue

  v4="$(aws ec2 describe-security-groups --group-ids "$ALB_SG_ID" --region "$ORIGIN_REGION" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`${p}\` && ToPort==\`${p}\`].IpRanges[].CidrIp" \
    --output text 2>/dev/null || echo "")"
  v6="$(aws ec2 describe-security-groups --group-ids "$ALB_SG_ID" --region "$ORIGIN_REGION" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`${p}\` && ToPort==\`${p}\`].Ipv6Ranges[].CidrIpv6" \
    --output text 2>/dev/null || echo "")"

  if echo "$v4 $v6" | grep -Eq '(^| )0\.0\.0\.0/0( |$)|(^| )::/0( |$)'; then
    add_failure "FAIL: ALB SG $ALB_SG_ID is world-open on port $p (0.0.0.0/0 or ::/0)."
  else
    add_detail "PASS: ALB SG $ALB_SG_ID not world-open on port $p."
  fi
done

# ---------- Optional: Require CloudFront-only ingress (best effort) ----------
# This can false-positive because teams might use CIDRs or private networking.
# We warn by default unless REQUIRE_CLOUDFRONT_ONLY_INGRESS=true.
if [[ "$REQUIRE_CLOUDFRONT_ONLY_INGRESS" == "true" ]]; then
  # We look for prefix-list sources on the ALB SG rules on listener ports.
  # If none found, we FAIL (strict).
  pl_sources="$(aws ec2 describe-security-groups --group-ids "$ALB_SG_ID" --region "$ORIGIN_REGION" \
    --query "SecurityGroups[0].IpPermissions[].PrefixListIds[].PrefixListId" --output text 2>/dev/null || echo "")"
  if [[ -n "$pl_sources" && "$pl_sources" != "None" ]]; then
    add_detail "PASS: ALB SG uses prefix lists for ingress (good sign for CloudFront-only)."
  else
    add_failure "FAIL: STRICT mode: ALB SG does not show prefix-list ingress sources (expected CloudFront prefix list)."
  fi
else
  add_detail "INFO: STRICT CloudFront-only ingress check disabled (set REQUIRE_CLOUDFRONT_ONLY_INGRESS=true to enforce)."
fi

# ---------- Final status ----------
overall_status="PASS"; overall_exit=0
(( ${#failures[@]} > 0 )) && overall_status="FAIL" && overall_exit=2

badge="$(badge_from "$overall_status" "${#warnings[@]}")"
echo "$badge" > "$BADGE_TXT"

# SLA clocks
mkdirp "$STATE_DIR"
first_seen_utc=""
last_seen_utc="$ts_now"
if [[ "$overall_status" == "FAIL" ]]; then
  [[ -f "$STATE_FILE" ]] && first_seen_utc="$(cat "$STATE_FILE" | tr -d '\n' || true)"
  [[ -z "$first_seen_utc" ]] && first_seen_utc="$ts_now" && echo "$first_seen_utc" > "$STATE_FILE"
else
  rm -f "$STATE_FILE" >/dev/null 2>&1 || true
fi

breach=false; due_utc=""; age_seconds=""; remaining_seconds=""
if [[ -n "$first_seen_utc" ]]; then
  first_epoch="$(iso_to_epoch "$first_seen_utc")"
  now_epoch="$(iso_to_epoch "$ts_now")"
  if [[ -n "$first_epoch" && -n "$now_epoch" ]]; then
    age_seconds="$(( now_epoch - first_epoch ))"
    sla_seconds="$(( SLA_HOURS * 3600 ))"
    due_epoch="$(( first_epoch + sla_seconds ))"
    due_utc="$(epoch_to_iso "$due_epoch")"
    if (( now_epoch > due_epoch )); then breach=true; remaining_seconds=0
    else remaining_seconds="$(( due_epoch - now_epoch ))"
    fi
  fi
fi

details_json="$(make_json_array "${details[@]}")"
warnings_json="$(make_json_array "${warnings[@]}")"
failures_json="$(make_json_array "${failures[@]}")"

cat > "$OUT_JSON" <<EOF
{
  "schema_version": "2.0",
  "gate": "lab2_alb",
  "timestamp_utc": "$(now_utc)",
  "badge": "$badge",
  "status": "$overall_status",
  "exit_code": $overall_exit,
  "inputs": {
    "origin_region": "$(echo "$ORIGIN_REGION" | json_escape)",
    "cloudfront_distribution_id": "$(echo "$CF_DISTRIBUTION_ID" | json_escape)",
    "domain_name": "$(echo "$DOMAIN_NAME" | json_escape)",
    "route53_zone_id": "$(echo "$ROUTE53_ZONE_ID" | json_escape)",
    "alb_arn": "$(echo "$ALB_ARN" | json_escape)",
    "alb_sg_id": "$(echo "$ALB_SG_ID" | json_escape)"
  },
  "observed": {
    "caller_arn": "$(echo "$caller_arn" | json_escape)",
    "cloudfront_domain": "$(echo "$cf_domain" | json_escape)",
    "cloudfront_status": "$(echo "$cf_status" | json_escape)",
    "alb_dns": "$(echo "$alb_dns" | json_escape)",
    "alb_scheme": "$(echo "$alb_scheme" | json_escape)"
  },
  "rollup": {
    "details": $details_json,
    "warnings": $warnings_json,
    "failures": $failures_json
  },
  "clocks": {
    "first_seen_utc": "$(echo "${first_seen_utc:-}" | json_escape)",
    "last_seen_utc": "$(echo "$last_seen_utc" | json_escape)"
  },
  "sla": {
    "target_hours": $SLA_HOURS,
    "due_utc": "$(echo "${due_utc:-}" | json_escape)",
    "breached": $breach,
    "age_seconds": "$(echo "${age_seconds:-}" | json_escape)",
    "remaining_seconds": "$(echo "${remaining_seconds:-}" | json_escape)"
  },
  "artifacts": {
    "badge_txt": "$(echo "$BADGE_TXT" | json_escape)",
    "pr_comment_md": "$(echo "$PR_COMMENT_MD" | json_escape)"
  }
}
EOF

cat > "$PR_COMMENT_MD" <<EOF
### SEIR Lab 2 (ALB Origin) Gate Result: **$badge** ($overall_status)

**Domain:** \`$DOMAIN_NAME\`  
**CloudFront:** \`$CF_DISTRIBUTION_ID\` → \`$cf_domain\`  
**ALB:** \`$ALB_ARN\` (scheme=\`$alb_scheme\`)  
**ALB SG:** \`$ALB_SG_ID\`  

**Failures (fix in order)**
$(if (( ${#failures[@]} == 0 )); then echo "- (none)"; else for f in "${failures[@]}"; do echo "- $f"; done; fi)

**Warnings**
$(if (( ${#warnings[@]} == 0 )); then echo "- (none)"; else for w in "${warnings[@]}"; do echo "- $w"; done; fi)

> Reminder: If the ALB is public or world-open, CloudFront is decorative, not protective.
EOF

echo ""
echo "===== SEIR Lab 2 (ALB) Gate Summary ====="
echo "BADGE:  $badge  (written to $BADGE_TXT)"
echo "RESULT: $overall_status"
echo "JSON:   $OUT_JSON"
echo "PR:     $PR_COMMENT_MD"
echo "========================================"
echo ""

exit "$overall_exit"
