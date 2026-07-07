#!/usr/bin/env bash

# check_dnssec_expiry.sh
#
# Copyright 2017 by Mario Rimann <mario@rimann.org>
# Licensed under the permissive MIT license, see LICENSE.md
#
# Development of this script was partially sponsored by my
# employer internezzo, see http://www.internezzo.ch
#
# If this script helps you to make your work easier, please consider
# to give feedback or do something good, see https://rimann.org/support
#

# Forked at 07.07.2026.
# This script is originally based on:
# https://github.com/mrimann/check_dnssec_expiry/tree/3125050d62566dc8ea6f35aaa949e1988713100e
#
# Modifications and enhancements:
# * Added support for absolute time thresholds (days, hours, minutes, seconds) alongside percentages.
# * Fixed time/percentage calculation logic to dynamically evaluate the actual signature lifetime.
# * Resolved min/max RRSIG evaluation bugs to ensure safe monitoring during key rollovers.
# * Added verbose (-v) logging and inline command-debugging output for Nagios alerts.
# * added status code of dig to monitoring one liner
# * added ad flag validation is the answer dnssec signed?
# * added anycast node debug messasge

# Default values
warning="10d"
critical="5d"
resolver="8.8.8.8"
alwaysFailingDomain="dnssec-failed.org"
recordType="SOA"
verbose=0
cmd_anycast="$DNSSEC_CMD_ANYCAST"

usage() {
    cat - >&2 << _EOT_
usage $0 -z <zone> [-w <warning %>] [-c <critical %>] [-r <resolver>] [-f <always failing domain>] [-t <record type>] [-a <anycast cmd>] [-v] [-h]

    -z <zone>
        specify zone to check
    -w <warning [%]> | <warning d> | <warning h> | <warning m> | <warning s>
        warning time left percentage or days or hours or minutes or seconds
    -c <critical [%]> | <critical d> | <critical h> | <critical m> | <critical s>
        critical time left percentage or days or hours or minutes or seconds
    -r <resolver>
        specify which resolver to use.
    -f <always failing domain>
        specify a domain that will always fail DNSSEC.
        used to test if DNSSEC is supported in used tools.
    -t <DNS record type to check>
        specify a DNS record type for calculating the remaining lifetime.
        For example SOA, A, etc.
    -a <command>
        specify a command which is used to find out which node is serving the request.
        Overrides: DNSSEC_CMD_ANYCAST environment variable
    -v
        enable verbose output for debugging (prints to stderr).
    -h
        show this help message.
_EOT_
    exit 255
}

# Parse the input options
while getopts ":z:w:c:r:f:h:t:v" opt; do
  case $opt in
    z) zone=$OPTARG ;;
    w) warning=$OPTARG ;;
    c) critical=$OPTARG ;;
    r) resolver=$OPTARG ;;
    f) alwaysFailingDomain=$OPTARG ;;
    t) recordType=$OPTARG ;;
    v) verbose=1 ;;
    a) cmd_anycast=$OPTARG;;
    h) usage ;;
  esac
done

# Helper function for verbose logging
log_verbose() {
    if [[ "$verbose" -eq 1 ]]; then
        echo "VERBOSE: $1" >&2
    fi
}

# parse the threshold string to separate percentage and absolute time
parse_threshold() {
    local raw_time=$1
    local is_pct=0
    local time_in_sec=0

    if [[ "$raw_time" == *"%" ]]; then
        is_pct=$(echo "$raw_time" | tr -d '%!' )
    elif [[ "$raw_time" == *"d" ]]; then
        time_in_sec=$(($(echo "$raw_time" | tr -d 'd') * 86400))
    elif [[ "$raw_time" == *"h" ]]; then
        time_in_sec=$(($(echo "$raw_time" | tr -d 'h') * 3600))
    elif [[ "$raw_time" == *"m" ]]; then
        time_in_sec=$(($(echo "$raw_time" | tr -d 'm') * 60))
    elif [[ "$raw_time" == *"s" ]]; then
        time_in_sec=$(echo "$raw_time" | tr -d 's')
    else
        # fallback: treat raw numbers as percentages
        is_pct=$raw_time
    fi

    echo "$is_pct $time_in_sec"
}

# calculate remaining time string out of total seconds
calculate_remaining_time_string() {
    total_time=$1
    seconds=$(($total_time % 60))
    total_time=$((($total_time - $seconds) / 60))
    minutes=$(($total_time % 60))
    total_time=$((($total_time - $minutes) / 60))
    hours=$(($total_time % 24))
    days=$((($total_time - $hours) / 24))
    echo "${days}d ${hours}h ${minutes}m ${seconds}s"
}

# Check if dig is available at all - fail hard if not
pathToDig=$( which dig )
if [[ ! -e $pathToDig ]]; then
    echo "UNKNOWN: No executable of dig found, cannot proceed without dig."
    exit 3
fi

# Check if we got a zone to validate - fail hard if not
if [[ -z $zone ]]; then
    echo "UNKNOWN: Missing zone to test - please provide a zone via the -z parameter."
    usage
fi

# Parse thresholds to separate seconds and percentages
read warn_pct warn_sec <<< $(parse_threshold "$warning")
read crit_pct crit_sec <<< $(parse_threshold "$critical")

log_verbose "Starting check for zone $zone (Type: $recordType, Resolver: $resolver)"
log_verbose "Thresholds -> Warn: $warning, Crit: $critical"

# ==============================================================================
# Anycast/Backend Debugging
# ==============================================================================
debug_msg=""

# Safely check if the anycast command string is not empty
if [[ -n "$cmd_anycast" ]]; then
    log_verbose "Fetching backend debug info via $cmd_anycast"

    # Execute the command with safeguards for monitoring environments:
    # 1. 'timeout 3' prevents the script from hanging indefinitely
    # 2. '2>/dev/null' suppresses unwanted stderr messages
    # 3. 'head -n 1' and 'tr' ensure a clean, single-line output without line breaks or quotes
    debug_backend_out=$(resolver="$resolver" timeout 3 bash -c "$cmd_anycast" 2>/dev/null | head -n 1 | tr -d '\r\n"')

    if [[ -n "$debug_backend_out" ]]; then
        debug_msg=" [Backend: $debug_backend_out]"
        log_verbose "   -> Backend identified as: $debug_backend_out"
    else
        log_verbose "   -> No backend debug info returned or command failed/timed out."
    fi
else
    log_verbose "Omitting anycast debugging. Because -a or DNSSEC_CMD_ANYCAST is not set."
fi

# ==============================================================================
# Pre-Flight Checks
# ==============================================================================
# Check the resolver to properly validate DNSSEC at all
cmd_resolver_check="dig +nocmd +nostats +noquestion $alwaysFailingDomain @${resolver}"
log_verbose "Running Pre-Flight: $cmd_resolver_check"
checkResolverDoesDnssecValidation=$($cmd_resolver_check | grep "opcode: QUERY" | grep "status: SERVFAIL")

if [[ -z $checkResolverDoesDnssecValidation ]]; then
    echo "WARNING: Resolver seems to not validate DNSSEC signatures. [Cmd: $cmd_resolver_check]${debug_msg}"
    exit 1
fi

# Check if the resolver delivers an answer for the domain to test
# remove short and grep for status and output
cmd_resolve="dig @${resolver} $recordType $zone +dnssec"
log_verbose "Fetching data and status in one go: $cmd_resolve"
raw_rec_output=$($cmd_resolve 2>&1)

# Parse Status
if [[ "$raw_rec_output" == *";; connection timed out"* ]] || [[ "$raw_rec_output" == *"network error"* ]]; then
    client_status="TIMEOUT"
else
    client_status=$(echo "$raw_rec_output" | grep -o "status: [A-Z]*" | awk '{print $2}')
fi
log_verbose "Resolver answered with status: ${client_status}."

# Parse flags and check if answer is dnssec signed at all
# we are searching for the ad flag in the header
answerFlags=$(echo "$raw_rec_output" | sed -n -e 's/^;; flags: \([^;]\+\);.*/\1/p')
log_verbose "Found the following flags in header: $answerFlags"

# Parse output (like dig +short)
checkDomainResolvableWithDnssecEnabledResolver=$(echo "$raw_rec_output" | grep -v -e "^;" -e "^$" -e "RRSIG")

# If no data was returned OR the status is not NOERROR
if [[ -z "$checkDomainResolvableWithDnssecEnabledResolver" ]] || [[ "$client_status" != 'NOERROR' ]]; then

    # Fallback test: Does it work without DNSSEC validation (+cd)?
    cmd_resolve_cd="dig +short @${resolver} $recordType $zone +cd"
    checkDomainResolvableWithDnssecValidationExplicitelyDisabled=$($cmd_resolve_cd)

    if [[ -n "$checkDomainResolvableWithDnssecValidationExplicitelyDisabled" ]]; then
        echo "CRITICAL: The domain $zone can be resolved without DNSSEC (+cd), but fails with validation! (Resolver status with validation: $client_status) [Cmd: $cmd_resolve]${debug_msg}"
        exit 2
    else
        echo "CRITICAL: The domain $zone cannot be resolved via $resolver at all (even with +cd). (Resolver status with validation: $client_status) [Cmd: $cmd_resolve_cd]${debug_msg}"
        exit 2
    fi
fi

# If the script reaches this point, we know: Status is NOERROR and data was returned.
if [[ " $answerFlags " == *" ad "* ]]; then
    log_verbose "Answer is dnssec signed. Found (ad) flag in HEADER."
else
    log_verbose "Answer is not dnssec signed (missing 'ad' flag). Checking for DS record to find out why..."

    # Check if the domain is DNSSEC signed at all (has a DS record)
    cmd_signed="dig $zone @$resolver DS +short"
    checkZoneItselfIsSignedAtAll=$($cmd_signed)

    if [[ -z "$checkZoneItselfIsSignedAtAll" ]]; then
        log_verbose "Answer is missing ad flag becuase zone is unsigned."
        echo "WARNING: Zone $zone seems to be unsigned (No DS found). [Cmd: $cmd_signed]${debug_msg}"
        exit 1
    else
        echo "WARNING: The domain $zone has a DS record, but the resolver did not set the 'ad' flag! Possible resolver or path misconfiguration or NTA (Negative Trust Anchor) is set for zone. (Resolver status: $client_status) [Cmd: $cmd_resolve]${debug_msg}"
        exit 1
    fi
fi

# ==============================================================================
# Validation
# ==============================================================================
# Check if there are multiple RRSIG responses and check them one after the other
now=$(date +"%s")
log_verbose "Extracting RRSIGs from the previous query..."
rrsigEntries=$( echo "$raw_rec_output" | grep RRSIG )

if [[ -z $rrsigEntries ]]; then
        echo "CRITICAL: There is no RRSIG for the $recordType of your zone. (Resolver status: $client_status) [Cmd: $cmd_resolve]${debug_msg}"
        exit 2
else
    while read -r rrsig; do
        # Get the RRSIG entry and extract the date out of it
        expiryDateOfSignature=$( echo "$rrsig" | awk '{print $9}')
        checkValidityOfExpirationTimestamp=$( echo "$expiryDateOfSignature" | egrep '[0-9]{14}')
        if [[ -z $checkValidityOfExpirationTimestamp ]]; then
            echo "UNKNOWN: Something went wrong while checking the expiration of the RRSIG entry.(Resolver status: $client_status)  Raw RRSIG: $rrsig${debug_msg}"
            exit 3
        fi

        inceptionDateOfSignature=$( echo "$rrsig" | awk '{print $10}')
        checkValidityOfInceptionTimestamp=$( echo "$inceptionDateOfSignature" | egrep '[0-9]{14}')
        if [[ -z $checkValidityOfInceptionTimestamp ]]; then
            echo "UNKNOWN: Something went wrong while checking the inception date of the RRSIG entry. (Resolver status: $client_status) Raw RRSIG: $rrsig${debug_msg}"
            exit 3
        fi

        log_verbose "Found RRSIG: Inception $inceptionDateOfSignature -> Expiry $expiryDateOfSignature"

        # Fiddle out the expiry and inceptiondate of the signature
        expiryDateAsString="${expiryDateOfSignature:0:4}-${expiryDateOfSignature:4:2}-${expiryDateOfSignature:6:2} ${expiryDateOfSignature:8:2}:${expiryDateOfSignature:10:2}:00"
        expiryDateOfSignatureAsUnixTime=$( date -u -d "$expiryDateAsString" +"%s" 2>/dev/null )
        if [[ $? -ne 0 ]]; then
            expiryDateOfSignatureAsUnixTime=$( date -j -u -f "%Y-%m-%d %T" "$expiryDateAsString" +"%s" )
        fi
        
        inceptionDateAsString="${inceptionDateOfSignature:0:4}-${inceptionDateOfSignature:4:2}-${inceptionDateOfSignature:6:2} ${inceptionDateOfSignature:8:2}:${inceptionDateOfSignature:10:2}:00"
        inceptionDateOfSignatureAsUnixTime=$( date -u -d "$inceptionDateAsString" +"%s" 2>/dev/null )
        if [[ $? -ne 0 ]]; then
            inceptionDateOfSignatureAsUnixTime=$( date -j -u -f "%Y-%m-%d %T" "$inceptionDateAsString" +"%s" )
        fi

        # calculate the remaining lifetime of the signature
        totalLifetime=$( expr $expiryDateOfSignatureAsUnixTime - $inceptionDateOfSignatureAsUnixTime)
        remainingLifetimeOfSignature=$( expr $expiryDateOfSignatureAsUnixTime - $now)
        remainingPercentage=$( expr "100" \* $remainingLifetimeOfSignature / $totalLifetime)

        # store the result of this single RRSIG's check
        if [[ -z $minRemainingLifetime || $remainingLifetimeOfSignature -lt $minRemainingLifetime ]]; then
            minRemainingLifetime=$remainingLifetimeOfSignature
            minRemainingPercentage=$remainingPercentage
        fi
    done <<< "$rrsigEntries"
fi

expire_at=$(date -u +"%s")
expire_at=$(($expire_at+minRemainingLifetime))
expire_at_string=$(date -u -d @${expire_at} +"%c")
remaining_day_string=$(calculate_remaining_time_string $minRemainingLifetime)

log_verbose "Evaluation: Shortest remaining lifetime is $remaining_day_string ($minRemainingPercentage%)"

# determine if we need to alert
state="OK"
exit_code=0

if [[ $crit_pct -gt 0 && $minRemainingPercentage -lt $crit_pct ]]; then
    state="CRITICAL"
    exit_code=2
elif [[ $crit_sec -gt 0 && $minRemainingLifetime -lt $crit_sec ]]; then
    state="CRITICAL"
    exit_code=2
elif [[ $warn_pct -gt 0 && $minRemainingPercentage -lt $warn_pct ]]; then
    state="WARNING"
    exit_code=1
elif [[ $warn_sec -gt 0 && $minRemainingLifetime -lt $warn_sec ]]; then
    state="WARNING"
    exit_code=1
fi

# output the final result (one line with performance data)
if [[ "$state" == "OK" ]]; then
    echo "OK: DNSSEC signatures for $zone valid ($remaining_day_string / $minRemainingPercentage% remaining; expire at $expire_at_string)${debug_msg} | sig_lifetime=$minRemainingLifetime sig_lifetime_percentage=$minRemainingPercentage%;$warning;$critical"
else
    echo "$state: DNSSEC signature for $zone short before expiration! ($remaining_day_string / $minRemainingPercentage% remaining) [Cmd: dig @$resolver $recordType $zone +dnssec]${debug_msg} | sig_lifetime=$minRemainingLifetime sig_lifetime_percentage=$minRemainingPercentage%;$warning;$critical"
fi

exit $exit_code