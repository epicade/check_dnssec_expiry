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
# * Modified to fix time/percentage calculation logic and min/max RRSIG bugs.

usage() {
    cat - >&2 << _EOT_
usage $0 -z <zone> [-w <warning %>] [-c <critical %>] [-r <resolver>] [-f <always failing domain>]

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
_EOT_
    exit 255
}

# Parse the input options
while getopts ":z:w:c:r:f:h:t:" opt; do
  case $opt in
    z)
      zone=$OPTARG
      ;;
    w)
      warning=$OPTARG
      ;;
    c)
      critical=$OPTARG
      ;;
    r)
      resolver=$OPTARG
      ;;
    f)
      alwaysFailingDomain=$OPTARG
      ;;
    t)
      recordType=$OPTARG
      ;;
    h)
      usage ;;
  esac
done

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
    echo "No executable of dig found, cannot proceed without dig. Sorry!"
    exit 1
fi

# Check if we got a zone to validate - fail hard if not
if [[ -z $zone ]]; then
    echo "Missing zone to test - please provide a zone via the -z parameter."
    usage
    exit 3
fi

# Check if we got warning/critical percentage values, use defaults if not
if [[ -z $warning ]]; then
    warning="10d"
fi
if [[ -z $critical ]]; then
    critical="5d"
fi

# Parse thresholds to separate seconds and percentages
read warn_pct warn_sec <<< $(parse_threshold "$warning")
read crit_pct crit_sec <<< $(parse_threshold "$critical")

# Use Google's 8.8.8.8 resolver as fallback if none is provided
if [[ -z $resolver ]]; then
    resolver="8.8.8.8"
fi

if [[ -z $alwaysFailingDomain ]]; then
    alwaysFailingDomain="dnssec-failed.org"
fi

# Use SOA record type as fallback
if [[ -z $recordType ]]; then
        recordType="SOA"
fi

# Check the resolver to properly validate DNSSEC at all (if he doesn't, every further test is futile and a waste of bandwith)
checkResolverDoesDnssecValidation=$(dig +nocmd +nostats +noquestion $alwaysFailingDomain @${resolver} | grep "opcode: QUERY" | grep "status: SERVFAIL")
if [[ -z $checkResolverDoesDnssecValidation ]]; then
    echo "WARNING: Resolver seems to not validate DNSSEC signatures - going further seems hopeless right now."
    exit 1
fi

# Check if the resolver delivers an answer for the domain to test
checkDomainResolvableWithDnssecEnabledResolver=$(dig +short @${resolver} $recordType $zone)
if [[ -z $checkDomainResolvableWithDnssecEnabledResolver ]]; then

    checkDomainResolvableWithDnssecValidationExplicitelyDisabled=$(dig +short @${resolver} $recordType $zone +cd)

    if [[ ! -z $checkDomainResolvableWithDnssecValidationExplicitelyDisabled ]]; then
        echo "CRITICAL: The domain $zone can be resolved without DNSSEC validation - but will fail on resolvers that do validate DNSSEC."
        exit 2
    else
        echo "CRITICAL: The domain $zone cannot be resolved via $resolver as resolver while DNSSEC validation is active."
        exit 2
    fi
fi

# Check if the domain is DNSSEC signed at all
# (and emerge a WARNING in that case, since this check is about testing DNSSEC being "present" and valid which is not the case for an unsigned zone)
checkZoneItselfIsSignedAtAll=$( dig $zone @$resolver DS +short )
if [[ -z $checkZoneItselfIsSignedAtAll ]]; then
    echo "WARNING: Zone $zone seems to be unsigned itself (= resolvable, but no DNSSEC involved at all)"
    exit 1
fi

# Check if there are multiple RRSIG responses and check them one after the other
now=$(date +"%s")
rrsigEntries=$( dig @$resolver $recordType $zone +dnssec | grep RRSIG )
if [[ -z $rrsigEntries ]]; then
        echo "CRITICAL: There is no RRSIG for the $recordType of your zone."
        exit 2
else
    while read -r rrsig; do
        # Get the RRSIG entry and extract the date out of it
        expiryDateOfSignature=$( echo $rrsig | awk '{print $9}')
        checkValidityOfExpirationTimestamp=$( echo $expiryDateOfSignature | egrep '[0-9]{14}')
        if [[ -z $checkValidityOfExpirationTimestamp ]]; then
            echo "UNKNOWN: Something went wrong while checking the expiration of the RRSIG entry - investigate please".
            exit 3
        fi

        inceptionDateOfSignature=$( echo $rrsig | awk '{print $10}')
        checkValidityOfInceptionTimestamp=$( echo $inceptionDateOfSignature | egrep '[0-9]{14}')
        if [[ -z $checkValidityOfInceptionTimestamp ]]; then
            echo "UNKNOWN: Something went wrong while checking the inception date of the RRSIG entry - investigate please".
            exit 3
        fi

        # Fiddle out the expiry and inceptiondate of the signature to have a base to do some calculations afterwards
        expiryDateAsString="${expiryDateOfSignature:0:4}-${expiryDateOfSignature:4:2}-${expiryDateOfSignature:6:2} ${expiryDateOfSignature:8:2}:${expiryDateOfSignature:10:2}:00"
        expiryDateOfSignatureAsUnixTime=$( date -u -d "$expiryDateAsString" +"%s" 2>/dev/null )
        if [[ $? -ne 0 ]]; then
            # if we come to this place, something must have gone wrong converting the date-string. This can happen as e.g. MacOS X and Linux don't behave the same way in this topic...
            expiryDateOfSignatureAsUnixTime=$( date -j -u -f "%Y-%m-%d %T" "$expiryDateAsString" +"%s" )
        fi
        inceptionDateAsString="${inceptionDateOfSignature:0:4}-${inceptionDateOfSignature:4:2}-${inceptionDateOfSignature:6:2} ${inceptionDateOfSignature:8:2}:${inceptionDateOfSignature:10:2}:00"
        inceptionDateOfSignatureAsUnixTime=$( date -u -d "$inceptionDateAsString" +"%s" 2>/dev/null )
        if [[ $? -ne 0 ]]; then
            # if we come to this place, something must have gone wrong converting the date-string. This can happen as e.g. MacOS X and Linux don't behave the same way in this topic...
            inceptionDateOfSignatureAsUnixTime=$( date -j -u -f "%Y-%m-%d %T" "$inceptionDateAsString" +"%s" )
        fi

        # calculate the remaining lifetime of the signature
        totalLifetime=$( expr $expiryDateOfSignatureAsUnixTime - $inceptionDateOfSignatureAsUnixTime)
        remainingLifetimeOfSignature=$( expr $expiryDateOfSignatureAsUnixTime - $now)
        remainingPercentage=$( expr "100" \* $remainingLifetimeOfSignature / $totalLifetime)

        # store the result of this single RRSIG's check
        # ensure we track the SHORTEST remaining lifetime in case of multiple signatures
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

# determine if we need to alert, and if so, how loud to cry, depending on warning/critial threshholds provided
state="OK"
exit_code=0

# evaluate critical thresholds first
if [[ $crit_pct -gt 0 && $minRemainingPercentage -lt $crit_pct ]]; then
    state="CRITICAL"
    exit_code=2
elif [[ $crit_sec -gt 0 && $minRemainingLifetime -lt $crit_sec ]]; then
    state="CRITICAL"
    exit_code=2
# evaluate warning thresholds
elif [[ $warn_pct -gt 0 && $minRemainingPercentage -lt $warn_pct ]]; then
    state="WARNING"
    exit_code=1
elif [[ $warn_sec -gt 0 && $minRemainingLifetime -lt $warn_sec ]]; then
    state="WARNING"
    exit_code=1
fi

# output the final result
if [[ "$state" == "OK" ]]; then
    echo "OK: DNSSEC signatures for $zone seem to be valid and not expired ($remaining_day_string / $minRemainingPercentage% remaining; expire at $expire_at_string) | sig_lifetime=$minRemainingLifetime  sig_lifetime_percentage=$minRemainingPercentage%;$warning;$critical"
else
    echo "$state: DNSSEC signature for $zone is short before expiration! ($remaining_day_string / $minRemainingPercentage% remaining; expire at $expire_at_string) | sig_lifetime=$minRemainingLifetime  sig_lifetime_percentage=$minRemainingPercentage%;$warning;$critical"
fi

exit $exit_code