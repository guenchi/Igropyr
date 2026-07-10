BEGIN {
  FS = ","
  failed = 0
}

NR == 1 { next }

{
  key = $1 SUBSEP $2
  rps[key] = $4 + 0
  cv[key] = $5 + 0
  alloc[key] = $6 + 0
  scenarios[$2] = 1
}

function pct_change(before, after) {
  return before == 0 ? 0 : ((after - before) / before) * 100
}

function fail(message) {
  print "GATE_FAIL," message > "/dev/stderr"
  failed = 1
}

END {
  for (scenario in scenarios) {
    bkey = "baseline" SUBSEP scenario
    ckey = "candidate" SUBSEP scenario
    if (!(bkey in rps) || !(ckey in rps)) {
      fail(sprintf("missing baseline/candidate summary for %s", scenario))
      continue
    }
    if (cv[bkey] > max_cv || cv[ckey] > max_cv)
      fail(sprintf("%s CV exceeds %s%% (baseline=%s%%, candidate=%s%%); rerun the benchmark",
                   scenario, max_cv, cv[bkey], cv[ckey]))

    change = pct_change(rps[bkey], rps[ckey])
    if (change < -max_regression)
      fail(sprintf("%s throughput regression %s%% exceeds -%s%%",
                   scenario, change, max_regression))
  }

  bprimary = "baseline" SUBSEP "primary"
  cprimary = "candidate" SUBSEP "primary"
  if ((bprimary in rps) && (cprimary in rps)) {
    gain = pct_change(rps[bprimary], rps[cprimary])
    alloc_drop = -pct_change(alloc[bprimary], alloc[cprimary])
    if (gain < min_rps_gain)
      fail(sprintf("primary throughput gain %s%% is below %s%%",
                   gain, min_rps_gain))
    if (alloc_drop < min_alloc_drop)
      fail(sprintf("primary allocation reduction %s%% is below %s%%",
                   alloc_drop, min_alloc_drop))
    print sprintf("GATE_RESULT,primary_rps_gain_percent=%s,primary_alloc_drop_percent=%s",
                  gain, alloc_drop)
  } else {
    fail("primary scenario is required for the merge gate")
  }

  if (!failed) print "GATE_PASS"
  exit failed
}
