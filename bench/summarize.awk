BEGIN {
  FS = ","
  OFS = ","
}

NR == 1 { next }

{
  key = $1 SUBSEP $2
  count[key]++
  rps[key, count[key]] = $5 + 0
  alloc[key, count[key]] = ($9 + 0) / ($4 + 0)
  sum[key] += $5 + 0
  sumsq[key] += ($5 + 0) * ($5 + 0)
}

function sort_values(key, source, out,    i, j, n, tmp) {
  n = count[key]
  for (i = 1; i <= n; i++) out[i] = source[key, i]
  for (i = 2; i <= n; i++) {
    tmp = out[i]
    j = i - 1
    while (j >= 1 && out[j] > tmp) {
      out[j + 1] = out[j]
      j--
    }
    out[j + 1] = tmp
  }
  return n
}

function median(a, n) {
  if (n % 2) return a[(n + 1) / 2]
  return (a[n / 2] + a[n / 2 + 1]) / 2
}

END {
  print "variant", "scenario", "runs", "median_rps", "cv_percent", "median_bytes_per_request"
  for (key in count) {
    split(key, parts, SUBSEP)
    delete sorted_rps
    delete sorted_alloc
    n = sort_values(key, rps, sorted_rps)
    sort_values(key, alloc, sorted_alloc)
    mean = sum[key] / n
    variance = (sumsq[key] / n) - (mean * mean)
    if (variance < 0) variance = 0
    cv = mean == 0 ? 0 : (sqrt(variance) / mean) * 100
    print parts[1], parts[2], n, median(sorted_rps, n), cv, median(sorted_alloc, n)
  }
}
