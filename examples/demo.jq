# One line per event for `--format json` output of cli-tcp and cli-tls.
# Usage: cli-tcp --format json pcap -f <file> | jq --unbuffered -rf examples/demo.jq

def pad($n): tostring | . + (" " * ([$n - length, 0] | max));
def color($code): "\u001b[\($code)m\(.)\u001b[0m";
def endpoint: "\(.ip):\(.port)";

if has("syn") then
  if .syn != null and .syn.os_matched.os != null then
    .syn as $syn
    | ("TCP" | color("1;36"))
      + "  " + ("SYN" | pad(4))
      + "  " + ($syn.source | endpoint | pad(30))
      + " → " + ($syn.destination | endpoint | pad(36))
      + "  " + ([$syn.os_matched.os.name, $syn.os_matched.os.variant] | map(select(. != null)) | join(" ") | pad(36) | color("1;32"))
      + ("mtu \(.mtu.mtu // "-")" | color("2"))
  else empty end
elif has("sig") then
  .sig as $sig
  | ("TLS" | color("1;35"))
    + "  " + ("\($sig.version[0:1]).\($sig.version[1:])" | pad(4))
    + "  " + (.source.ip | pad(30))
    + " → " + ($sig.sni // .destination.ip | pad(36))
    + "  " + ($sig.ja4 | color("1;33"))
else empty end
