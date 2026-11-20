# GIF shows only the live command. Curl and the PCAP replay start hidden,
# so the recording does not need a capture device or root.
# Run from the repository root after:
#   cargo build --release --example cli-tcp -p huginn-net-tcp --features full
#   cargo build --release --example cli-http -p huginn-net-http --features full
#   cargo build --release --example cli-tls -p huginn-net-tls --features full
#   vhs scripts/demo.tape

Output scripts/demo.gif

Set Shell "bash"
Set FontFamily "DejaVu Sans Mono"
Set FontSize 16
Set Width 1760
Set Height 700
Set Padding 32
Set Margin 16
Set MarginFill "#11111b"
Set BorderRadius 14
Set WindowBar Colorful
Set WindowBarSize 38
Set Theme "Catppuccin Mocha"
Set LineHeight 1.15
Set TypingSpeed 4ms
Set Framerate 20

Hide
Type "export PATH=$PWD/target/release/examples:$PATH"
Enter
Type "export PS1='huginn $ '"
Enter
Type "set +m"
Enter
Type "sudo() {"
Enter
Type "  unset RUST_LOG RUST_BACKTRACE"
Enter
Type "  while :; do"
Enter
Type "    for f in macos_tcp_flags ua-os-consistent-linux-syn-linux-ua; do cli-tcp pcap -f pcap/$f.pcap; sleep 0.6; done"
Enter
Type "    cli-http pcap -f pcap/http-simple-get.pcap; sleep 0.6"
Enter
Type "    for f in tls12 tls-alpn-h2 sigalg-grease; do cli-tls pcap -f pcap/$f.pcap; sleep 0.6; done"
Enter
Type "  done"
Enter
Type "}"
Enter
Type "curl -s -o /dev/null http://example.com/ &"
Enter
Sleep 300ms
Type "clear"
Enter
Show

Set TypingSpeed 18ms
Type "sudo RUST_LOG=info RUST_BACKTRACE=1 ./target/release/examples/cli -l capture.log live -i eth0"
Enter

# Cut while events are still printing.
Sleep 11s
