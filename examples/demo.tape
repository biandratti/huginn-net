# One command: TCP and TLS PCAPs in a loop, one line per event, still running when the GIF ends.
# Run from the repository root after:
#   cargo build --release --example cli-tcp -p huginn-net-tcp --features full
#   cargo build --release --example cli-tls -p huginn-net-tls --features full
#   vhs examples/demo.tape

Output examples/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1400
Set Height 520
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 12ms
Set Framerate 15

Hide
Type "export PATH=$PWD/target/release/examples:$PATH && clear"
Enter
Show

Type "while :; do"
Enter
Type "  for f in macos_tcp_flags ua-os-consistent-linux-syn-linux-ua; do cli-tcp pcap -f pcap/$f.pcap; sleep 1; done"
Enter
Type "  for f in tls12 tls-alpn-h2 sigalg-grease; do cli-tls pcap -f pcap/$f.pcap; sleep 1; done"
Enter
Type "done"
Sleep 600ms
Enter

# Cut while the loop is still printing. The prompt never comes back.
Sleep 9s
