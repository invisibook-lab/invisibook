# VHS tape file – run `vhs demo.tape` to generate demo.gif
# Install VHS: https://github.com/charmbracelet/vhs

Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 600
Set Framerate 30

Type "make build-cli && ./invisibook"
Enter
Sleep 1s

# Navigate down through the order book
Down
Sleep 300ms
Down
Sleep 300ms
Down
Sleep 300ms

# Expand order detail
Enter
Sleep 1s

# Close detail
Enter
Sleep 500ms

# Navigate back to top
Up
Sleep 200ms
Up
Sleep 200ms
Up
Sleep 200ms

# Type a buy command
Type "buy ETH 3500 10 USDT"
Sleep 500ms
Enter
Sleep 1.5s

# Type a sell command
Type "sell BTC 64000 5 USDT"
Sleep 500ms
Enter
Sleep 1.5s

# Exit
Escape
Sleep 500ms
