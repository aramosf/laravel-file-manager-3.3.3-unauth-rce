# Regenerate from the repository root (local lab must be running):
#   vhs demo/lfm-rce-demo.tape
Output "demo/lfm-rce-demo.gif"

Set Shell "bash"
Set FontFamily "DejaVu Sans Mono"
Set FontSize 14
Set LetterSpacing 1
Set LineHeight 1.2
Set Width 1040
Set Height 520
Set Padding 12
Set MarginFill "#0d1117"
Set Margin 20
Set BorderRadius 10
Set WindowBar Colorful
Set WindowBarSize 38
Set Theme "Dracula"
Set TypingSpeed 95ms
Set Framerate 20
Set CursorBlink false

Hide
Type "export PS1='operator@lab:~$ ' && clear"
Enter
Sleep 800ms
Show
Sleep 600ms

Type "echo '== target: http://127.0.0.1:18080  (authorized local lab) =='"
Sleep 400ms
Enter
Sleep 1200ms

Type "curl -s 127.0.0.1:18080/file-manager/initialize | jq -c '.config|{acl,disks}'"
Sleep 400ms
Enter
Sleep 1800ms

Type "python3 poc/lfm_upload_rce_poc.py --cmd 'id; whoami; hostname'"
Sleep 400ms
Enter
Sleep 2500ms

Sleep 5s
