# Regenerate from the repository root:
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
Set TypingSpeed 38ms
Set Framerate 20
Set CursorBlink false

Hide
Type "export PS1='operator@lab:~$ ' && clear"
Enter
Sleep 600ms
Show
Sleep 400ms

Type "echo '== target: http://127.0.0.1:18080  (authorized local lab) =='"
Enter
Sleep 700ms

Type "curl -s 127.0.0.1:18080/file-manager/initialize | jq -c '.config|{acl,disks}'"
Enter
Sleep 1000ms

Type "python3 poc/lfm_upload_rce_poc.py --cmd 'id; whoami; hostname'"
Enter
Sleep 1500ms

Sleep 5s
