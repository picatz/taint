Output ./vhs/demo.gif

Set Margin 20
Set MarginFill "#ffffff"
Set BorderRadius 10

Set FontSize 20
Set Width 1200
Set Height 600

Type "taint"

Sleep 500ms

Enter

Sleep 3s

Type "load ./example"

Sleep 500ms

Enter

Sleep 2s

Type "n"

Tab@500ms 2

Sleep 500ms

Enter

Sleep 2s

Type "p"

Tab@500ms 2

Enter

Sleep 5s

Type "cg"

Sleep 1s

Enter

Sleep 5s

Type "callpath (*database/sql.DB).Query"

Sleep 500ms

Enter

Sleep 3s

Type "check *net/http.Request (*database/sql.DB).Query"

Sleep 500ms

Enter

Sleep 5s

Type "ex"

Tab@500ms 2

Enter

Sleep 5s