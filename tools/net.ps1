function Send-Frame($s, [byte[]]$body) {
    $n = $body.Length
        $h = [byte[]](
        (($n -shr 24) -band 255),
        (($n -shr 16) -band 255),
        (($n -shr 8) -band 255),
        ($n -band 255)
    )
    $s.Write($h, 0, 4)
    if ($n -gt 0) { $s.Write($body, 0, $n) }
}
function Read-Frame($s) {
    $h = New-Object byte[] 4
    $null = $s.Read($h, 0, 4)
    $n = ($h[0] -shl 24) + ($h[1] -shl 16) + ($h[2] -shl 8) + $h[3]
    $b = New-Object byte[] $n
    if ($n -gt 0) { $null = $s.Read($b, 0, $n) }
    ,$b
}
function Connect-Secys {
    $c = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 9000)
    $c.GetStream()
}
function Register-Key($s, [byte[]]$key) {
    Send-Frame $s ([byte[]](,1 + $key))
    Read-Frame $s
}
function Send-To($s, [byte[]]$key, [string]$text) {
    $blob = [System.Text.Encoding]::UTF8.GetBytes($text)
    Send-Frame $s ([byte[]](,2 + $key + $blob))
    Read-Frame $s
}
function Show-Frame($f) {
    $hex = ($f | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
    if ($f.Length -gt 1 -and $f[0] -eq 3) {
        $text = [System.Text.Encoding]::UTF8.GetString($f, 1, $f.Length - 1)
        "$hex   => DELIVER: $text"
    } else { $hex }
}
$KeyA = [byte[]](1..32)
$KeyB = [byte[]](33..64)
$KeyC = [byte[]](,99 * 32)