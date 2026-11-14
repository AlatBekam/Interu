$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $PSScriptRoot 'Interu-Kartika-Cyber-2026.pptx'
$preview = Join-Path $PSScriptRoot 'preview'
New-Item -ItemType Directory -Force -Path $preview | Out-Null

function RGB([int]$r,[int]$g,[int]$b) { return ($r + 256*$g + 65536*$b) }
$navy=RGB 10 18 29; $navy2=RGB 17 30 45; $teal=RGB 31 189 175
$white=RGB 236 244 247; $muted=RGB 159 180 196; $amber=RGB 245 176 82
$line=RGB 48 70 88; $red=RGB 250 117 117

function Box($s,[double]$x,[double]$y,[double]$w,[double]$h,[int]$fill,[int]$stroke=$fill) {
  $z=$s.Shapes.AddShape(1,$x,$y,$w,$h)
  $z.Fill.ForeColor.RGB=$fill; $z.Line.ForeColor.RGB=$stroke
  return $z
}
function Txt($s,[string]$t,[double]$x,[double]$y,[double]$w,[double]$h,[int]$size=20,[int]$color=$white,[bool]$bold=$false,[int]$align=1) {
  $z=$s.Shapes.AddTextbox(1,$x,$y,$w,$h)
  $z.TextFrame.TextRange.Text=$t
  $z.TextFrame.MarginLeft=0; $z.TextFrame.MarginRight=0
  $z.TextFrame.MarginTop=0; $z.TextFrame.MarginBottom=0
  $z.TextFrame.WordWrap=-1
  $f=$z.TextFrame.TextRange.Font
  $f.Name='Aptos'; $f.Size=$size; $f.Color.RGB=$color
  if($bold){$f.Bold=-1}else{$f.Bold=0}
  $z.TextFrame.TextRange.ParagraphFormat.Alignment=$align
  return $z
}
function Base([string]$title,[string]$kicker,[string]$source='') {
  $s=$pres.Slides.Add($pres.Slides.Count+1,12)
  [void](Box $s 0 0 960 540 $navy)
  [void](Box $s 0 0 960 7 $teal)
  [void](Txt $s 'INTERU  /  RUY CYBERSECURITY TEAM' 48 25 650 20 11 $teal $true)
  [void](Txt $s $kicker.ToUpper() 48 70 850 20 11 $muted $true)
  [void](Txt $s $title 48 95 865 64 34 $white $true)
  [void](Box $s 48 500 864 1 $line)
  if($source){[void](Txt $s $source 48 510 790 20 9 $muted)}
  [void](Txt $s ([string]$pres.Slides.Count).PadLeft(2,'0') 865 510 48 18 10 $muted $false 3)
  return $s
}
function Card($s,[string]$num,[string]$heading,[string]$body,[double]$x,[double]$y,[double]$w,[double]$h) {
  [void](Box $s $x $y $w $h $navy2 $line)
  [void](Txt $s $num ($x+20) ($y+18) 42 30 17 $teal $true)
  [void](Txt $s $heading ($x+20) ($y+55) ($w-40) 38 21 $white $true)
  [void](Txt $s $body ($x+20) ($y+103) ($w-40) ($h-120) 16 $muted)
}

$ppt=New-Object -ComObject PowerPoint.Application
$pres=$ppt.Presentations.Add(0)
$pres.PageSetup.SlideWidth=960; $pres.PageSetup.SlideHeight=540
try {
  Write-Host 'render slide 01'
  # 01
  $s=$pres.Slides.Add(1,12); [void](Box $s 0 0 960 540 $navy)
  [void](Box $s 0 0 17 540 $teal)
  [void](Txt $s 'RUY CYBERSECURITY TEAM' 66 54 650 26 14 $teal $true)
  [void](Txt $s 'INTERU' 66 150 760 100 78 $white $true)
  [void](Txt $s 'Rule based offensive security workstation' 69 272 790 52 28 $muted)
  [void](Box $s 69 355 620 2 $line)
  [void](Txt $s 'Kartika Cyber Hackathon 2026  •  Demo produk' 69 380 750 36 19 $white)
  [void](Txt $s 'Windows desktop  |  v1.4.0  |  tanpa model AI' 69 480 760 24 13 $muted)

  Write-Host 'render slide 02'
  # 02
  $s=Base 'Satu alur dari scope ke bukti' 'Masalah yang ditangani'
  [void](Txt $s 'Pengujian web sering berpindah alat dan kehilangan konteks antara eksplorasi, pemeriksaan, dan pelaporan.' 50 172 850 70 22 $white)
  Card $s '01' 'Jelajah' 'Proxy Browser, crawler, dan peta target mengumpulkan URL serta form dalam scope.' 48 267 270 205
  Card $s '02' 'Uji' 'Active Scan dan Rule Engine memeriksa respons dengan aturan dan probe terbatas.' 345 267 270 205
  Card $s '03' 'Buktikan' 'Operations menyimpan detail request, response, tingkat keyakinan, dan flag lab.' 642 267 270 205

  Write-Host 'render slide 03'
  # 03
  $s=Base 'Arsitektur Automation' 'Alur kerja deterministik' 'Sumber: src/main/automation.ts, src/main/browser.ts, src/shared/automation.ts'
  $steps=@('SCOPE','PROXY BROWSER','CRAWLER + API','RULES + ACTIVE SCAN','EVIDENCE')
  for($i=0;$i -lt $steps.Count;$i++){
    $x=48+$i*181
    [void](Box $s $x 214 164 82 $navy2 $line)
    [void](Txt $s $steps[$i] ($x+9) 235 146 35 15 $(if($i -eq 4){$amber}else{$white}) $true 2)
    if($i -lt 4){[void](Txt $s '→' ($x+164) 232 18 38 23 $teal $true 2)}
  }
  [void](Txt $s 'Batas request, durasi, jeda, origin, dan Scope berlaku sepanjang run.' 50 335 850 48 22 $white)
  [void](Txt $s 'Temuan kandidat tetap ditandai suspected sampai pemeriksaan memberi bukti yang cukup.' 50 403 850 45 17 $muted)

  Write-Host 'render slide 04'
  # 04
  $s=Base 'Rule Engine dan Active Scan' 'Kemampuan' 'Sumber: README.md; src/shared/rulepack2025.ts; audit/installed-verification.json'
  [void](Txt $s '808' 50 177 230 90 69 $teal $true)
  [void](Txt $s 'template data' 55 263 260 37 23 $white $true)
  [void](Txt $s '28 port/banner  •  47 HTTP pasif  •  733 HTTP aktif' 55 315 370 80 18 $muted)
  [void](Box $s 440 185 1 268 $line)
  [void](Txt $s 'Probe aktif berbasis bukti' 483 180 420 44 25 $white $true)
  [void](Txt $s 'SQLi  •  XSS  •  LFI  •  SSRF  •  XXE  •  IDOR' 483 239 424 75 20 $white)
  [void](Txt $s 'SSTI  •  RCE  •  CSRF  •  akses sensitif' 483 313 424 54 20 $white)
  [void](Txt $s 'Baseline dan kontrol pembanding dipakai pada probe yang mendukungnya. Jumlah template bukan ukuran akurasi.' 483 386 422 70 16 $muted)

  # Modul lengkap untuk pembaca mandiri
  $s=Base 'Apa saja yang ada di Interu?' 'Peta produk' 'Sumber: README.md; info.txt; audit/installed-verification.json'
  [void](Txt $s 'Web Security Suite' 52 180 340 36 23 $teal $true)
  [void](Txt $s 'Proxy + Intercept, Browser, Repeater, Intruder, Site Map, Crawler, Active Scan, Decoder, Comparer, Sequencer.' 52 223 825 72 19 $white)
  [void](Box $s 50 307 860 1 $line)
  [void](Txt $s 'Operations + Detection' 52 327 400 36 23 $teal $true)
  [void](Txt $s 'Network Scanner TCP/banner, Exposure Monitor, Rule Engine, dan Vulnerabilities dengan detail request/response.' 52 369 825 65 19 $white)
  [void](Txt $s 'Pentest Automation menggabungkan eksplorasi, crawl, pemeriksaan pasif, probe aktif, dan bukti dalam satu run.' 52 448 850 44 16 $amber)

  Write-Host 'render slide 05'
  # 05
  $s=Base 'Bukti regresi lab: 150/150' 'Demo terukur' 'Sumber: audit/lab-ui-verification.json (paket 1.3.0); testcase/interu50-live.test.ts (sumber 1.4.0)'
  [void](Txt $s '150/150' 50 190 340 86 63 $teal $true)
  [void](Txt $s 'Active Scan, Rule Engine, dan Pentest Automation menemukan seluruh kasus lab RUY.' 54 288 335 120 21 $white)
  [void](Txt $s 'Lab memang dirancang untuk Interu; ini bukti regresi internal, bukan tingkat deteksi umum.' 54 424 340 60 15 $amber)
  $img=Join-Path $root 'audit\lab-automation.png'
  $pic=$s.Shapes.AddPicture($img,0,-1,422,191,490,282)
  [void](Box $s 422 191 490 282 $navy2 $line)
  $pic.ZOrder(0) | Out-Null

  Write-Host 'render slide 06'
  # 06
  $s=Base 'Evaluasi pada 10 aplikasi latihan' 'Bukti di luar lab RUY' 'Sumber: audit/multi-target-benchmark.json; audit/ten-browser-benchmark.json'
  [void](Txt $s '7 online  +  3 lokal' 50 180 800 54 31 $teal $true)
  [void](Box $s 50 250 860 1 $line)
  [void](Txt $s 'DVWA online' 52 275 220 35 22 $white $true)
  [void](Txt $s '3 sinyal SQLi MySQL + 1 disclosure file' 280 275 600 45 19 $white)
  [void](Txt $s 'Juice Shop lokal' 52 340 220 35 22 $white $true)
  [void](Txt $s '1 sinyal SQLi SQLite' 280 340 600 45 19 $white)
  [void](Txt $s 'VAmPI lokal' 52 405 220 35 22 $white $true)
  [void](Txt $s 'field password pada JSON daftar pengguna' 280 405 600 45 19 $white)
  [void](Txt $s 'Temuan lain perlu validasi manual; belum ada ground truth lengkap untuk precision/recall.' 52 467 850 30 13 $amber)

  # Seluruh sasaran evaluasi, tanpa menyamakan jumlah temuan dengan kerentanan terkonfirmasi.
  $s=Base 'Sepuluh target yang diuji' 'Cakupan evaluasi' 'Sumber: audit/ten-browser-benchmark.json, 14 November 2026'
  [void](Txt $s 'ONLINE' 52 177 390 28 15 $teal $true)
  [void](Txt $s "Gin and Juice Shop`nAltoro Mutual`nGoogle Firing Range`nPentest Ground DVWA`nPentest Ground DVGA`nPentest Ground RestFlaw`nPentest Ground GuardianLeaks" 52 211 405 255 18 $white)
  [void](Box $s 480 180 1 282 $line)
  [void](Txt $s 'DOCKER LOKAL' 510 177 390 28 15 $teal $true)
  [void](Txt $s "OWASP Juice Shop`nVAmPI`nOWASP WebGoat" 510 211 390 130 18 $white)
  [void](Txt $s '9 run selesai; Google Firing Range berhenti pada batas request. Tidak ada form registrasi cocok pada run ini.' 510 365 390 98 17 $amber)

  Write-Host 'render slide 07'
  # 07
  $s=Base 'Browser exploration dan akun uji' 'Fitur v1.4.0' 'Sumber: audit/browser-account-verification.json; audit/ten-browser-benchmark.json'
  Card $s '01' 'Jelajah sendiri' 'Chromium lewat Proxy membuka halaman satu origin dan mencatat URL serta form.' 48 190 270 247
  Card $s '02' 'Akun uji' 'Pada form yang cocok, Interu membuat identitas sementara dan mencoba register/login.' 345 190 270 247
  Card $s '03' 'Sesi ke scan' 'Cookie yang berubah dapat dipakai scanner; perubahan cookie saja bukan bukti login.' 642 190 270 247
  [void](Txt $s 'Tes lokal membuktikan alur register → login → request privat. Pada 10 target, tidak ditemukan form registrasi yang cocok; temuan inti terkonfirmasi belum bertambah.' 50 452 860 42 15 $amber)

  # Pembaca juri perlu memahami bagaimana sebuah temuan diberi label.
  $s=Base 'Bagaimana temuan dinilai?' 'Metode validasi' 'Sumber: README.md; src/shared/webvuln.ts; src/shared/rules.ts'
  Card $s '01' 'Observasi' 'Simpan respons nyata: status, header, potongan isi, dan URL yang diperiksa.' 48 192 270 242
  Card $s '02' 'Pembanding' 'Bila tersedia, bandingkan baseline, input probe, dan kontrol penyeimbang.' 345 192 270 242
  Card $s '03' 'Label bukti' 'Sinyal kontekstual tetap suspected. Detail temuan dapat dibuka untuk pemeriksaan manual.' 642 192 270 242
  [void](Txt $s 'Contoh: refleksi HTML tidak otomatis dinyatakan XSS; perubahan objek publik saja tidak otomatis dinyatakan IDOR.' 51 455 850 40 16 $amber)

  Write-Host 'render slide 08'
  # 08
  $s=Base 'Batas operasi dan kejujuran hasil' 'Keandalan' 'Sumber: README.md; audit/ten-browser-benchmark.json'
  [void](Txt $s 'Scope dan satu origin' 53 180 450 40 25 $teal $true)
  [void](Txt $s 'Cookie dibatasi origin; run dibatasi request, waktu, dan jeda. Respons 429/503 menghentikan pemindaian.' 53 230 840 72 19 $white)
  [void](Box $s 50 332 860 1 $line)
  [void](Txt $s 'Batas yang masih ada' 53 355 450 40 25 $amber $true)
  [void](Txt $s 'Probe otomatis masih dominan GET. Alur POST/GraphQL, MFA, SSO, dan logika bisnis kompleks perlu pengujian lanjutan. Tidak ada klaim tanpa respons target.' 53 405 840 72 19 $white)

  Write-Host 'render slide 09'
  # 09
  $s=Base 'Demo langsung untuk juri' 'Penutup' 'Artefak: release/Interu-Setup-1.4.0.exe; audit/installed-verification.json'
  [void](Txt $s '1' 60 185 45 50 30 $teal $true)
  [void](Txt $s 'Tunjukkan aplikasi Windows 1.4.0 dan Scope.' 114 185 755 48 23 $white)
  [void](Txt $s '2' 60 259 45 50 30 $teal $true)
  [void](Txt $s 'Jalankan Automation pada lab RUY, buka detail bukti.' 114 259 755 55 23 $white)
  [void](Txt $s '3' 60 338 45 50 30 $teal $true)
  [void](Txt $s 'Jelaskan hasil 10 target dan batas yang masih ada.' 114 338 755 55 23 $white)
  [void](Box $s 52 432 856 2 $teal)
  [void](Txt $s 'Interu: satu workstation, aturan transparan, bukti yang bisa diperiksa.' 54 453 850 37 22 $white $true)

  Write-Host 'saving pptx'
  if(Test-Path -LiteralPath $out){Remove-Item -LiteralPath $out -Force}
  $pres.SaveAs($out,24)
  Write-Host 'exporting previews'
  foreach($slide in $pres.Slides){
    $path=Join-Path $preview ('slide-'+([string]$slide.SlideIndex).PadLeft(2,'0')+'.png')
    $slide.Export($path,'PNG',1280,720)
  }
  Write-Output ('saved='+$out)
  Write-Output ('slides='+$pres.Slides.Count)
} finally {
  $pres.Close(); $ppt.Quit()
  [System.Runtime.InteropServices.Marshal]::ReleaseComObject($pres) | Out-Null
  [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ppt) | Out-Null
}
